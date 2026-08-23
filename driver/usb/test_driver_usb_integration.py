############################################################################
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.
#
############################################################################

"""Check that a USB CDC/ACM link survives Linux USB runtime suspend.

A USB device driver that reports ``CLASS_SUSPEND`` but never ``CLASS_RESUME``
leaves ``cdcacm_suspend()``'s ``uart_connected(false)`` latched, after which
``serial.c`` refuses every board-side ``open()`` and ``write()`` on the CDC
port with ``-ENOTCONN``.  The device stays enumerated throughout, so the
failure looks like a random USB wedge rather than a deterministic one.

Linux hosts reach that state unprompted: with ``power/control=auto`` and the
usual ``autosuspend_delay_ms=2000``, closing the tty is enough.  The test only
has to force it deterministically, so each cycle re-arms runtime PM and waits
for ``runtime_status`` to actually reach ``suspended`` before judging anything
-- a resumed device will not idle out again on its own until PM is toggled.

Opening the port is what resumes the device.  Bytes are then counted both over
the read window and over its trailing second; the tail count is what separates
a working link from one that only flushed its stale CDC TX buffer on resume.

Host requirements:

- Linux, plus passwordless ``sudo`` for two sysfs power attributes.
- The port under test is not the NTFC console.  The console stays open for the
  whole session, and an open port pins runtime PM, so the device never
  suspends and the test measures nothing.
- The board transmits unprompted on that port: a banner, a telemetry stream,
  anything periodic.

Wiring comes from the environment.  ``NTFC_USB_CDC_DEVICE`` is the host path of
the port under test, defaulting to the only CDC/ACM port present, and
``NTFC_USB_CDC_PATH`` is the same port as the board names it.
"""

import errno
import glob
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

import pytest
import serial

pytestmark = pytest.mark.dep_config("CONFIG_CDCACM")

SYSFS_TTY = "/sys/class/tty"
DEV_SERIAL_BY_ID = "/dev/serial/by-id"
PROCFS = "/proc"

CDC_DEVICE = os.getenv("NTFC_USB_CDC_DEVICE", "")
CDC_PATH = os.getenv("NTFC_USB_CDC_PATH", "/dev/ttyACM0")

CYCLES = int(os.getenv("NTFC_USB_SUSPEND_CYCLES", "5"))
BAUD = 115200
DELAY_MS = 1000
READ_SECS = 2.0
TAIL_SECS = 1.0
MIN_TAIL_BYTES = 2000


class UsbSuspendError(Exception):
    """Raised when the host cannot be brought into a measurable state."""


@dataclass
class StreamRead:
    """Bytes seen in a read window and in its trailing part."""

    total: int = 0
    tail: int = 0
    error: str = ""


@dataclass
class CycleResult:
    """Outcome of one suspend/resume cycle."""

    suspended: bool = False
    stream: StreamRead = field(default_factory=StreamRead)
    note: str = ""


def read_attr(base: str, name: str) -> Optional[str]:
    """Read one sysfs attribute, or None when it is not readable."""
    try:
        with open(os.path.join(base, name), encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def usb_device_dir(tty_path: str) -> str:
    """Map a tty device node to the sysfs directory of its USB device."""
    tty = os.path.basename(os.path.realpath(tty_path))
    link = os.path.join(SYSFS_TTY, tty, "device")

    if not os.path.exists(link):
        raise UsbSuspendError(f"{tty_path} is not a tty backed by sysfs")

    node = os.path.realpath(link)

    # Walk up from the USB interface to the USB device that owns it.
    while node != "/":
        if os.path.exists(os.path.join(node, "idVendor")):
            return node

        node = os.path.dirname(node)

    raise UsbSuspendError(
        f"{tty_path} is not on a USB device (no idVendor in any parent)"
    )


def find_cdc_ports() -> List[Tuple[str, str]]:
    """Return (port, usb sysfs dir) for every CDC/ACM port present."""
    found = []

    for path in sorted(glob.glob(os.path.join(DEV_SERIAL_BY_ID, "*"))):
        if not os.path.basename(os.path.realpath(path)).startswith("ttyACM"):
            continue

        try:
            found.append((path, usb_device_dir(path)))
        except UsbSuspendError:
            continue

    return found


def autodetect() -> str:
    """Pick the CDC/ACM port when exactly one is present."""
    found = find_cdc_ports()

    if not found:
        raise UsbSuspendError("no CDC/ACM port found, set NTFC_USB_CDC_DEVICE")

    if len(found) > 1:
        listing = "\n".join(
            f"  {path}  ({read_attr(usbdir, 'product')})" for path, usbdir in found
        )
        raise UsbSuspendError(
            f"several CDC/ACM ports present, set NTFC_USB_CDC_DEVICE:\n{listing}"
        )

    return found[0][0]


def port_holders(dev: str) -> List[Tuple[str, str]]:
    """Return (pid, command) of every process holding dev open."""
    real = os.path.realpath(dev)
    holders = []

    for entry in glob.glob(os.path.join(PROCFS, "[0-9]*", "fd", "*")):
        try:
            if os.readlink(entry) != real:
                continue

            pid = entry.split(os.sep)[-3]

            with open(os.path.join(PROCFS, pid, "comm"), encoding="utf-8") as handle:
                holders.append((pid, handle.read().strip()))
        except OSError:
            continue  # process exited, or not ours to inspect

    return sorted(set(holders))


def require_free_port(dev: str, baud: int) -> None:
    """Reject a port that another process holds open."""
    try:
        serial.Serial(os.path.realpath(dev), baud, timeout=0.2).close()
        return
    except OSError as exc:
        if exc.errno != errno.EBUSY:
            raise UsbSuspendError(f"cannot open {dev}: {exc}") from exc

    who = ", ".join(f"{name} (pid {pid})" for pid, name in port_holders(dev))
    raise UsbSuspendError(
        f"{dev} is held open by {who or 'another process'}; an open port "
        "keeps the device active, so it never suspends"
    )


def read_stream(dev: str, seconds: float, tail_seconds: float) -> StreamRead:
    """Read the port for seconds and count what arrives.

    Opening the port is also what resumes a suspended device.
    """
    try:
        port = serial.Serial(os.path.realpath(dev), BAUD, timeout=0.2)
    except OSError as exc:
        return StreamRead(error=str(exc))

    start = time.time()
    result = StreamRead()

    try:
        while True:
            now = time.time() - start

            if now >= seconds:
                break

            chunk = port.read(4096)
            result.total += len(chunk)

            if now >= seconds - tail_seconds:
                result.tail += len(chunk)
    finally:
        port.close()

    return result


def board_cdc_writable() -> bool:
    """Ask the board itself whether its CDC port is writable again."""
    # NSH renders -ENOTCONN as "Transport endpoint is not connected", so a
    # match means the class driver never saw the resume.  Any other outcome,
    # including a timeout, leaves the host-side byte count as the verdict.
    ret = pytest.product.sendCommand(
        f"echo probe > {CDC_PATH}", "not connected", timeout=5
    )

    return ret != 0


class UsbPower:
    """Runtime PM knobs of one USB device, restored on exit."""

    ATTRS = ("control", "autosuspend_delay_ms")

    def __init__(self, usbdir: str) -> None:
        """Snapshot the runtime PM attributes of a USB device."""
        self.usbdir = usbdir
        self.path = os.path.join(usbdir, "power")
        self.saved: Dict[str, Optional[str]] = {
            key: self.get_attr(key) for key in self.ATTRS
        }

    def get_attr(self, name: str) -> Optional[str]:
        """Read one power attribute."""
        return read_attr(self.path, name)

    def set_attr(self, name: str, value: object) -> None:
        """Write one power attribute through sudo tee."""
        target = os.path.join(self.path, name)
        proc = subprocess.run(
            ["sudo", "-n", "tee", target],
            input=str(value).encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )

        if proc.returncode != 0:
            reason = proc.stderr.decode().strip()
            raise UsbSuspendError(f"cannot write {target}: {reason}")

    def restore(self) -> None:
        """Put the saved runtime PM attributes back."""
        for name, value in self.saved.items():
            if value is not None:
                self.set_attr(name, value)

    def arm(self, delay_ms: int) -> None:
        """Re-arm the autosuspend timer.

        Once resumed, a device will not idle out again on its own until
        runtime PM is toggled, so every cycle has to re-allow it.
        """
        self.set_attr("autosuspend_delay_ms", delay_ms)
        self.set_attr("control", "on")
        self.set_attr("control", "auto")

    def wait_suspended(self, timeout: float) -> bool:
        """Wait for runtime_status to reach suspended."""
        deadline = time.time() + timeout

        while time.time() < deadline:
            if self.get_attr("runtime_status") == "suspended":
                return True

            time.sleep(0.1)

        return False


def run_cycle(device: str, power: UsbPower) -> CycleResult:
    """Force one suspend, resume by opening the port, and measure."""
    power.arm(DELAY_MS)
    suspended = power.wait_suspended(DELAY_MS / 1000.0 + 6.0)
    stream = read_stream(device, READ_SECS, TAIL_SECS)
    note = ""

    if suspended:
        # -ENOTCONN *during* suspend is correct on any build; the defect is
        # that it outlives the resume.  Pin the device active so the board is
        # asked about the resumed state.
        power.set_attr("control", "on")
        note = "board-side open ok" if board_cdc_writable() else "board-side -ENOTCONN"

    return CycleResult(suspended, stream, note)


def log_cycle(index: int, result: CycleResult) -> None:
    """Log the outcome of one cycle."""
    if result.stream.error:
        logging.info(
            "[%d] suspended=%-5s OPEN FAILED: %s",
            index,
            result.suspended,
            result.stream.error,
        )
        return

    logging.info(
        "[%d] suspended=%-5s read=%-7d tail=%-7d %s",
        index,
        result.suspended,
        result.stream.total,
        result.stream.tail,
        result.note,
    )


@pytest.fixture(scope="module")
def usb_device() -> Iterator[Tuple[str, UsbPower]]:
    """Resolve the port under test and restore its runtime PM afterwards."""
    if sys.platform != "linux":
        pytest.skip("USB runtime suspend is a Linux host feature")

    if subprocess.run(["sudo", "-n", "true"], check=False).returncode != 0:
        pytest.skip("needs passwordless sudo to write sysfs power attributes")

    try:
        device = CDC_DEVICE or autodetect()
        power = UsbPower(usb_device_dir(device))
        require_free_port(device, BAUD)
    except UsbSuspendError as exc:
        pytest.skip(str(exc))

    logging.info(
        "device %s -> %s, usb %s %s:%s",
        device,
        os.path.realpath(device),
        os.path.basename(power.usbdir),
        read_attr(power.usbdir, "idVendor"),
        read_attr(power.usbdir, "idProduct"),
    )

    try:
        yield device, power
    finally:
        power.restore()


def test_cdcacm_survives_host_suspend(usb_device: Tuple[str, UsbPower]) -> None:
    """The CDC/ACM link must still carry data after every host suspend."""
    device, power = usb_device
    results = []

    for index in range(1, CYCLES + 1):
        result = run_cycle(device, power)
        log_cycle(index, result)
        results.append(result)

    tested = [res for res in results if res.suspended]

    if not tested:
        pytest.skip(
            f"the host never suspended the device; check "
            f"{power.usbdir}/power/runtime_usage, something holds a "
            "runtime PM reference"
        )

    good = [res for res in tested if res.stream.tail >= MIN_TAIL_BYTES]

    assert len(good) == len(tested), (
        f"the link recovered from {len(good)} of {len(tested)} suspends; a "
        "cycle that reads bytes but no tail bytes only flushed the stale CDC "
        "TX buffer on resume"
    )
