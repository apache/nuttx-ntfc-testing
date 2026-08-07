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

import json
import logging
import os
from typing import Any, Dict, List

import pytest
from ntfc.lib.elf.elf_parser import ElfParser

"""
LTP test configuration for pytest
Handles test case generation and filtering without fixture dependencies
"""


class LTPManager:
    """Manages LTP test cases and configurations"""

    def __init__(self, ltp_cmds: List[str] = None):
        self.cmds = ltp_cmds or []
        self.json_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "expect.json"
        )
        self.data = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load LTP configuration from expect.json"""
        default_data = {
            "black_list": [],
            "crash_list": [],
            "failed_list": [],
            "except_list": {},
            "timeout": {},
        }

        try:
            if os.path.exists(self.json_file):
                with open(self.json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    logging.info(f"Loaded LTP configuration from {self.json_file}")
                    return data
            else:
                logging.warning("expect.json not found, using default configuration")
                return default_data
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in {self.json_file}: {e}")
            return default_data
        except Exception as e:
            logging.error(f"Failed to load LTP configuration: {e}")
            return default_data

    def get_skip_cases(self) -> List[str]:
        """Get list of test cases to skip"""
        skip_list = []
        for category in ["black_list", "crash_list", "failed_list"]:
            skip_list.extend(self.data.get(category, []))
        return skip_list

    def get_expect_list(self, case: str) -> List[str]:
        """Get expected output patterns for a test case"""
        expect_list = self.data.get("expect_list", {})

        for pattern, cases in expect_list.items():
            if case in cases:
                return [pattern]

        # Default expectations
        return ["PASSED", "passed", "Passed", "PASS", "skipped"]

    def get_case_timeout(self, case: str) -> int:
        """Get timeout for a specific test case"""
        timeout_config = self.data.get("timeout", {})

        for timeout_str, cases in timeout_config.items():
            try:
                timeout = int(timeout_str)
                if case in cases:
                    return timeout
            except ValueError:
                continue

        return 40  # Default timeout

    def generate_unique_case(self, case: str) -> str:
        """Generate unique case name with parameters"""
        if "ltp_stress_semaphores_multi_con_pro" in case:
            return f"{case} 2"
        return case


def _extract_ltp_functions(elf_path: str) -> List[str]:
    """Extract LTP test functions (ltp_*_main) from ELF file"""
    if not elf_path or not os.path.exists(elf_path):
        return []

    parser = ElfParser(elf_path)
    ltp_symbols = parser.get_symbols_by_pattern("ltp_", "_main")
    return [symbol.name[: -len("_main")] for symbol in ltp_symbols]


def _extract_ltp_applications(bindir: str) -> List[str]:
    """Extract LTP test applications (ltp_*) from a binary directory.

    Kernel builds install every application as a standalone binary, so
    the test cases are file names instead of symbols in the OS image.
    """
    if not bindir or not os.path.isdir(bindir):
        return []

    return sorted(name for name in os.listdir(bindir) if name.startswith("ltp_"))


def load_task_config() -> Dict[str, Any]:
    """Load task configuration from default_config.yaml"""
    try:
        if hasattr(pytest, "task") and pytest.task:
            return pytest.task
    except ImportError:
        logging.error("No pytest.task object")
        pass

    # Fallback: try to load from file
    return {}


@pytest.hookimpl(trylast=True)
def pytest_generate_tests(metafunc):
    """Generate LTP test cases during collection phase"""
    if (
        "ltp_case" not in metafunc.fixturenames
        or "ltp_expected" not in metafunc.fixturenames
    ):
        return

    logging.info("Generating LTP test cases...")

    # Get ELF path from task configuration
    task_config = load_task_config()
    core_conf = task_config.get("cores", {})
    main_core_conf = core_conf.get("core0", {})
    elf_path = main_core_conf.get("elf_path", "")

    if not elf_path:
        logging.error("ELF path not configured")
        # Generate dummy case to avoid test failure
        metafunc.parametrize(
            "ltp_case, ltp_expected, timeout",
            [("dummy_case", ["PASSED"], 40)],
            ids=["dummy"],
        )
        return

    if not os.path.exists(elf_path):
        logging.error(f"ELF file not found: {elf_path}")
        metafunc.parametrize(
            "ltp_case, ltp_expected, timeout",
            [("dummy_case", ["PASSED"], 40)],
            ids=["dummy"],
        )
        return

    # Extract LTP test cases from the application binaries on kernel
    # builds, from the OS image symbols otherwise
    ltp_cases = _extract_ltp_applications(main_core_conf.get("app_bindir", ""))
    if not ltp_cases:
        ltp_cases = _extract_ltp_functions(elf_path)

    if not ltp_cases:
        logging.warning("No LTP test cases found in ELF file")
        metafunc.parametrize(
            "ltp_case, ltp_expected, timeout",
            [("dummy_case", ["PASSED"], 40)],
            ids=["dummy"],
        )
        return

    # Create LTP manager
    ltp_manager = LTPManager(ltp_cases)

    # Generate test parameters
    parameters = []
    for case in ltp_cases:
        parameters.append(
            (
                ltp_manager.generate_unique_case(case),
                ltp_manager.get_expect_list(case),
                ltp_manager.get_case_timeout(case),
            )
        )

    metafunc.parametrize(
        "ltp_case, ltp_expected, timeout",
        parameters,
        ids=ltp_cases,
    )

    # Cache LTP manager for collection filtering
    pytest.ltp_manager = ltp_manager
    logging.info(f"Generated {len(ltp_cases)} LTP test cases")


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    """Modify test items to skip blacklisted cases"""
    if not hasattr(pytest, "ltp_manager"):
        return

    ltp_manager = pytest.ltp_manager
    skip_list = ltp_manager.get_skip_cases()

    if not skip_list:
        return

    logging.info(f"{len(skip_list)} LTP cases will be skipped")

    skipped_count = 0
    for item in items:
        if not hasattr(item, "callspec"):
            continue

        # Extract test case parameter
        case_param = None
        if hasattr(item.callspec, "params"):
            params = item.callspec.params
            if "ltp_case" in params:
                case_param = params["ltp_case"]

        if case_param and case_param in skip_list:
            reason = f"Skipping blacklisted LTP case: {case_param}"
            item.add_marker(pytest.mark.skip(reason=reason))
            skipped_count += 1

    if skipped_count > 0:
        logging.info(f"Skipped {skipped_count} LTP test cases")
