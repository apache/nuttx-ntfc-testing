# nuttx-ntfc-testing

This repository contains test cases compatible with the NTFC tool for
Apache NuttX RTOS. For details, please visit the NTFC repository.

### Preparing the image for testing

NuttX image requirements for tests:

- ``CONFIG_DEBUG_SYMBOLS`` must be set.

- NSH must be enabled (``CONFIG_SYSTEM_NSH``); the init entry point may be
  either ``nsh_main`` or ``init_main`` (nxinit)

- ``CONFIG_DEBUG_FEATURES=y`` and ``CONFIG_DEBUG_ASSERTIONS=y``
  are recommended.
