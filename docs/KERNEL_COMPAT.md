# Kernel Compatibility

This document describes the kernel version support range for crypto2dev and
the API changes handled by `src/crypto2dev_compat.h`.

## Overview

`src/crypto2dev_compat.h` centralizes all kernel version guards.
No `.c` file may contain a bare `#if LINUX_VERSION_CODE` check.
When an API changes between kernel versions, add a shim here under a
`CRYPTO2DEV_` prefixed name and include this header in the affected file.

## Supported Versions

| Kernel version | Distro                 | Status   |
|----------------|------------------------|----------|
| 5.15 LTS       | Ubuntu 22.04           | Tested   |
| 6.8            | Ubuntu 24.04           | Tested   |
| 5.10 – 5.14    | (various)              | Untested |
| 5.16 – 6.7     | (various)              | Untested |

CI (``tests/ci/test-on-aws.sh``) defaults to Ubuntu 22.04 (5.15) and
supports Ubuntu 24.04 (6.8) via ``UBUNTU_VERSION=24.04``.

## API Changes Handled

| API               | Changed in | What happened                    | Macro provided          |
|-------------------|------------|----------------------------------|-------------------------|
| ``no_llseek``     | 6.8        | Removed from ``<linux/fs.h>``    | ``CRYPTO2DEV_NO_LLSEEK`` |

**CRYPTO2DEV_NO_LLSEEK**: on kernel < 6.8 this expands to the kernel's own
``no_llseek``; on 6.8+ it expands to an inline stub that returns ``-ESPIPE``,
matching the behavior of the removed function.

``copy_from_user`` / ``copy_to_user`` are stable across the full target range
and require no shim.  Both return the number of bytes *not* copied; zero means
success.  This contract is documented in the header as a reminder to callers.

## Known Issues

None.

## Adding a New Kernel Version

1. Identify the breaking API (removed function, changed signature, new
   required call).
2. Add a shim in ``src/crypto2dev_compat.h`` guarded by
   ``LINUX_VERSION_CODE``.  Name the macro ``CRYPTO2DEV_<ORIGINAL_NAME>``
   or, for a wholly new abstraction, choose a descriptive ``CRYPTO2DEV_``
   prefix.
3. Include ``crypto2dev_compat.h`` in every ``.c`` file that uses the shim
   (it is safe to include it unconditionally — the header is idempotent).
4. Replace any direct use of the changed API in ``.c`` files with the new
   macro.
5. Test on CI against both the oldest and newest supported kernels.
