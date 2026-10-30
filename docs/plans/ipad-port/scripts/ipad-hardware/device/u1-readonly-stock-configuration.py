#!/var/jb/usr/bin/python3
"""Stream the fixed stock USB configuration plist without changing the iPad.

The caller must authenticate as root. This script opens only Apple's fixed
USBDeviceConfiguration.plist with no symlink following, bounds its size,
checks it is a regular single-link file, and writes its exact bytes to stdout.
It makes no USB request, starts no service, and writes no device file.
"""

import os
import stat
import sys


PATH = "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist"
MAX_BYTES = 2 * 1024 * 1024


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0 or not hasattr(os, "O_NOFOLLOW"):
        return 1
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(PATH, flags)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_size < 1 or before.st_size > MAX_BYTES):
            return 1
        data = bytearray()
        while len(data) <= MAX_BYTES:
            part = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(fd)
        if (len(data) != before.st_size or len(data) > MAX_BYTES or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            return 1
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return 0
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError):
        raise SystemExit(1)
