#!/var/jb/usr/bin/python3
"""Verify the exact staged U1 toolbox bytes without changing them.

What this code does: open one fixed Media path without following a symlink,
require a regular single-link file of bounded size, stream it once for a
SHA-256 digest, and print only size and digest. It does not run the IPA or
write to the iPad. The host checks the result against its pinned artifact.
"""

import hashlib
import os
import stat


PATH = "/var/mobile/Media/.mac2jb-u1-stdout-toolbox.tipa"
LIMIT = 1048576


def main():
    if os.geteuid() != 0:
        raise SystemExit(65)
    fd = os.open(PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= LIMIT):
            raise SystemExit(66)
        digest = hashlib.sha256()
        size = 0
        while size <= LIMIT:
            chunk = os.read(fd, min(65536, LIMIT + 1 - size))
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(fd)
        if (size != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise SystemExit(67)
    finally:
        os.close(fd)
    print("TOOLBOX_STAGE size=" + str(size) + " sha256=" + digest.hexdigest())


if __name__ == "__main__":
    main()
