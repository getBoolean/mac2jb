#!/var/jb/usr/bin/python3
"""Exclusively stage the exact SpringBoard marker IPA in iPad Media.

What this code does: check the complete hash-pinned IPA from stdin, create
only the fixed previously absent Media path with O_EXCL/O_NOFOLLOW and mode
0600, fsync, and verify its complete readback. It never installs or launches
an app and changes no USB, SSH, trust, registry, or system file. An interrupted
write may leave a partial file; its exact path is in the cleanup ledger.
"""

import hashlib
import os
import stat
import sys


DEST = "/var/mobile/Media/.mac2jb-u1-springboard-marker.tipa"
SIZE = 4074
SHA256 = "2f76c3dca4ea0b19fa352fc274f1bfd5b65a9fc74d39fcd70247e65852965c72"


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise SystemExit(64)
    data = sys.stdin.buffer.read(SIZE + 1)
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit(65)
    fd = os.open(DEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < SIZE:
            count = os.write(fd, data[offset:])
            if count <= 0:
                raise SystemExit(66)
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(DEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != SIZE):
            raise SystemExit(67)
        sha = hashlib.sha256()
        remaining = SIZE
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                raise SystemExit(68)
            sha.update(part)
            remaining -= len(part)
        if sha.hexdigest() != SHA256:
            raise SystemExit(69)
    finally:
        os.close(fd)
    print("MARKER_STAGE verified")


if __name__ == "__main__":
    main()
