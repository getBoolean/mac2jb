#!/var/jb/usr/bin/python3
"""Exclusively stage the exact U1 debug ordinary-app admission archive in Media.

What this code does: root Python reads exactly one hash-pinned archive from
stdin, verifies its bytes in memory, creates one fixed Media file with
O_EXCL/O_NOFOLLOW and mode 0600, fsyncs it, then reads it back and checks its
digest. It never invokes TrollStore or a probe and never touches USB, SSH,
trust, app registration, or system files. An interrupted write can leave a
partial file; its exact path is in the cleanup ledger and must be inspected
before removal or retry. The host controls a short SSH deadline.
"""

import hashlib
import os
import stat
import sys


DEST = "/var/mobile/Media/.mac2jb-u1-debug-ordinary.tipa"
SIZE = 232168
SHA256 = "3f2875acb9da2da2ebad2424aeb9570aa15bfaf49865f225458784281d21d37f"


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise SystemExit(65)
    data = sys.stdin.buffer.read(SIZE + 1)
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit(66)
    fd = os.open(DEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < SIZE:
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(DEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != SIZE):
            raise SystemExit(67)
        actual = hashlib.sha256()
        remaining = SIZE
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                raise SystemExit(68)
            actual.update(part)
            remaining -= len(part)
        if actual.hexdigest() != SHA256:
            raise SystemExit(69)
    finally:
        os.close(fd)
    print("DEBUG_ORDINARY_STAGE verified")


if __name__ == "__main__":
    main()
