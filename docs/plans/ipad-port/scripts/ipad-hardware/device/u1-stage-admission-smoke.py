#!/var/jb/usr/bin/python3
"""Stage one fixed, entitlement-free C launch check for U1.

What this code does: as root, read one exact hash-pinned binary from standard
input, exclusively create it in the existing Media directory, verify the
complete bytes, then make only that file executable. The file prints one
marker and exits; this staging script does not launch it. A failed or
interrupted stage can leave that exact file for cleanup. No system file, SSH
setting, USB state, or trust cache is changed.
"""

import hashlib
import os
import stat
import sys


PARENT = "/var/mobile/Media"
NAME = ".mac2jb-u1-admission-smoke"
SIZE = 49840
SHA256 = "9d4750ca37548b30653c4550b1307b5fc5da5a65e9ec0cadeaaf23f002e231e0"


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise SystemExit(65)
    data = sys.stdin.buffer.read(SIZE + 1)
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit(66)
    parent = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISDIR(os.fstat(parent).st_mode):
            raise SystemExit(67)
        fd = os.open(NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        try:
            written = 0
            while written < SIZE:
                written += os.write(fd, data[written:])
            os.fsync(fd)
            os.fchmod(fd, 0o755)
            os.fsync(fd)
        finally:
            os.close(fd)
        fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o755 or
                    info.st_size != SIZE):
                raise SystemExit(68)
            digest = hashlib.sha256()
            remaining = SIZE
            while remaining:
                part = os.read(fd, min(65536, remaining))
                if not part:
                    raise SystemExit(69)
                digest.update(part)
                remaining -= len(part)
            if digest.hexdigest() != SHA256:
                raise SystemExit(70)
        finally:
            os.close(fd)
        print("SMOKE_STAGE verified")
    finally:
        os.close(parent)


if __name__ == "__main__":
    main()
