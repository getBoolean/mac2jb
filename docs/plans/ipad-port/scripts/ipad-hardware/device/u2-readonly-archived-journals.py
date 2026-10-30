#!/var/jb/usr/bin/python3
"""Verify both failed U2 journals are archived exactly and active name absent.

Uses no-follow directory descriptors and exact root/mode/link/hash checks. It
reads no recipe values into output and changes no file, service or controller.
"""

import hashlib
import os
import stat


STATE = "/var/jb/var/lib/mac2jb-u2-native"
ARCHIVES = (
    ("restore-journal.oldboot-77caed18.json",
     "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"),
    ("restore-journal.oldboot-v2-f5934b3a.json",
     "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"),
)


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        details = os.fstat(directory)
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid != 0 or
                stat.S_IMODE(details.st_mode) != 0o700):
            raise ValueError("unsafe state directory")
        try:
            active = os.stat("restore-journal.json", dir_fd=directory,
                             follow_symlinks=False)
        except FileNotFoundError:
            active = None
        if active is not None:
            raise ValueError("active journal exists")
        for name, digest in ARCHIVES:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                        info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                        not 0 < info.st_size <= 2_000_000):
                    raise ValueError("unsafe archive")
                data = bytearray()
                while len(data) < info.st_size:
                    part = os.read(fd, info.st_size - len(data))
                    if not part:
                        raise ValueError("short archive")
                    data.extend(part)
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError("archive changed")
            finally:
                os.close(fd)
    finally:
        os.close(directory)
    print("U2_ARCHIVES first=exact v2=exact active=absent")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        print("U2_ARCHIVES rejected")
        raise SystemExit(1)
