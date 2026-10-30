#!/var/jb/usr/bin/python3
"""Stream the exact failed v7 journal to the Mac without changing the iPad.

The host runs this source over pinned root SSH. It checks the state directory
and journal with no-follow descriptors and sends only the bounded raw journal
to stdout for a private Mac backup. It never touches the controller or writes
an iPad file.
"""

import hashlib
import os
import stat
import sys

STATE = "/var/jb/var/lib/mac2jb-u2-native"
EXPECTED = "9be6c2b6bad2783f80445981f88fc159ed8c8c3d8c9e56ebf4c762a8665556c1"


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("unsafe state directory")
        fd = os.open("restore-journal.json", os.O_RDONLY | os.O_NOFOLLOW,
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                    not 0 < info.st_size <= 2_000_000):
                raise ValueError("unsafe journal")
            data = bytearray()
            while len(data) < info.st_size:
                chunk = os.read(fd, info.st_size - len(data))
                if not chunk:
                    raise ValueError("short journal")
                data.extend(chunk)
            if hashlib.sha256(data).hexdigest() != EXPECTED:
                raise ValueError("journal changed")
            sys.stdout.buffer.write(data)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        raise SystemExit(1)
