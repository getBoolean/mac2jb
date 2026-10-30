#!/var/jb/usr/bin/python3
"""Remove one captured R2 report so its app can run a second exclusive round.

What this code does: root locates exactly one fixed app data container by
bounded metadata, opens its tmp directory without following links, reads the
fixed mode-0600 mobile-owned single-link report, checks its complete SHA-256
against the Mac's already captured copy, then unlinks only that directory
entry. It fsyncs the app tmp directory. It never touches system, USB, SSH,
trust, another app, or a global temporary file. The ledger tracks this removal.
"""

import glob
import hashlib
import os
import plistlib
import stat
import sys


ROOT = "/var/mobile/Containers/Data/Application"
IDS = {"baseline": "dev.mac2jb.u1probe.r2baseline", "setdescription": "dev.mac2jb.u1probe.r2setdescription"}
NAME = ".mac2jb-u1-r2-report.json"


def main():
    if (os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] not in IDS or
            len(sys.argv[2]) != 64 or any(c not in "0123456789abcdef" for c in sys.argv[2])):
        raise SystemExit(64)
    label = sys.argv[1]
    candidates = glob.glob(ROOT + "/*")
    if len(candidates) > 2048:
        raise SystemExit(65)
    matches = []
    for path in candidates:
        try:
            if os.path.islink(path) or not os.path.isdir(path):
                continue
            metadata = path + "/.com.apple.mobile_container_manager.metadata.plist"
            fd = os.open(metadata, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 8192:
                    continue
                data = os.read(fd, 8193)
                if len(data) > 8192:
                    continue
                value = plistlib.loads(data)
                if isinstance(value, dict) and value.get("MCMMetadataIdentifier") == IDS[label]:
                    matches.append(path)
            finally:
                os.close(fd)
        except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
            continue
    if len(matches) != 1:
        raise SystemExit(66)
    directory = os.open(matches[0] + "/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if not (stat.S_ISREG(before.st_mode) and before.st_uid == 501 and
                    before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                    0 < before.st_size <= 1_048_576):
                raise SystemExit(67)
            data = os.read(fd, 1_048_577)
            after = os.fstat(fd)
            if (len(data) != before.st_size or hashlib.sha256(data).hexdigest() != sys.argv[2] or
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise SystemExit(68)
            named = os.stat(NAME, dir_fd=directory, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
                raise SystemExit(69)
            os.unlink(NAME, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    print("SPRINGBOARD_R2_CLEAR profile=" + label + " verified")


if __name__ == "__main__":
    main()
