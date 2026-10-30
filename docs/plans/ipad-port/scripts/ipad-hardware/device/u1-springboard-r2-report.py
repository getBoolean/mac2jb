#!/var/jb/usr/bin/python3
"""Inspect or privately stream one fixed SpringBoard R2 app report.

What this code does: root locates exactly one data container by its bounded
Apple metadata, then opens only that app's fixed report with O_NOFOLLOW. State
mode emits a category; capture mode streams at most 1 MiB of verified regular,
single-link, mobile-owned mode-0600 JSON to the pinned Mac SSH caller. Neither
mode writes to the iPad or prints container paths. The Mac keeps captured bytes
in ignored mode-0600 build storage. No USB, SSH, trust, or system setting changes.
"""

import glob
import os
import plistlib
import stat
import sys


ROOT = "/var/mobile/Containers/Data/Application"
IDS = {
    "baseline": "dev.mac2jb.u1probe.r2baseline",
    "setdescription": "dev.mac2jb.u1probe.r2setdescription",
}
NAME = ".mac2jb-u1-r2-report.json"
LIMIT = 1_048_576


def container(label):
    candidates = glob.glob(ROOT + "/*")
    if len(candidates) > 2048:
        raise ValueError("too many containers")
    matches = []
    for path in candidates:
        try:
            if os.path.islink(path) or not os.path.isdir(path):
                continue
            metadata = path + "/.com.apple.mobile_container_manager.metadata.plist"
            info = os.lstat(metadata)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 8192:
                continue
            fd = os.open(metadata, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
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
        raise ValueError("container cardinality")
    return matches[0]


def report(path):
    tmp = path + "/tmp"
    info = os.lstat(tmp)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("unsafe tmp")
    try:
        fd = os.open(tmp + "/" + NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid == 501 and
                before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                0 < before.st_size <= LIMIT):
            raise ValueError("unsafe report")
        data = os.read(fd, LIMIT + 1)
        after = os.fstat(fd)
        if len(data) != before.st_size or (before.st_dev, before.st_ino,
                before.st_size, before.st_mtime_ns) != (after.st_dev,
                after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("unstable report")
        return data
    finally:
        os.close(fd)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] not in ("state", "capture") or sys.argv[2] not in IDS:
        raise SystemExit(64)
    label = sys.argv[2]
    try:
        data = report(container(label))
    except (OSError, ValueError):
        if sys.argv[1] == "state":
            print("SPRINGBOARD_R2_REPORT profile=" + label + " state=other")
            return
        raise SystemExit(65)
    if sys.argv[1] == "state":
        print("SPRINGBOARD_R2_REPORT profile=" + label + " state=" + ("absent" if data is None else "present"))
    elif data is None:
        raise SystemExit(66)
    else:
        sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()
