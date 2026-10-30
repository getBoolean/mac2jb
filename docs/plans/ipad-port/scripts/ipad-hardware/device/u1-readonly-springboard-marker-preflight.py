#!/var/jb/usr/bin/python3
"""Check the exact SpringBoard marker install boundary without changing it.

What this code does: compare the live ClientTruth profile with the private Mac
backup digest, count only the fixed TrollStore, ordinary probe, and marker app
IDs in known roots, and classify the marker IPA stage by its complete digest.
It emits fixed categories only. It launches nothing and writes no file or
USB, SSH, trust, app-registration, or system setting.
"""

import glob
import hashlib
import os
import plistlib
import stat
import sys


PROFILE = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"
STAGE = "/var/mobile/Media/.mac2jb-u1-springboard-marker.tipa"
STAGE_SHA = "2f76c3dca4ea0b19fa352fc274f1bfd5b65a9fc74d39fcd70247e65852965c72"
STAGE_SIZE = 4074
ROOTS = (
    "/var/containers/Bundle/Application/*/",
    "/Applications/",
    "/var/jb/Applications/",
)
NAMES = {
    "store": ("TrollStore*.app", "com.opa334.TrollStore"),
    "ordinary": ("Mac2JBU1-OrdinaryAdmission.app", "dev.mac2jb.u1probe.ordinaryadmission"),
    "marker": ("Mac2JBU1-SpringBoardMarker.app", "dev.mac2jb.u1probe.springboardmarker"),
}


def digest(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise ValueError("unsafe file")
        result = hashlib.sha256()
        total = 0
        while total <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - total))
            if not part:
                break
            total += len(part)
            result.update(part)
        after = os.fstat(fd)
        if total != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("file changed")
        return total, result.hexdigest()
    finally:
        os.close(fd)


def count_app(name, expected):
    paths = [path for root in ROOTS for path in glob.glob(root + name)]
    if len(paths) > 2:
        return "many"
    found = 0
    for path in paths:
        try:
            if os.path.islink(path):
                return "other"
            info = os.lstat(path + "/Info.plist")
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 262144:
                return "other"
            with open(path + "/Info.plist", "rb") as stream:
                value = plistlib.load(stream)
            if not isinstance(value, dict) or value.get("CFBundleIdentifier") != expected:
                return "other"
            found += 1
        except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
            return "other"
    return "zero" if found == 0 else "one" if found == 1 else "many"


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or len(sys.argv[1]) != 64 or any(
            c not in "0123456789abcdef" for c in sys.argv[1]):
        raise SystemExit(64)
    profile = "unchanged" if digest(PROFILE, 1048576)[1] == sys.argv[1] else "changed"
    counts = {label: count_app(*value) for label, value in NAMES.items()}
    try:
        size, sha = digest(STAGE, STAGE_SIZE)
        stage = "verified" if size == STAGE_SIZE and sha == STAGE_SHA else "other"
    except FileNotFoundError:
        stage = "absent"
    except (OSError, ValueError):
        stage = "other"
    print("MARKER_PREFLIGHT profile=" + profile + " store=" + counts["store"] +
          " ordinary=" + counts["ordinary"] + " marker=" + counts["marker"] +
          " stage=" + stage)


if __name__ == "__main__":
    main()
