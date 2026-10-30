#!/var/jb/usr/bin/python3
"""Check the debug ordinary-app admission install boundary without writing files.

What this code does: as root, compare the live ClientTruth.plist with the
privately backed-up SHA-256 supplied by the Mac, classify the new debug ordinary app
as absent/present, classify the earlier probe apps, and confirm the TrollStore helper,
and refuse a preexisting staging path. Only fixed categories leave the iPad.
It does not call TrollStore, launch a probe, change SSH/USB, or write a file.
"""

import glob
import hashlib
import os
import plistlib
import stat
import sys


PROFILE = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"
STAGED = "/var/mobile/Media/.mac2jb-u1-debug-ordinary.tipa"
PATTERNS = (
    "/var/containers/Bundle/Application/*/TrollStore*.app",
    "/Applications/TrollStore*.app",
    "/var/jb/Applications/TrollStore*.app",
    "/var/containers/Bundle/Application/*/Mac2JBU1-Toolbox.app",
    "/Applications/Mac2JBU1-Toolbox.app",
    "/var/jb/Applications/Mac2JBU1-Toolbox.app",
    "/var/containers/Bundle/Application/*/Mac2JBU1-Admission.app",
    "/Applications/Mac2JBU1-Admission.app",
    "/var/jb/Applications/Mac2JBU1-Admission.app",
    "/var/containers/Bundle/Application/*/Mac2JBU1-DebugOrdinary.app",
    "/Applications/Mac2JBU1-DebugOrdinary.app",
    "/var/jb/Applications/Mac2JBU1-DebugOrdinary.app",
)


def digest(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise RuntimeError("unsafe profile")
        sha = hashlib.sha256()
        total = 0
        while total <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - total))
            if not part:
                break
            sha.update(part)
            total += len(part)
        after = os.fstat(fd)
        if total != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError("profile changed during read")
        return sha.hexdigest()
    finally:
        os.close(fd)


def app_id(path):
    if os.path.islink(path):
        return None
    info = path + "/Info.plist"
    try:
        item = os.lstat(info)
        if not stat.S_ISREG(item.st_mode) or not 0 < item.st_size <= 262144:
            return None
        with open(info, "rb") as stream:
            tree = plistlib.load(stream)
        return tree.get("CFBundleIdentifier") if isinstance(tree, dict) else None
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
        return None


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit(65)
    expected = sys.argv[1]
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise SystemExit(66)
    profile = "unchanged" if digest(PROFILE, 1048576) == expected else "changed"
    paths = [p for pattern in PATTERNS for p in glob.glob(pattern)]
    if len(paths) > 32:
        raise SystemExit(67)
    stores = [p for p in paths if app_id(p) == "com.opa334.TrollStore"]
    toolboxes = [p for p in paths if app_id(p) == "dev.mac2jb.u1probe.toolbox"]
    admissions = [p for p in paths if app_id(p) == "dev.mac2jb.u1probe.admission"]
    debug = [p for p in paths if app_id(p) == "dev.mac2jb.u1probe.debugordinary"]
    if len(stores) != 1 or len(toolboxes) > 1 or len(admissions) > 1 or len(debug) > 1:
        def count_category(items):
            return "0" if not items else "1" if len(items) == 1 else "many"
        print("DEBUG_ORDINARY_COUNTS store=" + count_category(stores) +
              " toolbox=" + count_category(toolboxes) +
              " platform=" + count_category(admissions) +
              " ordinary=" + count_category(debug), flush=True)
        raise SystemExit(68)
    helper = stores[0] + "/trollstorehelper"
    info = os.lstat(helper)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_mode & 0o111:
        raise SystemExit(69)
    try:
        os.lstat(STAGED)
        stage = "present"
    except FileNotFoundError:
        stage = "absent"
    print("DEBUG_ORDINARY_PREFLIGHT profile=" + profile + " app=" +
          ("present" if debug else "absent") +
          " toolbox=" + ("present" if toolboxes else "absent") +
          " platform=" + ("present" if admissions else "absent") +
          " helper=present stage=" + stage)


if __name__ == "__main__":
    main()
