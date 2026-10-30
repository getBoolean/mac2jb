#!/var/jb/usr/bin/python3
"""Install the separately staged U1 ordinary admission app through TrollStore once.

What this code does: as root, require the backed-up ClientTruth.plist digest,
the exact staged archive digest, one TrollStore helper, and no ordinary
admission app. It records whether the earlier probe apps are present, but
does not require them for this distinct installation. It calls `trollstorehelper install custom` for only
the fixed archive, waits at most 90 seconds, and reports fixed status fields.
TrollStore can create an app container, registration, icon caches, a marker,
and temporary files, and can rewrite ClientTruth.plist/restart profiled. The
original profile bytes, metadata, and ACL are backed up privately on the Mac.
This helper does not launch probe code or alter SSH/USB configuration. A
failed or interrupted install needs inspection before retry or cleanup.
"""

import glob
import hashlib
import os
import plistlib
import signal
import stat
import subprocess
import sys


STAGED = "/var/mobile/Media/.mac2jb-u1-ordinary-admission.tipa"
PROFILE = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"
IPA_SHA = "7dd7817c863b7add70a8d13f3764b05db8d39837283706ceb99cef635cdec961"
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
    "/var/containers/Bundle/Application/*/Mac2JBU1-OrdinaryAdmission.app",
    "/Applications/Mac2JBU1-OrdinaryAdmission.app",
    "/var/jb/Applications/Mac2JBU1-OrdinaryAdmission.app",
)


def digest(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise RuntimeError("unsafe input")
        value = hashlib.sha256()
        total = 0
        while total <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - total))
            if not part:
                break
            value.update(part)
            total += len(part)
        after = os.fstat(fd)
        if total != before.st_size or (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError("changed input")
        return value.hexdigest()
    finally:
        os.close(fd)


def app_id(path):
    try:
        if os.path.islink(path):
            return None
        info = path + "/Info.plist"
        item = os.lstat(info)
        if not stat.S_ISREG(item.st_mode) or not 0 < item.st_size <= 262144:
            return None
        with open(info, "rb") as stream:
            tree = plistlib.load(stream)
        return tree.get("CFBundleIdentifier") if isinstance(tree, dict) else None
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
        return None


def app_paths():
    paths = [p for pattern in PATTERNS for p in glob.glob(pattern)]
    if len(paths) > 32:
        raise RuntimeError("too many app candidates")
    return paths


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit(65)
    original = sys.argv[1]
    if len(original) != 64 or any(c not in "0123456789abcdef" for c in original):
        raise SystemExit(66)
    if digest(PROFILE, 1048576) != original:
        raise SystemExit(67)
    if digest(STAGED, 1048576) != IPA_SHA:
        raise SystemExit(68)
    paths = app_paths()
    store = [p for p in paths if app_id(p) == "com.opa334.TrollStore"]
    toolbox = [p for p in paths if app_id(p) == "dev.mac2jb.u1probe.toolbox"]
    platform = [p for p in paths if app_id(p) == "dev.mac2jb.u1probe.admission"]
    ordinary = [p for p in paths if app_id(p) == "dev.mac2jb.u1probe.ordinaryadmission"]
    if len(store) != 1 or len(toolbox) > 1 or len(platform) > 1 or ordinary:
        raise SystemExit(69)
    helper = store[0] + "/trollstorehelper"
    item = os.lstat(helper)
    if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or not item.st_mode & 0o111:
        raise SystemExit(70)
    process = subprocess.Popen([helper, "install", "custom", STAGED],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        status = str(process.wait(timeout=90))
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        status = "timeout"
    profile = "unchanged" if digest(PROFILE, 1048576) == original else "changed"
    paths = app_paths()
    ordinary = [p for p in paths if app_id(p) == "dev.mac2jb.u1probe.ordinaryadmission"]
    toolbox = [p for p in paths if app_id(p) == "dev.mac2jb.u1probe.toolbox"]
    platform = [p for p in paths if app_id(p) == "dev.mac2jb.u1probe.admission"]
    print("ORDINARY_INSTALL helper=" + status)
    print("ORDINARY_INSTALL profile=" + profile)
    print("ORDINARY_INSTALL app=" + ("one" if len(ordinary) == 1 else "other"))
    def count_category(items):
        return "zero" if not items else "one" if len(items) == 1 else "many"
    print("ORDINARY_INSTALL toolbox=" + count_category(toolbox))
    print("ORDINARY_INSTALL platform=" + count_category(platform))


if __name__ == "__main__":
    main()
