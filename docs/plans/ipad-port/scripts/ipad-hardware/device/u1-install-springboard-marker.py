#!/var/jb/usr/bin/python3
"""Install one exact, already-staged SpringBoard launch-marker app.

What this code does: as root, require the unchanged backed-up ClientTruth
profile, the exact staged IPA bytes, one TrollStore helper, the ordinary probe
present, and this marker app absent; then invoke TrollStore install custom
once with a 90-second bound. It reports fixed status categories and rechecks
the profile and app. TrollStore may create app/registration/cache state and
conditionally change ClientTruth; its original bytes, metadata, and ACL are
backed up privately. It does not launch the marker or alter USB/SSH policy.
An interrupted install must be inspected before retry or cleanup.
"""

import glob
import hashlib
import os
import plistlib
import signal
import stat
import subprocess
import sys


STAGE = "/var/mobile/Media/.mac2jb-u1-springboard-marker.tipa"
STAGE_SHA = "2f76c3dca4ea0b19fa352fc274f1bfd5b65a9fc74d39fcd70247e65852965c72"
PROFILE = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"
ROOTS = (
    "/var/containers/Bundle/Application/*/",
    "/Applications/",
    "/var/jb/Applications/",
)


def digest(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise ValueError("unsafe file")
        sha = hashlib.sha256()
        total = 0
        while total <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - total))
            if not part:
                break
            total += len(part)
            sha.update(part)
        after = os.fstat(fd)
        if total != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("file changed")
        return total, sha.hexdigest()
    finally:
        os.close(fd)


def app_paths(name, expected):
    paths = [path for root in ROOTS for path in glob.glob(root + name)]
    if len(paths) > 2:
        raise ValueError("too many app paths")
    for path in paths:
        if os.path.islink(path):
            raise ValueError("linked app")
        info = os.lstat(path + "/Info.plist")
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 262144:
            raise ValueError("unsafe app info")
        with open(path + "/Info.plist", "rb") as stream:
            tree = plistlib.load(stream)
        if not isinstance(tree, dict) or tree.get("CFBundleIdentifier") != expected:
            raise ValueError("app ID mismatch")
    return paths


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or len(sys.argv[1]) != 64 or any(
            c not in "0123456789abcdef" for c in sys.argv[1]):
        raise SystemExit(64)
    original = sys.argv[1]
    if digest(PROFILE, 1048576)[1] != original:
        raise SystemExit(65)
    if digest(STAGE, 4074) != (4074, STAGE_SHA):
        raise SystemExit(66)
    stores = app_paths("TrollStore*.app", "com.opa334.TrollStore")
    ordinary = app_paths("Mac2JBU1-OrdinaryAdmission.app", "dev.mac2jb.u1probe.ordinaryadmission")
    marker = app_paths("Mac2JBU1-SpringBoardMarker.app", "dev.mac2jb.u1probe.springboardmarker")
    if len(stores) != 1 or len(ordinary) != 1 or marker:
        raise SystemExit(67)
    helper = stores[0] + "/trollstorehelper"
    info = os.lstat(helper)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_mode & 0o111:
        raise SystemExit(68)
    process = subprocess.Popen([helper, "install", "custom", STAGE],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        status = str(process.wait(timeout=90))
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        status = "timeout"
    profile = "unchanged" if digest(PROFILE, 1048576)[1] == original else "changed"
    marker = app_paths("Mac2JBU1-SpringBoardMarker.app", "dev.mac2jb.u1probe.springboardmarker")
    print("MARKER_INSTALL helper=" + status + " profile=" + profile +
          " app=" + ("one" if len(marker) == 1 else "other"))


if __name__ == "__main__":
    main()
