#!/var/jb/usr/bin/python3
"""Install the one hash-pinned U1 toolbox with the existing TrollStore helper.

What this code does:
1. Requires root, the expected pre-install ClientTruth digest, the exact
   staged IPA digest, a unique installed TrollStore helper, and no toolbox.
2. Calls that installed helper once with `install custom` for the fixed IPA.
   This may create an app container, registration, marker, icon cache entries,
   and temporary extraction files. TrollStore may rewrite ClientTruth.plist
   and restart profiled; the host has private byte, ACL, and metadata backups.
3. Prints only the helper status and whether the profile changed and toolbox
   appeared. It suppresses raw helper logs and never invokes a probe binary.

The installed app, staged IPA, and potential profile change are tracked in
docs/ipad/device-cleanup-ledger.md. A failed or interrupted install may leave
partial app state; inspect that state before attempting cleanup or retry.
"""

import glob
import hashlib
import os
import plistlib
import signal
import stat
import subprocess
import sys


STAGED = "/var/mobile/Media/.mac2jb-u1-stdout-toolbox.tipa"
PROFILE = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"
IPA_SHA = "c97a5d9f60a67329b3b1946e478e95f1afc903d51a7cb7902d8dbdc9a4309f13"
GLOBS = ("/var/containers/Bundle/Application/*/TrollStore*.app",
         "/Applications/TrollStore*.app", "/var/jb/Applications/TrollStore*.app",
         "/var/containers/Bundle/Application/*/Mac2JBU1-Toolbox.app",
         "/Applications/Mac2JBU1-Toolbox.app",
         "/var/jb/Applications/Mac2JBU1-Toolbox.app")


def digest(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise RuntimeError("unsafe input")
        h = hashlib.sha256()
        total = 0
        while total <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - total))
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        if (total != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise RuntimeError("changed input")
        return h.hexdigest()
    finally:
        os.close(fd)


def app_id(path):
    try:
        if os.path.islink(path):
            return None
        info = path + "/Info.plist"
        st = os.lstat(info)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 262144:
            return None
        with open(info, "rb") as file:
            tree = plistlib.load(file)
        return tree.get("CFBundleIdentifier") if isinstance(tree, dict) else None
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
        return None


def app_paths():
    paths = []
    for pattern in GLOBS:
        paths.extend(glob.glob(pattern))
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
    if len(store) != 1 or toolbox:
        raise SystemExit(69)
    helper = store[0] + "/trollstorehelper"
    info = os.lstat(helper)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_mode & 0o111:
        raise SystemExit(70)
    process = subprocess.Popen([helper, "install", "custom", STAGED],
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        status = str(process.wait(timeout=90))
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        status = "timeout"
    profile = "unchanged" if digest(PROFILE, 1048576) == original else "changed"
    installed = any(app_id(p) == "dev.mac2jb.u1probe.toolbox" for p in app_paths())
    print("TOOLBOX_INSTALL helper=" + status)
    print("TOOLBOX_INSTALL profile=" + profile)
    print("TOOLBOX_INSTALL toolbox=" + ("present" if installed else "absent"))


if __name__ == "__main__":
    main()
