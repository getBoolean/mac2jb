#!/var/jb/usr/bin/python3
"""Preflight, stage, or install one fixed SpringBoard R2 app.

What this code does: as root, compare the live ClientTruth.plist to the
privately backed-up digest supplied by the pinned Mac host, count only the
two fixed R2 apps and one TrollStore helper, and inspect the two fixed Media
stages. Preflight reads only. Stage reads one exact hash-pinned IPA from stdin,
exclusively creates its own Media file, fsyncs, and verifies full readback.
Install requires the unchanged profile, one verified stage, and no target app,
then invokes TrollStore's helper once for that exact stage. It reports fixed
categories only and never launches the probe or changes USB/SSH settings.
TrollStore can create app/container/registration state and conditionally
rewrite ClientTruth.plist; the original bytes/metadata/ACL are backed up on
the Mac, and all new app/stage paths are in the cleanup ledger. Do not retry
an uncertain stage or install before inspecting the fixed state.
"""

import glob
import hashlib
import os
import plistlib
import signal
import stat
import subprocess
import sys


PROFILE = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist"
APPS = {
    "baseline": (
        "Mac2JBU1-R2Baseline.app", "dev.mac2jb.u1probe.r2baseline",
        "/var/mobile/Media/.mac2jb-u1-springboard-r2-baseline.tipa",
        109249, "565ad2fd8b4d90130fd29e562ad446911a5364be67f7c8e1b3547b43b8f06c1a",
    ),
    "setdescription": (
        "Mac2JBU1-R2SetDescription.app", "dev.mac2jb.u1probe.r2setdescription",
        "/var/mobile/Media/.mac2jb-u1-springboard-r2-setdescription.tipa",
        109335, "0424a37259f8c873d474dcd1965ccdcc386f0d39814f408869432f2aa235d65d",
    ),
}
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
            raise RuntimeError("unsafe fixed file")
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
            raise RuntimeError("fixed file changed during read")
        return value.hexdigest(), before
    finally:
        os.close(fd)


def app_id(path):
    if os.path.islink(path):
        return None
    info = path + "/Info.plist"
    try:
        fd = os.open(info, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            item = os.fstat(fd)
            if not stat.S_ISREG(item.st_mode) or not 0 < item.st_size <= 262144:
                return None
            data = os.read(fd, 262145)
            if len(data) != item.st_size:
                return None
        finally:
            os.close(fd)
        tree = plistlib.loads(data)
        return tree.get("CFBundleIdentifier") if isinstance(tree, dict) else None
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
        return None


def state(original):
    if len(original) != 64 or any(c not in "0123456789abcdef" for c in original):
        raise RuntimeError("invalid original digest")
    profile = "unchanged" if digest(PROFILE, 1048576)[0] == original else "changed"
    candidates = []
    for root in ROOTS:
        for name in ("TrollStore*.app", APPS["baseline"][0], APPS["setdescription"][0]):
            candidates.extend(glob.glob(root + name))
    if len(candidates) > 32:
        raise RuntimeError("too many app candidates")
    stores = [path for path in candidates if app_id(path) == "com.opa334.TrollStore"]
    if len(stores) != 1:
        raise RuntimeError("TrollStore not unique")
    helper = stores[0] + "/trollstorehelper"
    item = os.lstat(helper)
    if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or not item.st_mode & 0o111:
        raise RuntimeError("unsafe TrollStore helper")
    apps = {}
    stages = {}
    for label, (name, bundle_id, stage, size, sha) in APPS.items():
        matching = [path for path in candidates if app_id(path) == bundle_id]
        if len(matching) > 1:
            raise RuntimeError("duplicate target app")
        apps[label] = "one" if matching else "zero"
        try:
            actual, info = digest(stage, 1048576)
            stages[label] = "verified" if (
                actual == sha and info.st_size == size and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600
            ) else "other"
        except FileNotFoundError:
            stages[label] = "absent"
        except (OSError, RuntimeError):
            stages[label] = "other"
    return profile, apps, stages, helper


def preflight(original):
    profile, apps, stages, _ = state(original)
    print("SPRINGBOARD_R2_PREFLIGHT profile=" + profile +
          " store=one baseline=" + apps["baseline"] +
          " setdescription=" + apps["setdescription"] +
          " stage-baseline=" + stages["baseline"] +
          " stage-setdescription=" + stages["setdescription"])


def stage(label, original):
    profile, apps, stages, _ = state(original)
    if profile != "unchanged" or apps[label] != "zero" or stages[label] != "absent":
        raise RuntimeError("stage preconditions failed")
    _, _, target, size, expected = APPS[label]
    data = sys.stdin.buffer.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError("archive digest mismatch")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < size:
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    actual, info = digest(target, 1048576)
    if actual != expected or info.st_size != size or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError("stage readback mismatch")
    print("SPRINGBOARD_R2_STAGE profile=" + label + " verified")


def install(label, original):
    profile, apps, stages, helper = state(original)
    if profile != "unchanged" or apps[label] != "zero" or stages[label] != "verified":
        raise RuntimeError("install preconditions failed")
    other = "setdescription" if label == "baseline" else "baseline"
    previous_other = apps[other]
    process = subprocess.Popen([helper, "install", "custom", APPS[label][2]],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        status = str(process.wait(timeout=90))
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        status = "timeout"
    profile, apps, stages, _ = state(original)
    print("SPRINGBOARD_R2_INSTALL profile=" + label + " helper=" + status +
          " clienttruth=" + profile + " app=" + apps[label] +
          " other=" + apps[other] + " stage=" + stages[label])
    if status != "0" or profile != "unchanged" or apps[label] != "one" or apps[other] != previous_other:
        raise SystemExit(70)


def main():
    if os.geteuid() != 0 or len(sys.argv) not in (3, 4):
        raise SystemExit(64)
    action = sys.argv[1]
    if action == "preflight" and len(sys.argv) == 3:
        preflight(sys.argv[2])
    elif action in ("stage", "install") and len(sys.argv) == 4 and sys.argv[2] in APPS:
        (stage if action == "stage" else install)(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit(65)


if __name__ == "__main__":
    main()
