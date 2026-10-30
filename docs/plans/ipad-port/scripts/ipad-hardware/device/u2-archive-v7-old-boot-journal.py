#!/var/jb/usr/bin/python3
"""Archive only the exact failed v7 post-restore journal after a new boot.

Inspect and verify modes are read-only. Archive mode boots out the exact
retained v7, original, and v4 jobs, then hard-links the journal under a fixed old-boot name,
fsyncs the directory, removes only the active name, and fsyncs again. All
journal bytes and the four earlier archives remain. This script never opens
a USB controller, changes a description, or cycles the bus.
"""

import base64
import ctypes
import hashlib
import json
import os
import plistlib
import stat
import subprocess
import sys

STATE = "/var/jb/var/lib/mac2jb-u2-native"
ACTIVE = "restore-journal.json"
ARCHIVE = "restore-journal.oldboot-v7-0f265fd1.json"
EXPECTED = "0f265fd17847a9db1a1bc6814e39e7da94fd1eaef6e736811e3d618af1bbb02e"
ARCHIVES = (
    ("restore-journal.oldboot-77caed18.json", "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"),
    ("restore-journal.oldboot-v2-f5934b3a.json", "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"),
    ("restore-journal.oldboot-v3-b8e66632.json", "b8e66632f52f59ac13d389f650e71840d90226096bbe0945aeb881562ee7fe3d"),
    ("restore-journal.oldboot-v5-2ec38461.json", "2ec384616a51a6375e124ca3643e0bcfd0007783fe50cdab4f544a7bfb748976"),
)
SOURCE = "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist"
SOURCE_SHA = "a0f63c8c2372ebd1ed4e49492344a5c1290c530ae8e5c66d88e9ba481792c5fa"
LAUNCHCTL = "/var/jb/bin/launchctl"
V7 = "dev.mac2jb.u2.nooptrialv7"
V4 = "dev.mac2jb.u2.nooptrialv4"
ORIGINAL = "dev.mac2jb.u2.watchdog"
STAGES = (
    (V7, "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-87f0b112",
     "87f0b112378b6e38b7d90f770aa20a047f26814170edaa2bd63388aec0b1c380", "--serve-noop-trial"),
    (V4, "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-cedaa717",
     "cedaa71736aaf0d27f886b5cade552bfd6ee5ff3fde4e9c8eaaac071a8db34c7", "--serve-noop-trial"),
    (ORIGINAL, "/var/jb/usr/libexec/mac2jb-u2-native-watchdog",
     "1c7530d5796c27ce50efb4dacd522302ffbd96bbb800513808a929d061baad14", "--serve"),
)
SOCKET = STATE + "/broker.sock"


def boot_token():
    libc = ctypes.CDLL(None)
    call = libc.sysctlbyname
    call.argtypes = (ctypes.c_char_p, ctypes.c_void_p,
                     ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p,
                     ctypes.c_size_t)
    call.restype = ctypes.c_int
    size = ctypes.c_size_t()
    if call(b"kern.boottime", None, ctypes.byref(size), None, 0) or not 1 <= size.value <= 256:
        raise ValueError("boot unavailable")
    buffer = ctypes.create_string_buffer(size.value)
    if call(b"kern.boottime", buffer, ctypes.byref(size), None, 0):
        raise ValueError("boot changed")
    return hashlib.sha256(bytes(buffer[:size.value])).hexdigest()


def directory():
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        raise ValueError("state directory changed")
    return fd


def exact_bytes(data, digest):
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("journal digest changed")


def journal(fd, name, digest):
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        info = os.fstat(handle)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                not 0 < info.st_size <= 2_000_000):
            raise ValueError("journal metadata changed")
        data = bytearray()
        while len(data) < info.st_size:
            part = os.read(handle, info.st_size - len(data))
            if not part:
                raise ValueError("short journal")
            data.extend(part)
        exact_bytes(data, digest)
        return bytes(data)
    finally:
        os.close(handle)


def validate_old_boot(data):
    envelope = json.loads(data)
    if set(envelope) != {"payload", "sha256"}:
        raise ValueError("journal envelope changed")
    payload = base64.b64decode(envelope["payload"], validate=True)
    if hashlib.sha256(payload).hexdigest() != envelope["sha256"]:
        raise ValueError("journal checksum changed")
    record = json.loads(payload)
    recipe = record.get("recipe")
    if (record.get("phase") != "awaitingVerification" or
            not isinstance(recipe, dict) or
            recipe.get("productType") != "iPad14,5" or
            recipe.get("osBuild") != "21A329" or
            recipe.get("sourceSHA256") != SOURCE_SHA or
            not isinstance(recipe.get("bootSession"), str) or
            len(recipe["bootSession"]) != 64 or
            recipe["bootSession"] == boot_token()):
        raise ValueError("not exact old-boot v7 journal")
    with open(SOURCE, "rb") as source:
        if hashlib.sha256(source.read(2_000_001)).hexdigest() != SOURCE_SHA:
            raise ValueError("stock source changed")


def checked_file(path, mode, digest=None):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or
            not 0 < info.st_size <= 4 * 1024 * 1024):
        raise ValueError("stage metadata changed")
    with open(path, "rb") as source:
        data = source.read(4 * 1024 * 1024 + 1)
    if digest and hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("stage digest changed")
    return data


def stages():
    for label, binary, digest, mode in STAGES:
        checked_file(binary, 0o755, digest)
        plist = "/var/jb/Library/LaunchDaemons/" + label + ".plist"
        value = plistlib.loads(checked_file(plist, 0o644))
        if value != {"Label": label, "ProgramArguments": [binary, mode],
                      "RunAtLoad": True, "KeepAlive": True,
                      "ThrottleInterval": 2, "UserName": "root"}:
            raise ValueError("stage plist changed")


def job(label):
    result = subprocess.run([LAUNCHCTL, "print", "system/" + label],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=6)
    if len(result.stdout) > 128 * 1024:
        raise ValueError("oversize job status")
    if result.returncode:
        return "absent"
    return "running" if b"state = running" in result.stdout else "loaded-stopped"


def owned_socket():
    info = os.lstat(SOCKET)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("socket changed")


def preflight_jobs(states):
    # The new boot reloads all three RunAtLoad plists. The v7 broker owns the
    # socket while the other two jobs are loaded but stopped on its singleton.
    # Also accept the prior same-boot layout, in which only v4 was loaded.
    if states not in (
            ("running", "loaded-stopped", "loaded-stopped"),
            ("absent", "running", "absent")):
        raise ValueError("unexpected U2 job layout")


def bootout(label, fd, data):
    current = job(label)
    if current not in ("running", "loaded-stopped"):
        raise ValueError("job changed before bootout")
    result = subprocess.run([LAUNCHCTL, "bootout", "system/" + label],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=8)
    if result.returncode or job(label) != "absent":
        raise ValueError("U2 job bootout failed")
    if journal(fd, ACTIVE, EXPECTED) != data:
        raise ValueError("journal changed after bootout")


def main(mode):
    if os.geteuid() != 0 or mode not in ("--inspect", "--archive", "--verify"):
        raise ValueError("fixed root mode required")
    if os.link not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
        raise ValueError("safe archive operations unavailable")
    fd = directory()
    try:
        stages()
        for name, digest in ARCHIVES:
            journal(fd, name, digest)
        if mode == "--verify":
            if os.path.lexists(STATE + "/" + ACTIVE):
                raise ValueError("active journal remains")
            validate_old_boot(journal(fd, ARCHIVE, EXPECTED))
            if any(job(label) != "absent" for label in (V7, V4, ORIGINAL)):
                raise ValueError("watchdog still loaded")
            print("U2_V7_OLD_JOURNAL archive=verified active=absent jobs=absent old-archives=retained")
            return
        data = journal(fd, ACTIVE, EXPECTED)
        validate_old_boot(data)
        if os.path.lexists(STATE + "/" + ARCHIVE):
            raise ValueError("archive path already exists")
        states = tuple(job(label) for label in (V7, V4, ORIGINAL))
        preflight_jobs(states)
        owned_socket()
        if mode == "--inspect":
            print("U2_V7_OLD_JOURNAL inspect=ready jobs=known socket=owned journal=exact old-archives=retained")
            return
        for label in (V7, ORIGINAL, V4):
            if label == V7 and states[0] == "absent":
                continue
            if label == ORIGINAL and states[2] == "absent":
                continue
            bootout(label, fd, data)
        if (any(job(label) != "absent" for label in (V7, V4, ORIGINAL)) or
                journal(fd, ACTIVE, EXPECTED) != data):
            raise ValueError("state changed after bootout")
        validate_old_boot(data)
        os.link(ACTIVE, ARCHIVE, src_dir_fd=fd, dst_dir_fd=fd,
                follow_symlinks=False)
        os.fsync(fd)
        os.unlink(ACTIVE, dir_fd=fd)
        os.fsync(fd)
        validate_old_boot(journal(fd, ARCHIVE, EXPECTED))
        print("U2_V7_OLD_JOURNAL archive=retained active=absent jobs=booted-out old-archives=retained")
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired) as error:
        reason = str(error) if isinstance(error, ValueError) else "system-query"
        print("U2_V7_OLD_JOURNAL rejected reason=" + reason, file=sys.stderr)
        raise SystemExit(1)
