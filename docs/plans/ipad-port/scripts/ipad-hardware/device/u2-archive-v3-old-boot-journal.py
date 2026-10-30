#!/var/jb/usr/bin/python3
"""Preserve the failed v3 old-boot U2 journal after external reboot recovery.

Run only after the Mac independently verifies a new boot, original live
description and complete external USB/NCM/pairing recovery. `--copy` streams
the exact v3 journal for an owner-only Mac backup. `--archive` checks the
v3 binary/plist and current job/socket kinds, boots out its supervised job
and the publication-disabled original job, then links the journal to a fixed archive
name, fsyncs, unlinks the active name, and fsyncs again. It never starts a
service, changes a USB description, sends a USB request, or deletes journal
bytes. `--verify` checks the final state without writes. The archive remains
on the iPad for later cleanup and must be recorded in the cleanup ledger.
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
ARCHIVE = "restore-journal.oldboot-v3-b8e66632.json"
EXPECTED = "b8e66632f52f59ac13d389f650e71840d90226096bbe0945aeb881562ee7fe3d"
FIRST_ARCHIVE = "restore-journal.oldboot-77caed18.json"
FIRST_SHA256 = "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"
V2_ARCHIVE = "restore-journal.oldboot-v2-f5934b3a.json"
V2_SHA256 = "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"
SOURCE = "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist"
SOURCE_SHA256 = "a0f63c8c2372ebd1ed4e49492344a5c1290c530ae8e5c66d88e9ba481792c5fa"
LAUNCHCTL = "/var/jb/bin/launchctl"
TRIAL = "system/dev.mac2jb.u2.nooptrialv3"
ORIGINAL = "system/dev.mac2jb.u2.watchdog"
ORIGINAL_BINARY = "/var/jb/usr/libexec/mac2jb-u2-native-watchdog"
ORIGINAL_SHA256 = "1c7530d5796c27ce50efb4dacd522302ffbd96bbb800513808a929d061baad14"
ORIGINAL_PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.watchdog.plist"
BINARY = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-c98b4ee9"
BINARY_SHA256 = "c98b4ee9d6405036d38d9a05df87a388dd6db63c77452b8c72383dd4276febd7"
PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.nooptrialv3.plist"
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
        raise ValueError("boot time unavailable")
    buffer = ctypes.create_string_buffer(size.value)
    if call(b"kern.boottime", buffer, ctypes.byref(size), None, 0):
        raise ValueError("boot time changed")
    return hashlib.sha256(bytes(buffer[:size.value])).hexdigest()


def checked_directory():
    fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        raise ValueError("unsafe state directory")
    return fd


def checked_file(directory, name, expected=EXPECTED):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                not 0 < info.st_size <= 2_000_000):
            raise ValueError("unsafe journal metadata")
        data = bytearray()
        while len(data) < info.st_size:
            part = os.read(fd, info.st_size - len(data))
            if not part:
                raise ValueError("short journal")
            data.extend(part)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("journal digest changed")
        return bytes(data)
    finally:
        os.close(fd)


def validate(data):
    envelope = json.loads(data)
    if set(envelope) != {"payload", "sha256"}:
        raise ValueError("journal envelope changed")
    payload = base64.b64decode(envelope["payload"], validate=True)
    if hashlib.sha256(payload).hexdigest() != envelope["sha256"]:
        raise ValueError("journal checksum changed")
    record = json.loads(payload)
    if (record.get("phase") != "awaitingVerification" or
            not isinstance(record.get("recipe"), dict)):
        raise ValueError("journal phase changed")
    recipe = record["recipe"]
    if (recipe.get("productType") != "iPad14,5" or
            recipe.get("osBuild") != "21A329" or
            recipe.get("sourceSHA256") != SOURCE_SHA256 or
            not isinstance(recipe.get("bootSession"), str) or
            len(recipe["bootSession"]) != 64 or
            recipe["bootSession"] == boot_token()):
        raise ValueError("journal is not from an old boot")
    with open(SOURCE, "rb") as source:
        if hashlib.sha256(source.read(2_000_001)).hexdigest() != SOURCE_SHA256:
            raise ValueError("stock source changed")


def job_state(label):
    result = subprocess.run([LAUNCHCTL, "print", label],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=6)
    if len(result.stdout) > 128 * 1024:
        raise ValueError("oversize launchd state")
    if result.returncode:
        return "absent"
    return "running" if b"state = running" in result.stdout else "loaded-stopped"


def checked_stage():
    info = os.lstat(BINARY)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o755 or not 0 < info.st_size <= 4 * 1024 * 1024):
        raise ValueError("v3 binary metadata changed")
    with open(BINARY, "rb") as source:
        if hashlib.sha256(source.read(4 * 1024 * 1024 + 1)).hexdigest() != BINARY_SHA256:
            raise ValueError("v3 binary digest changed")
    info = os.lstat(PLIST)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o644 or not 0 < info.st_size <= 4096):
        raise ValueError("v3 plist metadata changed")
    with open(PLIST, "rb") as source:
        value = plistlib.load(source)
    if value != {"Label": "dev.mac2jb.u2.nooptrialv3",
                 "ProgramArguments": [BINARY, "--serve-noop-trial"],
                 "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
                 "UserName": "root"}:
        raise ValueError("v3 plist changed")


def checked_original_stage():
    info = os.lstat(ORIGINAL_BINARY)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o755 or not 0 < info.st_size <= 4 * 1024 * 1024):
        raise ValueError("original binary metadata changed")
    with open(ORIGINAL_BINARY, "rb") as source:
        if hashlib.sha256(source.read(4 * 1024 * 1024 + 1)).hexdigest() != ORIGINAL_SHA256:
            raise ValueError("original binary digest changed")
    info = os.lstat(ORIGINAL_PLIST)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o644 or not 0 < info.st_size <= 4096):
        raise ValueError("original plist metadata changed")
    with open(ORIGINAL_PLIST, "rb") as source:
        value = plistlib.load(source)
    if value != {"Label": "dev.mac2jb.u2.watchdog",
                 "ProgramArguments": [ORIGINAL_BINARY, "--serve"],
                 "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
                 "UserName": "root"}:
        raise ValueError("original plist changed")


def checked_socket_kind():
    try:
        info = os.lstat(SOCKET)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise ValueError("v3 socket changed")


def main(mode):
    if os.geteuid() != 0 or mode not in ("--copy", "--archive", "--verify"):
        raise ValueError("root and fixed mode required")
    if (os.link not in os.supports_dir_fd or
            os.link not in os.supports_follow_symlinks or
            os.unlink not in os.supports_dir_fd):
        raise ValueError("safe archive operations unavailable")
    directory = checked_directory()
    try:
        if mode == "--verify":
            if os.path.lexists(STATE + "/" + ACTIVE):
                raise ValueError("active journal remains")
            validate(checked_file(directory, ARCHIVE))
            checked_file(directory, FIRST_ARCHIVE, FIRST_SHA256)
            checked_file(directory, V2_ARCHIVE, V2_SHA256)
            if job_state(TRIAL) != "absent" or job_state(ORIGINAL) != "absent":
                raise ValueError("v3 trial job still loaded")
            checked_stage()
            checked_original_stage()
            print("U2_V3_OLD_JOURNAL archive=verified active=absent trial=absent old-archives=retained")
            return
        data = checked_file(directory, ACTIVE)
        validate(data)
        checked_file(directory, FIRST_ARCHIVE, FIRST_SHA256)
        checked_file(directory, V2_ARCHIVE, V2_SHA256)
        checked_stage()
        checked_original_stage()
        if os.path.lexists(STATE + "/" + ARCHIVE):
            raise ValueError("archive path already exists")
        trial_state = job_state(TRIAL)
        original_state = job_state(ORIGINAL)
        if trial_state not in ("running", "loaded-stopped") or original_state not in (
                "running", "loaded-stopped", "absent"):
            raise ValueError("trial job state changed")
        checked_socket_kind()
        if mode == "--copy":
            view = memoryview(data)
            while view:
                view = view[os.write(1, view):]
            return
        for label, state in ((ORIGINAL, original_state), (TRIAL, trial_state)):
            if state in ("running", "loaded-stopped"):
                result = subprocess.run([LAUNCHCTL, "bootout", label],
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=8)
                if result.returncode or job_state(label) != "absent":
                    raise ValueError("watchdog bootout failed")
        if job_state(TRIAL) != "absent" or job_state(ORIGINAL) != "absent":
            raise ValueError("watchdog job remained loaded")
        if checked_file(directory, ACTIVE) != data:
            raise ValueError("journal changed after bootout")
        os.link(ACTIVE, ARCHIVE, src_dir_fd=directory, dst_dir_fd=directory,
                follow_symlinks=False)
        os.fsync(directory)
        os.unlink(ACTIVE, dir_fd=directory)
        os.fsync(directory)
        validate(checked_file(directory, ARCHIVE))
        checked_file(directory, FIRST_ARCHIVE, FIRST_SHA256)
        checked_file(directory, V2_ARCHIVE, V2_SHA256)
        print("U2_V3_OLD_JOURNAL archive=retained active=absent trial=booted-out old-archives=retained")
    finally:
        os.close(directory)


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired) as error:
        reason = str(error) if isinstance(error, ValueError) else "system-query"
        print("U2_V3_OLD_JOURNAL rejected reason=" + reason, file=sys.stderr)
        raise SystemExit(1)
