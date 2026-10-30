#!/var/jb/usr/bin/python3
"""Stage the signed U2 readiness-gated candidate without publication.

The host streams one exact signed binary on stdin. `--inspect` checks every
precondition without writing; `--stage` performs the guarded stage. This root-only helper
requires all four archived old journals, no active journal or broker socket,
all old U2 jobs absent, exact installed disabled package files, and absent v7
stage paths. It exclusively creates and fsyncs the v7 binary/plist, bootstraps
only the v7 label, and requires its private socket to report an empty journal.
It sends no prepare/publish/restore command and makes no USB controller call.
On failure it boots out the v7 label if loaded and retains files for inspection.
"""

import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import sys
import time


TRIAL_SHA256 = "87f0b112378b6e38b7d90f770aa20a047f26814170edaa2bd63388aec0b1c380"
TRIAL = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-87f0b112"
LABEL = "dev.mac2jb.u2.nooptrialv7"
PLIST = "/var/jb/Library/LaunchDaemons/" + LABEL + ".plist"
ORIGINAL = "/var/jb/usr/libexec/mac2jb-u2-native-watchdog"
ORIGINAL_SHA256 = "1c7530d5796c27ce50efb4dacd522302ffbd96bbb800513808a929d061baad14"
ORIGINAL_PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.watchdog.plist"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
ARCHIVE = STATE + "/restore-journal.oldboot-77caed18.json"
ARCHIVE_SHA256 = "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"
V2_ARCHIVE = STATE + "/restore-journal.oldboot-v2-f5934b3a.json"
V2_ARCHIVE_SHA256 = "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"
V3_ARCHIVE = STATE + "/restore-journal.oldboot-v3-b8e66632.json"
V3_ARCHIVE_SHA256 = "b8e66632f52f59ac13d389f650e71840d90226096bbe0945aeb881562ee7fe3d"
V5_ARCHIVE = STATE + "/restore-journal.oldboot-v5-2ec38461.json"
V5_ARCHIVE_SHA256 = "2ec384616a51a6375e124ca3643e0bcfd0007783fe50cdab4f544a7bfb748976"
ACTIVE = STATE + "/restore-journal.json"
SOCKET = STATE + "/broker.sock"
LAUNCHCTL = "/var/jb/bin/launchctl"
DPKG = "/var/jb/usr/bin/dpkg"


def command(args, timeout=8):
    return subprocess.run(args, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=timeout).returncode


def loaded(label):
    return command([LAUNCHCTL, "print", "system/" + label], 5) == 0


def checked(path, mode, digest=None):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or
            not 0 < info.st_size <= 4 * 1024 * 1024):
        raise ValueError("unsafe exact file")
    with open(path, "rb") as source:
        data = source.read(4 * 1024 * 1024 + 1)
    if digest is not None and hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("exact file digest changed")
    return data


def create(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        if os.write(fd, data) != len(data):
            raise ValueError("short trial stage")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def status():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(1)
        peer.connect(SOCKET)
        peer.sendall(b"status\n")
        return peer.recv(128)


def main(mode):
    if (mode not in ("--inspect", "--stage") or os.geteuid() != 0 or
            os.path.lexists(TRIAL) or os.path.lexists(PLIST) or
            os.path.lexists(ACTIVE) or os.path.lexists(SOCKET)):
        raise ValueError("unsafe v7 stage path")
    state = os.lstat(STATE)
    if (not stat.S_ISDIR(state.st_mode) or state.st_uid != 0 or
            stat.S_IMODE(state.st_mode) != 0o700 or
            any(loaded(label) for label in
                ("dev.mac2jb.u2.nooptrial", "dev.mac2jb.u2.nooptrialv2",
                 "dev.mac2jb.u2.nooptrialv3", "dev.mac2jb.u2.nooptrialv4",
                 "dev.mac2jb.u2.nooptrialv5", "dev.mac2jb.u2.watchdog", LABEL))):
        raise ValueError("U2 service state changed")
    checked(ARCHIVE, 0o600, ARCHIVE_SHA256)
    checked(V2_ARCHIVE, 0o600, V2_ARCHIVE_SHA256)
    checked(V3_ARCHIVE, 0o600, V3_ARCHIVE_SHA256)
    checked(V5_ARCHIVE, 0o600, V5_ARCHIVE_SHA256)
    checked(ORIGINAL, 0o755, ORIGINAL_SHA256)
    original = plistlib.loads(checked(ORIGINAL_PLIST, 0o644))
    if original != {
            "Label": "dev.mac2jb.u2.watchdog",
            "ProgramArguments": [ORIGINAL, "--serve"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
            "UserName": "root"}:
        raise ValueError("installed disabled plist changed")
    if command([DPKG, "-s", "mac2jb-u2-native-watchdog"]) != 0:
        raise ValueError("installed package missing")
    binary = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
    if not 0 < len(binary) <= 4 * 1024 * 1024 or hashlib.sha256(binary).hexdigest() != TRIAL_SHA256:
        raise ValueError("trial binary changed")
    if mode == "--inspect":
        print("U2_NOOP_STAGE_V7 preflight=ready binary=exact archives=retained")
        return
    create(TRIAL, binary, 0o755)
    description = {
        "Label": LABEL,
        "ProgramArguments": [TRIAL, "--serve-noop-trial"],
        "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
        "UserName": "root",
    }
    create(PLIST, plistlib.dumps(description, fmt=plistlib.FMT_XML), 0o644)
    checked(TRIAL, 0o755, TRIAL_SHA256)
    if plistlib.loads(checked(PLIST, 0o644)) != description:
        raise ValueError("v7 trial plist changed")
    try:
        if command([LAUNCHCTL, "bootstrap", "system", PLIST]) != 0:
            raise ValueError("v7 trial bootstrap failed")
        time.sleep(8)
        try:
            ready = status() == b"OK phase=absent publication=enabled\n"
        except (OSError, socket.timeout):
            ready = False
        if not ready:
            raise ValueError("v7 trial service not ready")
        if os.path.lexists(ACTIVE) or not loaded(LABEL):
            raise ValueError("unexpected v7 trial state")
    except BaseException:
        if loaded(LABEL):
            command([LAUNCHCTL, "bootout", "system/" + LABEL])
        raise
    print("U2_NOOP_STAGE_V7 trial=ready journal=absent archives=retained")


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, TypeError, KeyError, socket.timeout,
            subprocess.TimeoutExpired):
        print("U2_NOOP_STAGE_V7 rejected; inspect exact stage paths")
        raise SystemExit(1)
