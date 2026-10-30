#!/var/jb/usr/bin/python3
"""Replace the idle v4 U2 service with v5, without a controller call.

The host streams the exact signed v5 binary. Inspect mode reads only. Stage
mode verifies an absent active journal, all three old archives, exact v4
binary/plist/socket status, and absent v5 paths; it boots out only the v4 job,
leaves its binary/plist for reversal, creates the v5 binary/plist exclusively,
and bootstraps v5 idle. No prepare, publish, restore, or bus-cycle command is
sent. If bootstrap fails, the old exact v4 files remain for guarded recovery.
"""

import hashlib
import errno
import os
import plistlib
import socket
import stat
import subprocess
import sys
import time


STATE = "/var/jb/var/lib/mac2jb-u2-native"
ACTIVE = STATE + "/restore-journal.json"
SOCKET = STATE + "/broker.sock"
LIBEXEC = "/var/jb/usr/libexec"
DAEMONS = "/var/jb/Library/LaunchDaemons"
OLD_LABEL = "dev.mac2jb.u2.nooptrialv4"
NEW_LABEL = "dev.mac2jb.u2.nooptrialv5"
OLD_BINARY = LIBEXEC + "/.mac2jb-u2-noop-trial-cedaa717"
NEW_BINARY = LIBEXEC + "/.mac2jb-u2-noop-trial-54e29b76"
OLD_SHA = "cedaa71736aaf0d27f886b5cade552bfd6ee5ff3fde4e9c8eaaac071a8db34c7"
NEW_SHA = "54e29b7635bae3a700366100333aa10849321c69e23ac90d26f41240bce83387"
OLD_PLIST = DAEMONS + "/" + OLD_LABEL + ".plist"
NEW_PLIST = DAEMONS + "/" + NEW_LABEL + ".plist"
ARCHIVES = (
    (STATE + "/restore-journal.oldboot-77caed18.json",
     "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"),
    (STATE + "/restore-journal.oldboot-v2-f5934b3a.json",
     "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"),
    (STATE + "/restore-journal.oldboot-v3-b8e66632.json",
     "b8e66632f52f59ac13d389f650e71840d90226096bbe0945aeb881562ee7fe3d"),
)
LAUNCHCTL = "/var/jb/bin/launchctl"


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


def command(args, timeout=8):
    return subprocess.run(args, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=timeout).returncode


def loaded(label):
    return command([LAUNCHCTL, "print", "system/" + label], 5) == 0


def status():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(1)
        peer.connect(SOCKET)
        peer.sendall(b"status\n")
        return peer.recv(128)


def stale_socket():
    info = os.lstat(SOCKET)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("unsafe socket kind")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(1)
        if peer.connect_ex(SOCKET) != errno.ECONNREFUSED:
            raise ValueError("socket may have a listener")
    if loaded(OLD_LABEL) or loaded(NEW_LABEL) or os.path.lexists(ACTIVE):
        raise ValueError("journal or service appeared")
    return info.st_ino


def remove_stale_socket(inode):
    if os.lstat(SOCKET).st_ino != inode:
        raise ValueError("socket changed")
    os.unlink(SOCKET)
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def create(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        if os.write(fd, data) != len(data):
            raise ValueError("short v5 stage")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(mode):
    if mode not in ("--inspect", "--stage", "--inspect-resume", "--resume") or os.geteuid() != 0:
        raise ValueError("invalid v5 transition")
    resume = mode in ("--inspect-resume", "--resume")
    state = os.lstat(STATE)
    if (not stat.S_ISDIR(state.st_mode) or state.st_uid != 0 or
            stat.S_IMODE(state.st_mode) != 0o700 or
            os.path.lexists(ACTIVE) or os.path.lexists(NEW_BINARY) or
            os.path.lexists(NEW_PLIST) or loaded(NEW_LABEL) or
            loaded(OLD_LABEL) == resume):
        raise ValueError("U2 state changed")
    checked(OLD_BINARY, 0o755, OLD_SHA)
    if plistlib.loads(checked(OLD_PLIST, 0o644)) != {
            "Label": OLD_LABEL,
            "ProgramArguments": [OLD_BINARY, "--serve-noop-trial"],
            "RunAtLoad": True, "KeepAlive": True,
            "ThrottleInterval": 2, "UserName": "root"}:
        raise ValueError("v4 plist changed")
    for path, digest in ARCHIVES:
        checked(path, 0o600, digest)
    if resume:
        stale = stale_socket()
    elif status() != b"OK phase=absent publication=enabled\n":
        raise ValueError("v4 service not idle")
    binary = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
    if not 0 < len(binary) <= 4 * 1024 * 1024 or hashlib.sha256(binary).hexdigest() != NEW_SHA:
        raise ValueError("v5 binary changed")
    if mode in ("--inspect", "--inspect-resume"):
        print("U2_TRANSITION_V5 inspect=" +
              ("resume-ready old=booted-out" if resume else "ready old=idle") +
              " new=absent archives=retained")
        return
    if not resume:
        if command([LAUNCHCTL, "bootout", "system/" + OLD_LABEL]) != 0:
            raise ValueError("v4 bootout failed")
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline and loaded(OLD_LABEL):
            time.sleep(0.1)
        if loaded(OLD_LABEL) or os.path.lexists(ACTIVE):
            raise ValueError("v4 service did not leave cleanly")
        stale = stale_socket() if os.path.lexists(SOCKET) else None
    if stale is not None:
        remove_stale_socket(stale)
    create(NEW_BINARY, binary, 0o755)
    description = {
        "Label": NEW_LABEL,
        "ProgramArguments": [NEW_BINARY, "--serve-noop-trial"],
        "RunAtLoad": True, "KeepAlive": True,
        "ThrottleInterval": 2, "UserName": "root",
    }
    create(NEW_PLIST, plistlib.dumps(description, fmt=plistlib.FMT_XML), 0o644)
    checked(NEW_BINARY, 0o755, NEW_SHA)
    if plistlib.loads(checked(NEW_PLIST, 0o644)) != description:
        raise ValueError("v5 plist changed")
    if command([LAUNCHCTL, "bootstrap", "system", NEW_PLIST]) != 0:
        raise ValueError("v5 bootstrap failed")
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        try:
            if status() == b"OK phase=absent publication=enabled\n":
                break
        except (OSError, socket.timeout):
            pass
        time.sleep(0.1)
    else:
        raise ValueError("v5 service not ready")
    if not loaded(NEW_LABEL) or loaded(OLD_LABEL) or os.path.lexists(ACTIVE):
        raise ValueError("v5 service state changed")
    print("U2_TRANSITION_V5 trial=idle journal=absent old=retained archives=retained")


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, TypeError, KeyError, socket.timeout,
            subprocess.TimeoutExpired):
        print("U2_TRANSITION_V5 rejected; inspect stage paths and jobs")
        raise SystemExit(1)
