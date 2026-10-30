#!/var/jb/usr/bin/python3
"""Resume only the retained exact v4 broker after v7 old-boot archival.

Inspect and verify are read-only. Stage bootstraps the exact retained launchd
plist but sends no broker request and makes no USB controller call.
"""

import errno
import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import sys
import time

STATE = "/var/jb/var/lib/mac2jb-u2-native"
ACTIVE = STATE + "/restore-journal.json"
ARCHIVE = STATE + "/restore-journal.oldboot-v7-0f265fd1.json"
ARCHIVE_SHA = "0f265fd17847a9db1a1bc6814e39e7da94fd1eaef6e736811e3d618af1bbb02e"
OLD_ARCHIVES = (
    ("restore-journal.oldboot-77caed18.json", "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"),
    ("restore-journal.oldboot-v2-f5934b3a.json", "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"),
    ("restore-journal.oldboot-v3-b8e66632.json", "b8e66632f52f59ac13d389f650e71840d90226096bbe0945aeb881562ee7fe3d"),
    ("restore-journal.oldboot-v5-2ec38461.json", "2ec384616a51a6375e124ca3643e0bcfd0007783fe50cdab4f544a7bfb748976"),
)
TRIAL = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-cedaa717"
TRIAL_SHA = "cedaa71736aaf0d27f886b5cade552bfd6ee5ff3fde4e9c8eaaac071a8db34c7"
LABEL = "dev.mac2jb.u2.nooptrialv4"
PLIST = "/var/jb/Library/LaunchDaemons/" + LABEL + ".plist"
SOCKET = STATE + "/broker.sock"
LAUNCHCTL = "/var/jb/bin/launchctl"


def checked(path, mode, digest=None):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or
            not 0 < info.st_size <= 4 * 1024 * 1024):
        raise ValueError("exact file changed")
    with open(path, "rb") as source:
        data = source.read(4 * 1024 * 1024 + 1)
    if digest is not None and hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("exact digest changed")
    return data


def loaded(label):
    result = subprocess.run([LAUNCHCTL, "print", "system/" + label],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5)
    if len(result.stdout) > 128 * 1024:
        raise ValueError("job output oversized")
    return result.returncode == 0


def ready():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(1)
        peer.connect(SOCKET)
        peer.sendall(b"status\n")
        return peer.recv(128) == b"OK phase=absent publication=enabled\n"


def inactive_socket():
    try:
        info = os.lstat(SOCKET)
    except FileNotFoundError:
        return None
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("unexpected broker socket")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(1)
            peer.connect(SOCKET)
    except OSError as error:
        if error.errno == errno.ECONNREFUSED:
            again = os.lstat(SOCKET)
            if (again.st_dev, again.st_ino, again.st_mode, again.st_uid,
                    again.st_nlink) != (info.st_dev, info.st_ino, info.st_mode,
                    info.st_uid, info.st_nlink):
                raise ValueError("broker socket changed")
            return info
        raise ValueError("broker socket state ambiguous") from error
    raise ValueError("broker socket has a listener")


def preconditions():
    info = os.lstat(STATE)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) != 0o700 or os.path.lexists(ACTIVE)):
        raise ValueError("state directory or active journal changed")
    checked(ARCHIVE, 0o600, ARCHIVE_SHA)
    for name, digest in OLD_ARCHIVES:
        checked(STATE + "/" + name, 0o600, digest)
    checked(TRIAL, 0o755, TRIAL_SHA)
    description = plistlib.loads(checked(PLIST, 0o644))
    if description != {
            "Label": LABEL, "ProgramArguments": [TRIAL, "--serve-noop-trial"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
            "UserName": "root"}:
        raise ValueError("v4 plist changed")
    if any(loaded(label) for label in (
            "dev.mac2jb.u2.nooptrialv7", "dev.mac2jb.u2.watchdog")):
        raise ValueError("other U2 service loaded")


def main(mode):
    if os.geteuid() != 0 or mode not in ("--inspect", "--stage", "--verify"):
        raise ValueError("fixed root mode required")
    preconditions()
    if mode == "--verify":
        info = os.lstat(SOCKET)
        if (not loaded(LABEL) or not stat.S_ISSOCK(info.st_mode) or
                info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or
                not ready()):
            raise ValueError("v4 service not ready")
        print("U2_V4_REPEAT_SERVICE verified=exact journal=absent archive=exact")
        return
    if loaded(LABEL):
        raise ValueError("v4 service already loaded")
    stale = inactive_socket()
    if mode == "--inspect":
        print("U2_V4_REPEAT_SERVICE inspect=ready journal=absent archive=exact")
        return
    preconditions()
    if loaded(LABEL):
        raise ValueError("v4 service became loaded")
    current = inactive_socket()
    if (stale is None) != (current is None) or (stale is not None and
            (stale.st_dev, stale.st_ino) != (current.st_dev, current.st_ino)):
        raise ValueError("broker socket changed")
    if current is not None:
        again = os.lstat(SOCKET)
        if (again.st_dev, again.st_ino, again.st_mode, again.st_uid,
                again.st_nlink) != (current.st_dev, current.st_ino,
                current.st_mode, current.st_uid, current.st_nlink):
            raise ValueError("broker socket changed")
        os.unlink(SOCKET)
    result = subprocess.run([LAUNCHCTL, "bootstrap", "system", PLIST],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=8)
    if result.returncode:
        raise ValueError("v4 bootstrap failed")
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        try:
            preconditions()
            if loaded(LABEL) and ready():
                break
        except (OSError, socket.timeout):
            pass
        time.sleep(0.1)
    else:
        raise ValueError("v4 service not ready after bootstrap")
    print("U2_V4_REPEAT_SERVICE staged=exact journal=absent archive=exact")


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, TypeError, KeyError, socket.timeout,
            subprocess.TimeoutExpired):
        print("U2_V4_REPEAT_SERVICE rejected", file=sys.stderr)
        raise SystemExit(1)
