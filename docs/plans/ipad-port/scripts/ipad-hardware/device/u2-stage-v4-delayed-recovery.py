#!/var/jb/usr/bin/python3
"""Switch an idle failed v7 broker to the exact v4 broker without restoring.

The host streams the previously tested signed v4 binary. Inspect mode reads
only exact stage, journal, socket and launchd state. Stage mode boots out the
v7 service, removes only its stale private socket, creates the exact v4 binary
and plist, and starts v4 with the journal still `recoveryRequired`. The v4
broker does not auto-recover that phase. This script sends no `restore`, does
not open a USB controller, and never changes the journal or stock files.
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
JOURNAL_SHA = "9be6c2b6bad2783f80445981f88fc159ed8c8c3d8c9e56ebf4c762a8665556c1"
SOCKET = STATE + "/broker.sock"
LAUNCHCTL = "/var/jb/bin/launchctl"
V7_LABEL = "dev.mac2jb.u2.nooptrialv7"
V7_BINARY = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-87f0b112"
V7_SHA = "87f0b112378b6e38b7d90f770aa20a047f26814170edaa2bd63388aec0b1c380"
V7_PLIST = "/var/jb/Library/LaunchDaemons/" + V7_LABEL + ".plist"
V4_LABEL = "dev.mac2jb.u2.nooptrialv4"
V4_BINARY = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-cedaa717"
V4_SHA = "cedaa71736aaf0d27f886b5cade552bfd6ee5ff3fde4e9c8eaaac071a8db34c7"
V4_PLIST = "/var/jb/Library/LaunchDaemons/" + V4_LABEL + ".plist"
ARCHIVES = (
    ("restore-journal.oldboot-77caed18.json", "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"),
    ("restore-journal.oldboot-v2-f5934b3a.json", "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"),
    ("restore-journal.oldboot-v3-b8e66632.json", "b8e66632f52f59ac13d389f650e71840d90226096bbe0945aeb881562ee7fe3d"),
    ("restore-journal.oldboot-v5-2ec38461.json", "2ec384616a51a6375e124ca3643e0bcfd0007783fe50cdab4f544a7bfb748976"),
)


def checked(path, mode, digest):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != mode or not 0 < info.st_size <= 4_000_000):
        raise ValueError("unsafe exact file")
    with open(path, "rb") as source:
        data = source.read(4_000_001)
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("exact file changed")
    return data


def job(label):
    result = subprocess.run([LAUNCHCTL, "print", "system/" + label],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    if len(result.stdout) > 128 * 1024:
        raise ValueError("launchd output oversized")
    return result.returncode == 0


def socket_status():
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(2)
        peer.connect(SOCKET)
        peer.sendall(b"status\n")
        return peer.recv(128)


def plist(label, binary):
    return {"Label": label, "ProgramArguments": [binary, "--serve-noop-trial"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
            "UserName": "root"}


def preflight():
    info = os.lstat(STATE)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) != 0o700 or
            os.path.lexists(V4_BINARY) or os.path.lexists(V4_PLIST) or job(V4_LABEL)):
        raise ValueError("unsafe recovery stage")
    checked(ACTIVE, 0o600, JOURNAL_SHA)
    for name, digest in ARCHIVES:
        checked(STATE + "/" + name, 0o600, digest)
    checked(V7_BINARY, 0o755, V7_SHA)
    if plistlib.loads(checked(V7_PLIST, 0o644,
                             hashlib.sha256(plistlib.dumps(plist(V7_LABEL, V7_BINARY),
                                                            fmt=plistlib.FMT_XML)).hexdigest())) != \
            plist(V7_LABEL, V7_BINARY):
        raise ValueError("v7 plist changed")
    if not job(V7_LABEL) or socket_status() != b"OK phase=recoveryRequired publication=enabled\n":
        raise ValueError("v7 broker not idle on failed journal")


def create(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        if os.write(fd, data) != len(data):
            raise ValueError("short stage write")
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def remove_stale_socket():
    try:
        info = os.lstat(SOCKET)
    except FileNotFoundError:
        return
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("unsafe socket")
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(1)
        if peer.connect_ex(SOCKET) != errno.ECONNREFUSED:
            raise ValueError("socket listener present")
    os.unlink(SOCKET)


def verify_staged():
    checked(ACTIVE, 0o600, JOURNAL_SHA)
    for name, digest in ARCHIVES:
        checked(STATE + "/" + name, 0o600, digest)
    checked(V7_BINARY, 0o755, V7_SHA)
    if plistlib.loads(checked(V7_PLIST, 0o644,
            hashlib.sha256(plistlib.dumps(plist(V7_LABEL, V7_BINARY),
                                           fmt=plistlib.FMT_XML)).hexdigest())) != \
            plist(V7_LABEL, V7_BINARY):
        raise ValueError("v7 plist changed")
    checked(V4_BINARY, 0o755, V4_SHA)
    if (plistlib.loads(checked(V4_PLIST, 0o644,
            hashlib.sha256(plistlib.dumps(plist(V4_LABEL, V4_BINARY),
                                           fmt=plistlib.FMT_XML)).hexdigest())) !=
            plist(V4_LABEL, V4_BINARY) or
            job(V7_LABEL) or not job(V4_LABEL) or
            socket_status() != b"OK phase=recoveryRequired publication=enabled\n"):
        raise ValueError("v4 broker not idle on failed journal")
    print("U2_DELAYED_RECOVERY_STAGE verify=v4-idle journal=exact controller-write=none")


def main(mode):
    if os.geteuid() != 0 or mode not in ("--inspect", "--stage", "--verify"):
        raise ValueError("root fixed mode required")
    if mode == "--verify":
        verify_staged()
        return
    preflight()
    binary = sys.stdin.buffer.read(4_000_001)
    if not 0 < len(binary) <= 4_000_000 or hashlib.sha256(binary).hexdigest() != V4_SHA:
        raise ValueError("v4 binary changed")
    if mode == "--inspect":
        print("U2_DELAYED_RECOVERY_STAGE inspect=ready journal=exact v7=idle v4=absent")
        return
    result = subprocess.run([LAUNCHCTL, "bootout", "system/" + V7_LABEL],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
    if result.returncode or job(V7_LABEL):
        raise ValueError("v7 bootout failed")
    remove_stale_socket()
    checked(ACTIVE, 0o600, JOURNAL_SHA)
    create(V4_BINARY, binary, 0o755)
    create(V4_PLIST, plistlib.dumps(plist(V4_LABEL, V4_BINARY), fmt=plistlib.FMT_XML), 0o644)
    result = subprocess.run([LAUNCHCTL, "bootstrap", "system", V4_PLIST],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
    if result.returncode:
        raise ValueError("v4 bootstrap failed")
    time.sleep(8)
    verify_staged()
    print("U2_DELAYED_RECOVERY_STAGE v4=idle journal=exact controller-write=none")


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, TypeError, KeyError, socket.timeout,
            subprocess.TimeoutExpired):
        print("U2_DELAYED_RECOVERY_STAGE rejected; inspect exact stage and journal")
        raise SystemExit(1)
