#!/var/jb/usr/bin/python3
"""Read the exact controller-clone U2 trial service without changing it.

Checks the v4 launchd label, signed binary digest, exact plist, all three archived
journals and existing private socket. Sends only `status` or the v4-only
`validate-only` in-memory clone check to the socket and prints fixed categories.
It does not prepare, publish, restore or confirm a
journal, and it never opens a USB user client or changes an iPad file.
"""

import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import sys


LABEL = "dev.mac2jb.u2.nooptrialv4"
TRIAL = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-cedaa717"
TRIAL_SHA256 = "cedaa71736aaf0d27f886b5cade552bfd6ee5ff3fde4e9c8eaaac071a8db34c7"
PLIST = "/var/jb/Library/LaunchDaemons/" + LABEL + ".plist"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
SOCKET = STATE + "/broker.sock"
ARCHIVE = STATE + "/restore-journal.oldboot-77caed18.json"
ARCHIVE_SHA256 = "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"
V2_ARCHIVE = STATE + "/restore-journal.oldboot-v2-f5934b3a.json"
V2_ARCHIVE_SHA256 = "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"
V3_ARCHIVE = STATE + "/restore-journal.oldboot-v3-b8e66632.json"
V3_ARCHIVE_SHA256 = "b8e66632f52f59ac13d389f650e71840d90226096bbe0945aeb881562ee7fe3d"
PHASES = {"absent", "prepared", "published", "restoring",
          "awaitingVerification", "recoveryRequired", "restored"}


def checked(path, mode, digest=None):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or
            not 0 < info.st_size <= 4 * 1024 * 1024):
        raise ValueError("exact file metadata changed")
    with open(path, "rb") as source:
        data = source.read(4 * 1024 * 1024 + 1)
    if digest is not None and hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("exact file digest changed")
    return data


def job(label):
    result = subprocess.run(["/var/jb/bin/launchctl", "print", "system/" + label],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    if len(result.stdout) > 128 * 1024 or result.returncode:
        raise ValueError("v4 job unavailable")
    return b"state = running" in result.stdout


def main():
    if (os.geteuid() != 0 or len(sys.argv) != 2 or
            sys.argv[0] not in ("-", "-c") or
            sys.argv[1] not in ("--status", "--validate-only")):
        raise ValueError("root required")
    checked(TRIAL, 0o755, TRIAL_SHA256)
    if plistlib.loads(checked(PLIST, 0o644)) != {
            "Label": LABEL, "ProgramArguments": [TRIAL, "--serve-noop-trial"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
            "UserName": "root"}:
        raise ValueError("v4 plist changed")
    checked(ARCHIVE, 0o600, ARCHIVE_SHA256)
    checked(V2_ARCHIVE, 0o600, V2_ARCHIVE_SHA256)
    checked(V3_ARCHIVE, 0o600, V3_ARCHIVE_SHA256)
    running = job(LABEL)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(SOCKET)
        connection.sendall(b"status\n")
        answer = connection.recv(128)
    prefix = b"OK phase="
    suffix = b" publication=enabled\n"
    if not answer.startswith(prefix) or not answer.endswith(suffix):
        raise ValueError("unexpected v4 socket status")
    phase = answer[len(prefix):-len(suffix)].decode("ascii")
    if phase not in PHASES:
        raise ValueError("unknown v4 phase")
    if sys.argv[1] == "--validate-only":
        if phase != "absent":
            raise ValueError("active journal present")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(4)
            connection.connect(SOCKET)
            connection.sendall(b"validate-only\n")
            if connection.recv(128) != b"OK validated-in-memory\n":
                raise ValueError("native clone dry run failed")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(SOCKET)
            connection.sendall(b"status\n")
            if connection.recv(128) != b"OK phase=absent publication=enabled\n":
                raise ValueError("native clone dry run changed journal")
        print("U2_TRIAL_V4 clone=in-memory-valid journal=absent archives=retained")
        return
    print("U2_TRIAL_V4 job=loaded running=" + ("yes" if running else "no") +
          " binary=exact plist=exact socket=responding phase=" + phase +
          " publication=enabled archives=retained")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_TRIAL_V4 rejected")
        raise SystemExit(1)
