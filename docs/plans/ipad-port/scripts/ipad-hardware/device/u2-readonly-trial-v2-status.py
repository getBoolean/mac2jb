#!/var/jb/usr/bin/python3
"""Read the exact corrected U2 trial service state without changing it.

Checks the v2 launchd label, signed binary digest, exact plist, archived old
journal and existing private socket. Sends only `status` to the socket and
prints fixed categories. It does not prepare, publish, restore or confirm a
journal, and it never opens a USB user client or changes an iPad file.
"""

import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import sys


LABEL = "dev.mac2jb.u2.nooptrialv2"
TRIAL = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-7e85c5f9"
TRIAL_SHA256 = "7e85c5f94ee2a6715e6c52179370f4594aa2f986f3feefda07b544750a290df6"
PLIST = "/var/jb/Library/LaunchDaemons/" + LABEL + ".plist"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
SOCKET = STATE + "/broker.sock"
ARCHIVE = STATE + "/restore-journal.oldboot-77caed18.json"
ARCHIVE_SHA256 = "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"
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
        raise ValueError("v2 job unavailable")
    return b"state = running" in result.stdout


def main():
    if (os.geteuid() != 0 or len(sys.argv) != 2 or
            sys.argv[0] not in ("-", "-c") or sys.argv[1] != "--status"):
        raise ValueError("root required")
    checked(TRIAL, 0o755, TRIAL_SHA256)
    if plistlib.loads(checked(PLIST, 0o644)) != {
            "Label": LABEL, "ProgramArguments": [TRIAL, "--serve-noop-trial"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
            "UserName": "root"}:
        raise ValueError("v2 plist changed")
    checked(ARCHIVE, 0o600, ARCHIVE_SHA256)
    running = job(LABEL)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(SOCKET)
        connection.sendall(b"status\n")
        answer = connection.recv(128)
    prefix = b"OK phase="
    suffix = b" publication=enabled\n"
    if not answer.startswith(prefix) or not answer.endswith(suffix):
        raise ValueError("unexpected v2 socket status")
    phase = answer[len(prefix):-len(suffix)].decode("ascii")
    if phase not in PHASES:
        raise ValueError("unknown v2 phase")
    print("U2_TRIAL_V2 job=loaded running=" + ("yes" if running else "no") +
          " binary=exact plist=exact socket=responding phase=" + phase +
          " publication=enabled archive=retained")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_TRIAL_V2 rejected")
        raise SystemExit(1)
