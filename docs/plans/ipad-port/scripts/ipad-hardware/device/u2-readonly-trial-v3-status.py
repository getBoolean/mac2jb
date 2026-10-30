#!/var/jb/usr/bin/python3
"""Read the exact explicit-bus-cycle U2 trial service without changing it.

Checks the v3 launchd label, signed binary digest, exact plist, both archived
journals and existing private socket. Sends only `status` to the socket and
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


LABEL = "dev.mac2jb.u2.nooptrialv3"
TRIAL = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-c98b4ee9"
TRIAL_SHA256 = "c98b4ee9d6405036d38d9a05df87a388dd6db63c77452b8c72383dd4276febd7"
PLIST = "/var/jb/Library/LaunchDaemons/" + LABEL + ".plist"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
SOCKET = STATE + "/broker.sock"
ARCHIVE = STATE + "/restore-journal.oldboot-77caed18.json"
ARCHIVE_SHA256 = "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"
V2_ARCHIVE = STATE + "/restore-journal.oldboot-v2-f5934b3a.json"
V2_ARCHIVE_SHA256 = "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"
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
        raise ValueError("v3 job unavailable")
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
        raise ValueError("v3 plist changed")
    checked(ARCHIVE, 0o600, ARCHIVE_SHA256)
    checked(V2_ARCHIVE, 0o600, V2_ARCHIVE_SHA256)
    running = job(LABEL)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(SOCKET)
        connection.sendall(b"status\n")
        answer = connection.recv(128)
    prefix = b"OK phase="
    suffix = b" publication=enabled\n"
    if not answer.startswith(prefix) or not answer.endswith(suffix):
        raise ValueError("unexpected v3 socket status")
    phase = answer[len(prefix):-len(suffix)].decode("ascii")
    if phase not in PHASES:
        raise ValueError("unknown v3 phase")
    print("U2_TRIAL_V3 job=loaded running=" + ("yes" if running else "no") +
          " binary=exact plist=exact socket=responding phase=" + phase +
          " publication=enabled archives=retained")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_TRIAL_V3 rejected")
        raise SystemExit(1)
