#!/var/jb/usr/bin/python3
"""Ask the staged U2 broker for exactly one restore after a host-observed USB failure.

Effect: verifies the root-owned active journal matches the SHA-256 given as
argv[1], reads broker status, then sends one request over the root-only
socket: `restore-after-failure` (re-publishes the journaled original only
while the controller is unconfigured), or, for older brokers without it,
plain `restore` when the phase is recoveryRequired. Never sends `confirm`,
never retries, makes no direct IOKit or file write; the broker journals.
"""

import hashlib
import os
import re
import socket
import stat
import sys

STATE = "/var/jb/var/lib/mac2jb-u2-native"
SOCKET = STATE + "/broker.sock"


def ask(command):
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(120)
        peer.connect(SOCKET)
        peer.sendall(command + b"\n")
        return peer.recv(512)


def journal_sha():
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("unsafe state directory")
        fd = os.open("restore-journal.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 2_000_000):
                raise ValueError("unsafe journal")
            data = b""
            while len(data) < info.st_size:
                chunk = os.read(fd, info.st_size - len(data))
                if not chunk:
                    raise ValueError("short journal")
                data += chunk
            return hashlib.sha256(data).hexdigest()
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or not re.fullmatch(r"[0-9a-f]{64}", sys.argv[1]):
        raise ValueError("root and exact journal digest required")
    if journal_sha() != sys.argv[1]:
        raise ValueError("journal changed")
    status = ask(b"status")
    match = re.fullmatch(rb"OK phase=(awaitingVerification|recoveryRequired) publication=enabled\n", status)
    if not match:
        raise ValueError("broker phase not eligible")
    reply = ask(b"restore-after-failure")
    if reply.startswith(b"OK restore-after-failure-issued"):
        # v9+ brokers append the automatic heal summary.
        summary = reply[len(b"OK restore-after-failure-issued"):].strip().decode("ascii", "replace")
        print("U2_WIFI_RESTORE command=restore-after-failure api=success heal=%s" %
              (summary.replace(" ", ";") or "n/a"))
        return
    if reply == b"ERR rejected\n" and match[1] == b"recoveryRequired":
        if ask(b"restore") == b"OK restore-issued\n":
            print("U2_WIFI_RESTORE command=restore api=success")
            return
    print("U2_WIFI_RESTORE command=none phase=%s broker-reply=%s" % (
        match[1].decode(), "rejected" if reply.startswith(b"ERR") else "other"))
    raise SystemExit(2)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, socket.timeout):
        print("U2_WIFI_RESTORE rejected; journal retained")
        raise SystemExit(1)
