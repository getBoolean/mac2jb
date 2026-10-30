#!/var/jb/usr/bin/python3
"""Request exactly one delayed restore from the idle v4 native broker.

The host streams this exact script only after the failed v7 journal was backed
up and the v4 broker was staged idle on the same boot. It checks the exact
root-owned journal, confirms `recoveryRequired` over the private socket, and
sends one `restore` request. Only the broker opens the USB controller and
journals the result. This script makes no direct IOKit or filesystem write,
never retries, and never sends `confirm`. The Mac must independently observe
USB enumeration and function recovery before clearing the journal.
"""

import hashlib
import os
import socket
import stat


STATE = "/var/jb/var/lib/mac2jb-u2-native"
JOURNAL = STATE + "/restore-journal.json"
SOCKET = STATE + "/broker.sock"
EXPECTED_SHA = "9be6c2b6bad2783f80445981f88fc159ed8c8c3d8c9e56ebf4c762a8665556c1"


def ask(command):
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(20)
        peer.connect(SOCKET)
        peer.sendall(command + b"\n")
        return peer.recv(128)


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("unsafe state directory")
        fd = os.open("restore-journal.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 2_000_000):
                raise ValueError("unsafe journal")
            data = bytearray()
            while len(data) < info.st_size:
                chunk = os.read(fd, info.st_size - len(data))
                if not chunk:
                    raise ValueError("short journal")
                data.extend(chunk)
            if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
                raise ValueError("journal changed")
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    if ask(b"status") != b"OK phase=recoveryRequired publication=enabled\n":
        raise ValueError("broker not ready")
    if ask(b"restore") != b"OK restore-issued\n":
        raise ValueError("restore call rejected")
    print("U2_DELAYED_RESTORE api=success journal=awaitingVerification")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, socket.timeout):
        print("U2_DELAYED_RESTORE rejected; journal retained")
        raise SystemExit(1)
