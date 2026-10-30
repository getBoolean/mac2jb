#!/var/jb/usr/bin/python3
"""Classify the v5 watchdog's postreboot job and socket without changing it.

This reads only the exact launchd label and file kinds, and optionally sends
the socket's status request. A stale postreboot socket is reported as such.
It does not publish, restore, confirm, boot out, or change an iPad file.
"""

import os
import socket
import stat
import subprocess


LABEL = "system/dev.mac2jb.u2.nooptrialv5"
ORIGINAL = "system/dev.mac2jb.u2.watchdog"
BINARY = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-54e29b76"
PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.nooptrialv5.plist"
SOCKET = "/var/jb/var/lib/mac2jb-u2-native/broker.sock"


def kind(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    if stat.S_ISREG(info.st_mode):
        return "regular"
    if stat.S_ISSOCK(info.st_mode):
        return "socket"
    return "other"


def job(label):
    result = subprocess.run(["/var/jb/bin/launchctl", "print", label],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5)
    if len(result.stdout) > 128 * 1024:
        raise ValueError("oversized job state")
    if result.returncode:
        return "absent"
    return "running" if b"state = running" in result.stdout else "loaded-stopped"


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    trial = job(LABEL)
    original = job(ORIGINAL)
    socket_kind = kind(SOCKET)
    phase = "unavailable"
    if socket_kind == "socket":
        try:
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(2)
                connection.connect(SOCKET)
                connection.sendall(b"status\n")
                response = connection.recv(128)
            if response == b"OK phase=awaitingVerification publication=enabled\n":
                phase = "awaitingVerification"
        except OSError:
            pass
    print("U2_V5_POSTREBOOT job=" + trial + " binary=" + kind(BINARY) +
          " plist=" + kind(PLIST) + " socket=" + socket_kind +
          " phase=" + phase + " original-job=" + original)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_V5_POSTREBOOT rejected")
        raise SystemExit(1)
