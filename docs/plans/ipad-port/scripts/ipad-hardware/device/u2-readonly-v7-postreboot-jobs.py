#!/var/jb/usr/bin/python3
"""Classify exact U2 jobs and shared socket twice without changing device state."""

import errno
import os
import socket
import stat
import subprocess
import time

LAUNCHCTL = "/var/jb/bin/launchctl"
SOCKET = "/var/jb/var/lib/mac2jb-u2-native/broker.sock"
LABELS = (
    ("v7", "dev.mac2jb.u2.nooptrialv7"),
    ("v4", "dev.mac2jb.u2.nooptrialv4"),
    ("original", "dev.mac2jb.u2.watchdog"),
)


def job(label):
    result = subprocess.run(
        [LAUNCHCTL, "print", "system/" + label],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=6)
    if len(result.stdout) > 128 * 1024:
        raise ValueError("oversize job status")
    if result.returncode:
        return "absent"
    return "running" if b"state = running" in result.stdout else "loaded-stopped"


def broker_socket():
    try:
        info = os.lstat(SOCKET)
    except FileNotFoundError:
        return "absent", "unavailable"
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        return "unexpected", "unavailable"
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(2)
            connection.connect(SOCKET)
            connection.sendall(b"status\n")
            answer = connection.recv(129)
    except socket.timeout:
        return "owned", "timeout"
    except OSError as error:
        return "owned", "refused" if error.errno == errno.ECONNREFUSED else "unresponsive"
    if answer == b"OK phase=awaitingVerification publication=enabled\n":
        return "owned", "awaitingVerification"
    return "owned", "unexpected"


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    for round_number in (1, 2):
        states = {name: job(label) for name, label in LABELS}
        socket_state, phase = broker_socket()
        print("U2_V7_POSTREBOOT_JOBS round=" + str(round_number) +
              " v7=" + states["v7"] + " v4=" + states["v4"] +
              " original=" + states["original"] +
              " socket=" + socket_state + " phase=" + phase, flush=True)
        if round_number == 1:
            time.sleep(8)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_V7_POSTREBOOT_JOBS rejected")
        raise SystemExit(1)
