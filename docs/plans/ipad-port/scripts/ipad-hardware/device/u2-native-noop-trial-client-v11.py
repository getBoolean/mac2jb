#!/var/jb/usr/bin/python3
"""Drive only the v11 (auto-heal incl. restart) watchdog during a bounded no-op trial.

This client never opens an IOKit controller or writes a system file. It sends
prepare, watch, and publish-noop to the separately supervised native broker,
which alone journals and invokes SetDescription with the captured original
description. `normal` closes the watched worker after three seconds;
`worker-kill` exits the client abruptly after publication; `watchdog-kill`
sends SIGKILL only to the exact trial launchd job so launchd restarts it and
the journal recovery path runs. Each mode is used only by the Mac host runner
after a private external baseline and host lifecycle monitor are armed.
"""

import os
import socket
import subprocess
import sys
import time


SOCKET = "/var/jb/var/lib/mac2jb-u2-native/broker.sock"
LAUNCHCTL = "/var/jb/bin/launchctl"
LABEL = "system/dev.mac2jb.u2.nooptrialv11"


def peer(command):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(8)
    connection.connect(SOCKET)
    connection.sendall(command)
    return connection


def ask(command):
    with peer(command + b"\n") as connection:
        return connection.recv(256)


def wait_for_verification():
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            if ask(b"status") == b"OK phase=awaitingVerification publication=enabled\n":
                return True
        except (OSError, socket.timeout):
            pass
        time.sleep(0.1)
    return False


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in (
            "status", "normal", "worker-kill", "watchdog-kill"):
        raise ValueError("unsafe client arguments")
    mode = sys.argv[1]
    if ask(b"status") != b"OK phase=absent publication=enabled\n":
        raise ValueError("trial service not ready")
    if mode == "status":
        print("U2_NOOP_CLIENT service=ready", flush=True)
        return
    if ask(b"prepare") != b"OK prepared\n":
        raise ValueError("journal preparation refused")
    worker = peer(b"watch\n")
    try:
        if worker.recv(256) != b"OK watching\n":
            raise ValueError("worker lease unavailable")
        print("U2_NOOP_CLIENT armed", flush=True)
        if ask(b"publish-noop") != b"OK published\n":
            raise ValueError("no-op publication rejected")
        print("U2_NOOP_CLIENT publication=success", flush=True)
        if mode == "normal":
            time.sleep(3)
            worker.close()
        elif mode == "worker-kill":
            os._exit(17)
        else:
            time.sleep(1)
            killed = subprocess.run([LAUNCHCTL, "kill", "SIGKILL", LABEL],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=5)
            if killed.returncode != 0:
                raise ValueError("exact trial watchdog kill rejected")
            worker.close()
        if not wait_for_verification():
            raise ValueError("watchdog did not complete restoration call")
        print("U2_NOOP_CLIENT recovery=awaitingVerification", flush=True)
    finally:
        worker.close()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, socket.timeout, subprocess.TimeoutExpired):
        print("U2_NOOP_CLIENT rejected", flush=True)
        raise SystemExit(1)
