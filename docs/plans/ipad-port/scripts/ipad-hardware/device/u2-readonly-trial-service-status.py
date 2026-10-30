#!/var/jb/usr/bin/python3
"""Classify the exact native U2 trial service without changing its state.

This checks the known launchd label and exact staged paths, then sends only
the root-only broker's `status` request through its existing Unix socket. It
does not send prepare, restore, confirm, or any USB/controller command. It
prints no PID, device identifier, socket content beyond the fixed status
categories, or journal recipe.
"""

import os
import socket
import stat
import subprocess


LABEL = "system/dev.mac2jb.u2.nooptrial"
ORIGINAL_LABEL = "system/dev.mac2jb.u2.watchdog"
BINARY = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-b91b3dc7"
PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.nooptrial.plist"
SOCKET = "/var/jb/var/lib/mac2jb-u2-native/broker.sock"
PHASES = {"absent", "prepared", "published", "restoring",
          "awaitingVerification", "recoveryRequired", "restored"}


def kind(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    if stat.S_ISREG(info.st_mode):
        return "regular"
    if stat.S_ISSOCK(info.st_mode):
        return "socket"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    return "other"


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    def job_state(label):
        job = subprocess.run(["/var/jb/bin/launchctl", "print", label],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=5)
        if len(job.stdout) > 128 * 1024:
            raise ValueError("oversize launchd state")
        if job.returncode:
            return "absent"
        return "running" if b"state = running" in job.stdout else "loaded-stopped"

    trial = job_state(LABEL)
    original = job_state(ORIGINAL_LABEL)
    loaded = trial != "absent"
    running = trial == "running"
    phase = "unavailable"
    publication = "unavailable"
    if kind(SOCKET) == "socket":
        try:
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(2)
                connection.connect(SOCKET)
                connection.sendall(b"status\n")
                response = connection.recv(128)
            if (response.startswith(b"OK phase=") and
                    response.endswith(b" publication=enabled\n")):
                value = response[len(b"OK phase="):-len(b" publication=enabled\n")]
                if value.decode("ascii") in PHASES:
                    phase = value.decode("ascii")
                    publication = "enabled"
        except (OSError, UnicodeError):
            # A reboot may leave a stale socket path while launchd has no job.
            # Keep reporting the file kind without changing the socket.
            pass
    print("U2_TRIAL_SERVICE job=" + ("loaded" if loaded else "absent") +
          " running=" + ("yes" if running else "no") +
          " binary=" + kind(BINARY) + " plist=" + kind(PLIST) +
          " socket=" + kind(SOCKET) +
          " phase=" + phase + " publication=" + publication +
          " original-job=" + original)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("U2_TRIAL_SERVICE rejected")
        raise SystemExit(1)
