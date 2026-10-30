#!/var/jb/usr/bin/python3
"""Categorize the v4-to-v5 service transition without modifying the iPad."""

import os
import socket
import stat
import subprocess


ROOT = "/var/jb/usr/libexec/"
DAEMONS = "/var/jb/Library/LaunchDaemons/"
STATE = "/var/jb/var/lib/mac2jb-u2-native/"
LAUNCHCTL = "/var/jb/bin/launchctl"


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


def loaded(label):
    result = subprocess.run([LAUNCHCTL, "print", "system/" + label],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=5)
    return "yes" if result.returncode == 0 else "no"


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    old = "dev.mac2jb.u2.nooptrialv4"
    new = "dev.mac2jb.u2.nooptrialv5"
    print("U2_V5_TRANSITION_STATE old-job=" + loaded(old) +
          " new-job=" + loaded(new) +
          " old-binary=" + kind(ROOT + ".mac2jb-u2-noop-trial-cedaa717") +
          " new-binary=" + kind(ROOT + ".mac2jb-u2-noop-trial-54e29b76") +
          " old-plist=" + kind(DAEMONS + old + ".plist") +
          " new-plist=" + kind(DAEMONS + new + ".plist") +
          " socket=" + kind(STATE + "broker.sock") +
          " journal=" + kind(STATE + "restore-journal.json"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_V5_TRANSITION_STATE rejected")
        raise SystemExit(1)
