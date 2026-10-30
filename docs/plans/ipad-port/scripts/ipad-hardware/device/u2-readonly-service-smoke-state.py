#!/var/jb/usr/bin/python3
"""Classify exact temporary native watchdog service paths and launchd state.

This read-only iPad probe checks the one smoke binary/plist/state directory,
socket, lock, and journal, plus the exact launchd label. It does not open the
socket, remove a file, or change the service or USB controller.
"""

import os
import stat
import subprocess


BINARY = "/var/jb/usr/libexec/.mac2jb-u2-native-watchdog-1c7530d5796c"
PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.watchdogsmoke.plist"
STATE = "/var/jb/var/lib/mac2jb-u2-native"


def kind(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISSOCK(info.st_mode):
        return "socket"
    if stat.S_ISREG(info.st_mode):
        return "regular"
    return "other"


def main():
    result = subprocess.run(
        ["/var/jb/bin/launchctl", "print", "system/dev.mac2jb.u2.watchdogsmoke"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    print("U2_SERVICE_STATE job=" + ("loaded" if result.returncode == 0 else "absent") +
          " binary=" + kind(BINARY) + " plist=" + kind(PLIST) +
          " state=" + kind(STATE))
    print("U2_SERVICE_STATE socket=" + kind(STATE + "/broker.sock") +
          " lock=" + kind(STATE + "/broker.lock") +
          " journal=" + kind(STATE + "/restore-journal.json"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.TimeoutExpired):
        print("U2_SERVICE_STATE rejected")
        raise SystemExit(1)
