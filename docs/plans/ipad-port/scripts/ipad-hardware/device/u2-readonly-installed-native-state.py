#!/var/jb/usr/bin/python3
"""Classify the exact native U2 package/install state after an installer refusal.

This read-only probe checks only the fixed stage, installed files, journal,
launchd label, package registration, and dpkg audit status. It prints no
paths, package contents, or private device identifiers and changes nothing.
"""

import os
import stat
import subprocess


STAGE = "/var/mobile/Media/.mac2jb-u2-native-watchdog-6f328b46.deb"
BINARY = "/var/jb/usr/libexec/mac2jb-u2-native-watchdog"
PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.watchdog.plist"
STATE = "/var/jb/var/lib/mac2jb-u2-native"


def kind(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    if stat.S_ISREG(info.st_mode):
        return "regular"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISSOCK(info.st_mode):
        return "socket"
    return "other"


def main():
    dpkg = subprocess.run(
        ["/var/jb/usr/bin/dpkg", "-s", "mac2jb-u2-native-watchdog"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    package = ("installed" if dpkg.returncode == 0 and
               b"Status: install ok installed" in dpkg.stdout else
               "other" if dpkg.returncode == 0 else "absent")
    audit = subprocess.run(["/var/jb/usr/bin/dpkg", "--audit"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    audit_state = ("clean" if audit.returncode == 0 and not audit.stdout else "other")
    job = subprocess.run(
        ["/var/jb/bin/launchctl", "print", "system/dev.mac2jb.u2.watchdog"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    print("U2_INSTALLED_STATE package=" + package + " audit=" + audit_state +
          " job=" + ("loaded" if job.returncode == 0 else "absent"))
    print("U2_INSTALLED_STATE stage=" + kind(STAGE) + " binary=" + kind(BINARY) +
          " plist=" + kind(PLIST) + " state=" + kind(STATE) +
          " journal=" + kind(STATE + "/restore-journal.json"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.TimeoutExpired):
        print("U2_INSTALLED_STATE rejected")
        raise SystemExit(1)
