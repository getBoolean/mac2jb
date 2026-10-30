#!/var/jb/usr/bin/python3
"""Remove only the verified leftovers from the failed native service smoke.

The job must already be absent. This script checks the exact staged binary
digest, exact launchd plist, private directory, empty lock, stale socket,
and absent journal before unlinking them and removing the empty directory.
It does not modify a live service, SSH, USB, or any system configuration.
If any file changed or a journal appeared, it refuses all cleanup.
"""

import hashlib
import os
import plistlib
import stat
import subprocess


BINARY = "/var/jb/usr/libexec/.mac2jb-u2-native-watchdog-1c7530d5796c"
DIGEST = "1c7530d5796c27ce50efb4dacd522302ffbd96bbb800513808a929d061baad14"
PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.watchdogsmoke.plist"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
SOCKET = STATE + "/broker.sock"
LOCK = STATE + "/broker.lock"
LABEL = "dev.mac2jb.u2.watchdogsmoke"


def checked(path, kind, mode, limit):
    info = os.lstat(path)
    if (info.st_uid != 0 or (kind != "directory" and info.st_nlink != 1) or
            stat.S_IMODE(info.st_mode) != mode or info.st_size > limit):
        raise OSError("changed path")
    if kind == "regular" and not stat.S_ISREG(info.st_mode):
        raise OSError("changed file type")
    if kind == "directory" and not stat.S_ISDIR(info.st_mode):
        raise OSError("changed directory type")
    if kind == "socket" and not stat.S_ISSOCK(info.st_mode):
        raise OSError("changed socket type")


def main():
    if os.geteuid() != 0:
        raise OSError("root required")
    result = subprocess.run(
        ["/var/jb/bin/launchctl", "print", "system/" + LABEL],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    if result.returncode == 0 or os.path.lexists(STATE + "/restore-journal.json"):
        raise OSError("live job or journal")
    checked(BINARY, "regular", 0o755, 4 * 1024 * 1024)
    checked(PLIST, "regular", 0o644, 4096)
    checked(STATE, "directory", 0o700, 4096)
    checked(SOCKET, "socket", 0o600, 4096)
    checked(LOCK, "regular", 0o600, 0)
    with open(BINARY, "rb") as source:
        if hashlib.sha256(source.read()).hexdigest() != DIGEST:
            raise OSError("binary changed")
    with open(PLIST, "rb") as source:
        config = plistlib.load(source)
    if config != {
            "Label": LABEL,
            "ProgramArguments": [BINARY, "--serve"],
            "RunAtLoad": True, "KeepAlive": True,
            "ThrottleInterval": 2, "UserName": "root"}:
        raise OSError("plist changed")
    if set(os.listdir(STATE)) != {"broker.sock", "broker.lock"}:
        raise OSError("unexpected state entries")
    os.unlink(SOCKET)
    os.unlink(LOCK)
    os.rmdir(STATE)
    os.unlink(PLIST)
    os.unlink(BINARY)
    print("U2_SERVICE_CLEANUP removed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_SERVICE_CLEANUP rejected")
        raise SystemExit(1)
