#!/var/jb/usr/bin/python3
"""Return from a clean U2 trial service to the installed disabled watchdog.

This root-only exact-path cleanup refuses an unresolved journal. It checks
the trial job, binary digest, plist, and empty phase, boots out only the trial
label, bootstraps the original installed disabled job, verifies its socket,
then removes only the two verified trial stage files and fsyncs their parents.
If the original job cannot become ready, it retains both trial files and
attempts to restart the trial job. It never removes a journal or changes USB,
SSH, or the stock configuration.
"""

import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import time


TRIAL_SHA256 = "b91b3dc74bc27374687337e29b81df170773cf28dde252e220fe850e6ac45844"
TRIAL = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-b91b3dc7"
TRIAL_LABEL = "dev.mac2jb.u2.nooptrial"
TRIAL_PLIST = "/var/jb/Library/LaunchDaemons/" + TRIAL_LABEL + ".plist"
ORIGINAL = "/var/jb/usr/libexec/mac2jb-u2-native-watchdog"
ORIGINAL_LABEL = "dev.mac2jb.u2.watchdog"
ORIGINAL_PLIST = "/var/jb/Library/LaunchDaemons/" + ORIGINAL_LABEL + ".plist"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
JOURNAL = STATE + "/restore-journal.json"
LAUNCHCTL = "/var/jb/bin/launchctl"


def command(args, timeout=8):
    return subprocess.run(args, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=timeout).returncode


def loaded(label):
    return command([LAUNCHCTL, "print", "system/" + label], 5) == 0


def status():
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.settimeout(1)
    try:
        peer.connect(STATE + "/broker.sock")
        peer.sendall(b"status\n")
        return peer.recv(128)
    finally:
        peer.close()


def checked(path, mode, digest=None):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != mode or info.st_size > 4 * 1024 * 1024):
        raise ValueError("unsafe trial path")
    data = open(path, "rb").read()
    if digest is not None and hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("trial file changed")
    return data


def wait_status(expected):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            if status() == expected:
                return True
        except (OSError, socket.timeout):
            pass
        time.sleep(0.1)
    return False


def main():
    if os.geteuid() != 0 or os.path.lexists(JOURNAL):
        raise ValueError("unresolved journal or wrong account")
    checked(TRIAL, 0o755, TRIAL_SHA256)
    config = plistlib.loads(checked(TRIAL_PLIST, 0o644))
    if config != {
            "Label": TRIAL_LABEL,
            "ProgramArguments": [TRIAL, "--serve-noop-trial"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
            "UserName": "root"}:
        raise ValueError("trial plist changed")
    if (not loaded(TRIAL_LABEL) or loaded(ORIGINAL_LABEL) or
            status() != b"OK phase=absent publication=enabled\n"):
        raise ValueError("trial service not clean")
    if command([LAUNCHCTL, "bootout", "system/" + TRIAL_LABEL]) != 0:
        raise ValueError("trial bootout failed")
    try:
        if (command([LAUNCHCTL, "bootstrap", "system", ORIGINAL_PLIST]) != 0 or
                not wait_status(b"OK phase=absent publication=disabled\n") or
                os.path.lexists(JOURNAL)):
            raise ValueError("original service not ready")
    except BaseException:
        if not os.path.lexists(JOURNAL):
            if loaded(ORIGINAL_LABEL):
                command([LAUNCHCTL, "bootout", "system/" + ORIGINAL_LABEL])
            command([LAUNCHCTL, "bootstrap", "system", TRIAL_PLIST])
        raise
    checked(TRIAL, 0o755, TRIAL_SHA256)
    if plistlib.loads(checked(TRIAL_PLIST, 0o644)) != config:
        raise ValueError("trial file changed before removal")
    os.unlink(TRIAL)
    os.unlink(TRIAL_PLIST)
    for parent in (os.path.dirname(TRIAL), os.path.dirname(TRIAL_PLIST)):
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    print("U2_NOOP_CLEAN original=disabled trial=removed journal=absent")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, socket.timeout,
            subprocess.TimeoutExpired):
        print("U2_NOOP_CLEAN rejected; preserve trial files and journal")
        raise SystemExit(1)
