#!/var/jb/usr/bin/python3
"""Stage and supervise the exact U2 no-op trial service, without publishing.

The pinned Mac runner sends the signed binary on stdin. This root-only helper
checks the installed disabled service/package, absent journal, exact prior
binary, private state, and absent trial paths; it exclusively creates the
trial binary and launchd plist and fsyncs them. It then boots out only the
disabled job and bootstraps the distinct trial job. It requires the new
socket to say `phase=absent publication=enabled` before returning. No prepare,
SetDescription, bus cycle, SSH or USB configuration change is made here. On
an admission failure with no journal it attempts to restore the original
disabled job; staged paths remain for exact-path inspection/cleanup.
"""

import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import sys
import time


TRIAL_SHA256 = "b91b3dc74bc27374687337e29b81df170773cf28dde252e220fe850e6ac45844"
ORIGINAL_SHA256 = "1c7530d5796c27ce50efb4dacd522302ffbd96bbb800513808a929d061baad14"
TRIAL = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-b91b3dc7"
TRIAL_LABEL = "dev.mac2jb.u2.nooptrial"
TRIAL_PLIST = "/var/jb/Library/LaunchDaemons/" + TRIAL_LABEL + ".plist"
ORIGINAL = "/var/jb/usr/libexec/mac2jb-u2-native-watchdog"
ORIGINAL_LABEL = "dev.mac2jb.u2.watchdog"
ORIGINAL_PLIST = "/var/jb/Library/LaunchDaemons/" + ORIGINAL_LABEL + ".plist"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
JOURNAL = STATE + "/restore-journal.json"
LAUNCHCTL = "/var/jb/bin/launchctl"
DPKG = "/var/jb/usr/bin/dpkg"


def command(args, timeout=8):
    return subprocess.run(args, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=timeout).returncode


def loaded(label):
    return command([LAUNCHCTL, "print", "system/" + label], 5) == 0


def status():
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1)
    try:
        client.connect(STATE + "/broker.sock")
        client.sendall(b"status\n")
        return client.recv(128)
    finally:
        client.close()


def exact_file(path, mode, digest=None):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != mode or info.st_size > 4 * 1024 * 1024):
        raise ValueError("unsafe file")
    data = open(path, "rb").read()
    if digest is not None and hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("file digest changed")
    return data


def fsync_parent(path):
    fd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as output:
            if output.write(data) != len(data):
                raise ValueError("short stage")
            output.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_parent(path)


def main():
    if os.geteuid() != 0 or os.path.lexists(TRIAL) or os.path.lexists(TRIAL_PLIST):
        raise ValueError("unsafe trial preflight")
    state = os.lstat(STATE)
    if (not stat.S_ISDIR(state.st_mode) or state.st_uid != 0 or
            stat.S_IMODE(state.st_mode) != 0o700 or os.path.lexists(JOURNAL) or
            not loaded(ORIGINAL_LABEL) or loaded(TRIAL_LABEL)):
        raise ValueError("unsafe service state")
    exact_file(ORIGINAL, 0o755, ORIGINAL_SHA256)
    original_plist = plistlib.loads(exact_file(ORIGINAL_PLIST, 0o644))
    if original_plist != {
            "Label": ORIGINAL_LABEL,
            "ProgramArguments": [ORIGINAL, "--serve"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
            "UserName": "root"}:
        raise ValueError("original service changed")
    if (command([DPKG, "-s", "mac2jb-u2-native-watchdog"]) != 0 or
            status() != b"OK phase=absent publication=disabled\n"):
        raise ValueError("original watchdog unavailable")
    binary = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
    if len(binary) > 4 * 1024 * 1024 or hashlib.sha256(binary).hexdigest() != TRIAL_SHA256:
        raise ValueError("trial binary changed")
    create(TRIAL, binary, 0o755)
    description = {
        "Label": TRIAL_LABEL,
        "ProgramArguments": [TRIAL, "--serve-noop-trial"],
        "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
        "UserName": "root",
    }
    create(TRIAL_PLIST, plistlib.dumps(description, fmt=plistlib.FMT_XML), 0o644)
    exact_file(TRIAL, 0o755, TRIAL_SHA256)
    if plistlib.loads(exact_file(TRIAL_PLIST, 0o644)) != description:
        raise ValueError("trial plist changed")
    if command([LAUNCHCTL, "bootout", "system/" + ORIGINAL_LABEL]) != 0:
        raise ValueError("original job did not boot out")
    try:
        if command([LAUNCHCTL, "bootstrap", "system", TRIAL_PLIST]) != 0:
            raise ValueError("trial bootstrap failed")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if status() == b"OK phase=absent publication=enabled\n":
                    break
            except (OSError, socket.timeout):
                pass
            time.sleep(0.1)
        else:
            raise ValueError("trial service not ready")
        if os.path.lexists(JOURNAL) or not loaded(TRIAL_LABEL):
            raise ValueError("unexpected trial state")
    except BaseException:
        if not os.path.lexists(JOURNAL):
            if loaded(TRIAL_LABEL):
                command([LAUNCHCTL, "bootout", "system/" + TRIAL_LABEL])
            command([LAUNCHCTL, "bootstrap", "system", ORIGINAL_PLIST])
        raise
    print("U2_NOOP_STAGE trial=ready journal=absent original=installed-disabled")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, socket.timeout,
            subprocess.TimeoutExpired):
        print("U2_NOOP_STAGE rejected; inspect exact trial paths and job")
        raise SystemExit(1)
