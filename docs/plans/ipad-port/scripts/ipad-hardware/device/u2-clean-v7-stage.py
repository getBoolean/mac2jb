#!/var/jb/usr/bin/python3
"""Remove only the v7 trial stage and its stale broker socket.

Inspect mode reads exact file, journal, job, and socket state. Clean mode
requires all U2 jobs absent and all four older failed journals archived with
no active name, then unlinks only the exact v7 binary and launch plist
and a root-owned connection-refused socket. It retains the publication-
disabled base package, all journal archives, and SSH/USB configuration.
No controller API is opened or called.
"""

import errno
import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import sys

STATE = "/var/jb/var/lib/mac2jb-u2-native"
ACTIVE = STATE + "/restore-journal.json"
SOCKET = STATE + "/broker.sock"
LAUNCHCTL = "/var/jb/bin/launchctl"
ARCHIVES = (
    ("restore-journal.oldboot-77caed18.json", "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"),
    ("restore-journal.oldboot-v2-f5934b3a.json", "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"),
    ("restore-journal.oldboot-v3-b8e66632.json", "b8e66632f52f59ac13d389f650e71840d90226096bbe0945aeb881562ee7fe3d"),
    ("restore-journal.oldboot-v5-2ec38461.json", "2ec384616a51a6375e124ca3643e0bcfd0007783fe50cdab4f544a7bfb748976"),
)
TRIALS = (
    ("dev.mac2jb.u2.nooptrialv7", "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-87f0b112",
     "87f0b112378b6e38b7d90f770aa20a047f26814170edaa2bd63388aec0b1c380"),
)
ORIGINAL = "dev.mac2jb.u2.watchdog"
ORIGINAL_BINARY = "/var/jb/usr/libexec/mac2jb-u2-native-watchdog"
ORIGINAL_SHA = "1c7530d5796c27ce50efb4dacd522302ffbd96bbb800513808a929d061baad14"
OLD_LABELS = (
    ORIGINAL, "dev.mac2jb.u2.nooptrial", "dev.mac2jb.u2.nooptrialv2",
    "dev.mac2jb.u2.nooptrialv3", "dev.mac2jb.u2.nooptrialv4",
    "dev.mac2jb.u2.nooptrialv5",
)


def checked(path, mode, digest):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or
            not 0 < info.st_size <= 4 * 1024 * 1024):
        raise ValueError("stage metadata changed")
    with open(path, "rb") as source:
        data = source.read(4 * 1024 * 1024 + 1)
    if digest and hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("stage digest changed")
    return data


def job_absent(label):
    result = subprocess.run([LAUNCHCTL, "print", "system/" + label],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    if len(result.stdout) > 128 * 1024 or result.returncode == 0:
        raise ValueError("U2 job loaded")


def archived():
    info = os.lstat(STATE)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) != 0o700 or os.path.lexists(ACTIVE)):
        raise ValueError("journal state changed")
    for name, digest in ARCHIVES:
        checked(STATE + "/" + name, 0o600, digest)


def stages():
    for label, binary, digest in TRIALS:
        checked(binary, 0o755, digest)
        plist = "/var/jb/Library/LaunchDaemons/" + label + ".plist"
        value = plistlib.loads(checked(plist, 0o644, None))
        if value != {"Label": label,
                     "ProgramArguments": [binary, "--serve-noop-trial"],
                     "RunAtLoad": True, "KeepAlive": True,
                     "ThrottleInterval": 2, "UserName": "root"}:
            raise ValueError("trial plist changed")
    checked(ORIGINAL_BINARY, 0o755, ORIGINAL_SHA)
    original_plist = "/var/jb/Library/LaunchDaemons/" + ORIGINAL + ".plist"
    value = plistlib.loads(checked(original_plist, 0o644, None))
    if value != {"Label": ORIGINAL,
                 "ProgramArguments": [ORIGINAL_BINARY, "--serve"],
                 "RunAtLoad": True, "KeepAlive": True,
                 "ThrottleInterval": 2, "UserName": "root"}:
        raise ValueError("base package plist changed")


def stale_socket():
    try:
        info = os.lstat(SOCKET)
    except FileNotFoundError:
        return False
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("socket metadata changed")
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(1)
        if connection.connect_ex(SOCKET) != errno.ECONNREFUSED:
            raise ValueError("socket has listener")
    return True


def fsync_parent(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main(mode):
    if os.geteuid() != 0 or mode not in ("--inspect", "--clean", "--verify"):
        raise ValueError("root fixed mode required")
    archived()
    for label in (*OLD_LABELS, *(name for name, _, _ in TRIALS)):
        job_absent(label)
    if mode == "--verify":
        for label, binary, _ in TRIALS:
            plist = "/var/jb/Library/LaunchDaemons/" + label + ".plist"
            if os.path.lexists(binary) or os.path.lexists(plist):
                raise ValueError("trial stage remains")
        if os.path.lexists(SOCKET):
            raise ValueError("socket remains")
        checked(ORIGINAL_BINARY, 0o755, ORIGINAL_SHA)
        print("U2_V7_CLEAN stage=absent socket=absent archives=exact jobs=absent base=retained")
        return
    stages()
    has_socket = stale_socket()
    if mode == "--inspect":
        print("U2_V7_CLEAN inspect=ready socket=" +
              ("stale" if has_socket else "absent") +
              " archives=exact jobs=absent base=retained")
        return
    for label in (*OLD_LABELS, *(name for name, _, _ in TRIALS)):
        job_absent(label)
    archived()
    stages()
    if stale_socket() != has_socket:
        raise ValueError("socket changed before cleanup")
    if has_socket:
        os.unlink(SOCKET)
    for label, binary, _ in TRIALS:
        os.unlink(binary)
        os.unlink("/var/jb/Library/LaunchDaemons/" + label + ".plist")
    for parent in (STATE, "/var/jb/usr/libexec", "/var/jb/Library/LaunchDaemons"):
        fsync_parent(parent)
    main("--verify")


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_V7_CLEAN rejected")
        raise SystemExit(1)
