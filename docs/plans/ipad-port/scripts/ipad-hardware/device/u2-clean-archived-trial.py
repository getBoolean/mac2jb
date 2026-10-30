#!/var/jb/usr/bin/python3
"""Remove only the stopped old U2 trial's exact stage files and stale socket.

Requires both U2 launchd labels absent, the active journal absent, and the
old journal preserved under its fixed archived name with its exact digest.
It checks the old signed binary digest and launch plist before unlinking.
The socket must be root-owned and refuse a connection. No package, journal,
USB controller, SSH configuration, or unrelated path is changed. The removed
trial binary and plist remain reproducible from private Mac build artifacts.
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
ARCHIVE = STATE + "/restore-journal.oldboot-77caed18.json"
ACTIVE = STATE + "/restore-journal.json"
SOCKET = STATE + "/broker.sock"
ARCHIVE_SHA256 = "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"
TRIAL = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-b91b3dc7"
TRIAL_SHA256 = "b91b3dc74bc27374687337e29b81df170773cf28dde252e220fe850e6ac45844"
LABEL = "dev.mac2jb.u2.nooptrial"
PLIST = "/var/jb/Library/LaunchDaemons/" + LABEL + ".plist"
LAUNCHCTL = "/var/jb/bin/launchctl"


def checked(path, mode, digest):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or
            not 0 < info.st_size <= 4 * 1024 * 1024):
        raise ValueError("unsafe exact file")
    with open(path, "rb") as source:
        data = source.read(4 * 1024 * 1024 + 1)
    if digest and hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("exact file digest changed")
    return data


def job_absent(label):
    result = subprocess.run([LAUNCHCTL, "print", "system/" + label],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=5)
    if len(result.stdout) > 128 * 1024 or result.returncode == 0:
        raise ValueError("watchdog job remains loaded")


def stale_socket():
    try:
        info = os.lstat(SOCKET)
    except FileNotFoundError:
        return False
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise ValueError("unsafe socket path")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        try:
            connection.connect(SOCKET)
        except OSError as error:
            if error.errno != errno.ECONNREFUSED:
                raise
        else:
            raise ValueError("socket still serving")
    return True


def main(mode):
    if mode not in ("--inspect", "--clean") or os.geteuid() != 0 or os.path.lexists(ACTIVE):
        raise ValueError("root required or active journal remains")
    directory = os.lstat(STATE)
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or
            stat.S_IMODE(directory.st_mode) != 0o700):
        raise ValueError("unsafe state directory")
    checked(ARCHIVE, 0o600, ARCHIVE_SHA256)
    job_absent(LABEL)
    job_absent("dev.mac2jb.u2.watchdog")
    checked(TRIAL, 0o755, TRIAL_SHA256)
    plist = plistlib.loads(checked(PLIST, 0o644, None))
    if plist != {
            "Label": LABEL, "ProgramArguments": [TRIAL, "--serve-noop-trial"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
            "UserName": "root"}:
        raise ValueError("trial plist changed")
    has_socket = stale_socket()
    if mode == "--inspect":
        print("U2_ARCHIVED_TRIAL_CLEAN stage=exact socket=" +
              ("stale" if has_socket else "absent") +
              " archive=retained jobs=absent")
        return
    # Recheck both labels immediately before removing the paths they name.
    job_absent(LABEL)
    job_absent("dev.mac2jb.u2.watchdog")
    if has_socket:
        os.unlink(SOCKET)
    os.unlink(TRIAL)
    os.unlink(PLIST)
    for parent in (STATE, os.path.dirname(TRIAL), os.path.dirname(PLIST)):
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    if (os.path.lexists(SOCKET) or os.path.lexists(TRIAL) or
            os.path.lexists(PLIST) or os.path.lexists(ACTIVE)):
        raise ValueError("old trial path still present")
    checked(ARCHIVE, 0o600, ARCHIVE_SHA256)
    print("U2_ARCHIVED_TRIAL_CLEAN stage=removed socket=removed "
          "archive=retained jobs=absent")


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired):
        print("U2_ARCHIVED_TRIAL_CLEAN rejected; inspect exact paths")
        raise SystemExit(1)
