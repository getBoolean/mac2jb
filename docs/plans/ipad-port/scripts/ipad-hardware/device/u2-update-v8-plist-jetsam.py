#!/var/jb/usr/bin/python3
"""Give the idle v8 broker a 96 MB jetsam limit (it was killed at the 18 MB default).

Effect: `--inspect` is read-only. `--update` requires the exact original v8
plist, the exact v8 binary, no active journal and the broker idle
(`phase=absent`); atomically replaces only the v8 plist with the same job plus
JetsamProperties {JetsamMemoryLimit: 96, JetsamPriority: -49}, then boots the
job out and in and requires `phase=absent publication=enabled`. No USB call.
"""

import hashlib
import os
import plistlib
import socket
import subprocess
import sys
import time

LABEL = "dev.mac2jb.u2.nooptrialv8"
PLIST = "/var/jb/Library/LaunchDaemons/" + LABEL + ".plist"
OLD_SHA = "b7222a820dd62bee2858913e0e83297d62feba18f0c60780204aaf6f10f1919b"
BINARY = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-404f34aa"
BINARY_SHA = "404f34aa0656222762f7ed228907f7b7940d6462dc2a03db88a5942693b2132c"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
LAUNCHCTL = "/var/jb/bin/launchctl"
NEW = {"Label": LABEL, "ProgramArguments": [BINARY, "--serve-noop-trial"],
       "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2, "UserName": "root",
       "JetsamProperties": {"JetsamMemoryLimit": 96, "JetsamPriority": -49}}


def sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def status():
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(3)
        peer.connect(STATE + "/broker.sock")
        peer.sendall(b"status\n")
        return peer.recv(128)


def main(mode):
    if os.geteuid() != 0 or mode not in ("--inspect", "--update"):
        raise ValueError("fixed root mode required")
    if sha(BINARY) != BINARY_SHA or sha(PLIST) != OLD_SHA:
        raise ValueError("v8 stage changed")
    if os.path.lexists(STATE + "/restore-journal.json") or status() != b"OK phase=absent publication=enabled\n":
        raise ValueError("broker not idle with journal absent")
    if mode == "--inspect":
        print("U2_V8_JETSAM inspect=ready")
        return
    data = plistlib.dumps(NEW, fmt=plistlib.FMT_XML)
    temporary = PLIST + ".new"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.fchmod(fd, 0o644)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(temporary, PLIST)
    directory = os.open(os.path.dirname(PLIST), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    subprocess.run([LAUNCHCTL, "bootout", "system/" + LABEL], timeout=10)
    time.sleep(2)
    if subprocess.run([LAUNCHCTL, "bootstrap", "system", PLIST], timeout=10).returncode != 0:
        raise ValueError("bootstrap failed")
    time.sleep(8)
    if status() != b"OK phase=absent publication=enabled\n":
        raise ValueError("v8 not idle after update")
    print("U2_V8_JETSAM updated limit=96MB sha=%s" % hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("U2_V8_JETSAM rejected (%s)" % error)
        raise SystemExit(1)
