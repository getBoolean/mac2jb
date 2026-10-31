#!/var/jb/usr/bin/python3
"""Replace the v8 broker with the v9 auto-heal broker, keeping the active journal.

Effect: `--inspect` is read-only. `--transition` requires the exact v8
binary/plist, an active journal in recoveryRequired or awaitingVerification,
and absent v9 paths; reads the exact v9 binary from stdin; boots v8 out;
removes only the stale socket and the v8 plist; exclusively creates the v9
binary (0755) and plist (0644, JetsamMemoryLimit 96); bootstraps v9 and
requires it to report the same journal phase. The journal is never modified.
No USB controller call.
"""

import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import sys
import time

STATE = "/var/jb/var/lib/mac2jb-u2-native"
SOCKET = STATE + "/broker.sock"
JOURNAL = STATE + "/restore-journal.json"
LAUNCHCTL = "/var/jb/bin/launchctl"
DAEMONS = "/var/jb/Library/LaunchDaemons/"
V8 = "dev.mac2jb.u2.nooptrialv8"
V8_PLIST = DAEMONS + V8 + ".plist"
V8_PLIST_SHAS = ("b7222a820dd62bee2858913e0e83297d62feba18f0c60780204aaf6f10f1919b",
                 "ef4e3c885100e77dfcce8b707bdfc3dab46ddd4365574cedbf2d5181adccf499")
V8_BINARY = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-404f34aa"
V8_SHA = "404f34aa0656222762f7ed228907f7b7940d6462dc2a03db88a5942693b2132c"
V9 = "dev.mac2jb.u2.nooptrialv9"
V9_PLIST = DAEMONS + V9 + ".plist"
V9_BINARY = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-507b5889"
V9_SHA = "507b5889012f5f3177cab9443bc1b0c92f50cc79b39aff4012887eedca1733cc"
V9_DESCRIPTION = {"Label": V9, "ProgramArguments": [V9_BINARY, "--serve-noop-trial"],
                  "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2, "UserName": "root",
                  "JetsamProperties": {"JetsamMemoryLimit": 96, "JetsamPriority": -49}}


def sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def loaded(label):
    return subprocess.run([LAUNCHCTL, "print", "system/" + label], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=6).returncode == 0


def status():
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(5)
        peer.connect(SOCKET)
        peer.sendall(b"status\n")
        return peer.recv(128)


def create(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        if os.write(fd, data) != len(data):
            raise ValueError("short write")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(mode):
    if os.geteuid() != 0 or mode not in ("--inspect", "--transition"):
        raise ValueError("fixed root mode required")
    if sha(V8_BINARY) != V8_SHA or sha(V8_PLIST) not in V8_PLIST_SHAS or not loaded(V8):
        raise ValueError("v8 stage changed")
    if os.path.lexists(V9_BINARY) or os.path.lexists(V9_PLIST) or loaded(V9):
        raise ValueError("v9 already present")
    info = os.lstat(JOURNAL)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("journal unsafe")
    journal_sha = sha(JOURNAL)
    before = status()
    if before not in (b"OK phase=recoveryRequired publication=enabled\n",
                      b"OK phase=awaitingVerification publication=enabled\n"):
        raise ValueError("journal phase not eligible")
    binary = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
    if hashlib.sha256(binary).hexdigest() != V9_SHA:
        raise ValueError("v9 binary changed")
    if mode == "--inspect":
        print("U2_V8_TO_V9 inspect=ready %s" % before.decode().strip().replace("OK ", ""))
        return
    if subprocess.run([LAUNCHCTL, "bootout", "system/" + V8], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL, timeout=10).returncode != 0 or loaded(V8):
        raise ValueError("v8 bootout failed")
    if sha(JOURNAL) != journal_sha:
        raise ValueError("journal changed during bootout")
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.path.lexists(SOCKET):
            try:
                status()
                raise ValueError("socket still live")
            except ConnectionRefusedError:
                os.unlink("broker.sock", dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)
    os.unlink(V8_PLIST)
    create(V9_BINARY, binary, 0o755)
    create(V9_PLIST, plistlib.dumps(V9_DESCRIPTION, fmt=plistlib.FMT_XML), 0o644)
    if subprocess.run([LAUNCHCTL, "bootstrap", "system", V9_PLIST], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL, timeout=10).returncode != 0:
        raise ValueError("v9 bootstrap failed")
    time.sleep(8)
    after = status()
    if after != before or sha(JOURNAL) != journal_sha:
        raise ValueError("v9 state differs after start")
    print("U2_V8_TO_V9 transitioned v9=running %s journal=unchanged" %
          after.decode().strip().replace("OK ", ""))


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("U2_V8_TO_V9 rejected (%s)" % error)
        raise SystemExit(1)
