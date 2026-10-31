#!/var/jb/usr/bin/python3
"""Bootstrap the already-staged exact v8 broker idle.

Effect: `--inspect` is read-only. `--resume` requires the exact v8 binary and
plist, no active journal, the v8 job not loaded, and either no broker socket or
a stale root-owned 0600 single-link socket that refuses connections (removed);
then bootstraps only dev.mac2jb.u2.nooptrialv8 and requires
`phase=absent publication=enabled`. No prepare/publish/restore, no USB call.
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
LABEL = "dev.mac2jb.u2.nooptrialv8"
PLIST = "/var/jb/Library/LaunchDaemons/" + LABEL + ".plist"
BINARY = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-404f34aa"
BINARY_SHA = "404f34aa0656222762f7ed228907f7b7940d6462dc2a03db88a5942693b2132c"
PLIST_SHAS = ("b7222a820dd62bee2858913e0e83297d62feba18f0c60780204aaf6f10f1919b", "ef4e3c885100e77dfcce8b707bdfc3dab46ddd4365574cedbf2d5181adccf499")
LAUNCHCTL = "/var/jb/bin/launchctl"


def exact(path, mode, digest):
    digests = digest if isinstance(digest, tuple) else (digest,)
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != mode):
        raise ValueError("unsafe " + path)
    with open(path, "rb") as handle:
        if hashlib.sha256(handle.read()).hexdigest() not in digests:
            raise ValueError("changed " + path)


def loaded():
    return subprocess.run([LAUNCHCTL, "print", "system/" + LABEL], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=6).returncode == 0


def status():
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(2)
        peer.connect(SOCKET)
        peer.sendall(b"status\n")
        return peer.recv(128)


def main(mode):
    if os.geteuid() != 0 or mode not in ("--inspect", "--resume"):
        raise ValueError("fixed root mode required")
    exact(BINARY, 0o755, BINARY_SHA)
    exact(PLIST, 0o644, PLIST_SHAS)
    if os.path.lexists(STATE + "/restore-journal.json") or loaded():
        raise ValueError("journal present or v8 already loaded")
    stale = False
    if os.path.lexists(SOCKET):
        info = os.lstat(SOCKET)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("unexpected socket")
        try:
            status()
            raise ValueError("socket is live")
        except ConnectionRefusedError:
            stale = True
    if mode == "--inspect":
        print("U2_V8_RESUME inspect=ready socket=%s" % ("stale" if stale else "absent"))
        return
    if stale:
        directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.unlink("broker.sock", dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)
    if subprocess.run([LAUNCHCTL, "bootstrap", "system", PLIST], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL, timeout=10).returncode != 0:
        raise ValueError("bootstrap failed")
    time.sleep(8)
    if status() != b"OK phase=absent publication=enabled\n":
        subprocess.run([LAUNCHCTL, "bootout", "system/" + LABEL], timeout=10)
        raise ValueError("v8 not idle")
    print("U2_V8_RESUME ready phase=absent publication=enabled")


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("U2_V8_RESUME rejected (%s)" % error)
        raise SystemExit(1)
