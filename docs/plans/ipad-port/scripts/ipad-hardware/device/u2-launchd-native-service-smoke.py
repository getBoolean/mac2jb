#!/var/jb/usr/bin/python3
"""Stage and test the native watchdog with publication hard-disabled.

The pinned Mac runner supplies an exact signed binary. This script creates a
private empty state directory, one root-owned executable and launchd plist,
boots a supervised service, checks its root-only socket status and that
prepare is refused, then boots it out and removes only those verified paths.
The binary's --serve entry cannot enable publication; no journal or USB
write is allowed in this smoke. A cleanup failure retains the paths for the
recorded cleanup procedure.
"""

import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import sys
import time


DIGEST = "1c7530d5796c27ce50efb4dacd522302ffbd96bbb800513808a929d061baad14"
BINARY = "/var/jb/usr/libexec/.mac2jb-u2-native-watchdog-1c7530d5796c"
PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.watchdogsmoke.plist"
LABEL = "dev.mac2jb.u2.watchdogsmoke"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
SOCKET = STATE + "/broker.sock"
LOCK = STATE + "/broker.lock"
LAUNCHCTL = "/var/jb/bin/launchctl"


def exclusive(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as output:
            if output.write(data) != len(data):
                raise OSError("short stage write")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        os.unlink(path)
        raise


def exact_remove(path, digest, mode):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or
            info.st_size > 4 * 1024 * 1024):
        raise OSError("unsafe cleanup file")
    with open(path, "rb") as source:
        if hashlib.sha256(source.read()).hexdigest() != digest:
            raise OSError("changed cleanup file")
    os.unlink(path)


def request(command):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1)
    try:
        client.connect(SOCKET)
        client.sendall((command + "\n").encode("ascii"))
        result = client.recv(257)
        if len(result) > 256:
            raise OSError("oversized broker result")
        return result
    finally:
        client.close()


def main():
    if os.geteuid() != 0 or os.path.lexists(STATE):
        raise OSError("unsafe or existing state")
    binary = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
    if len(binary) > 4 * 1024 * 1024 or hashlib.sha256(binary).hexdigest() != DIGEST:
        raise OSError("binary mismatch")
    for parent in ("/var/jb/usr/libexec", "/var/jb/Library/LaunchDaemons",
                   "/var/jb/var/lib"):
        info = os.lstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise OSError("unsafe parent")
    plist = plistlib.dumps({
        "Label": LABEL,
        "ProgramArguments": [BINARY, "--serve"],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 2,
        "UserName": "root",
    }, fmt=plistlib.FMT_XML)
    plist_digest = hashlib.sha256(plist).hexdigest()
    exclusive(BINARY, binary, 0o755)
    try:
        exclusive(PLIST, plist, 0o644)
    except BaseException:
        exact_remove(BINARY, DIGEST, 0o755)
        raise
    try:
        os.mkdir(STATE, 0o700)
    except BaseException:
        exact_remove(PLIST, plist_digest, 0o644)
        exact_remove(BINARY, DIGEST, 0o755)
        raise
    loaded = False
    try:
        result = subprocess.run([LAUNCHCTL, "bootstrap", "system", PLIST],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=8)
        loaded = result.returncode == 0
        ready = False
        if loaded:
            for _ in range(30):
                try:
                    status = request("status")
                    ready = status == b"OK phase=absent publication=disabled\n"
                    if ready:
                        break
                except (OSError, socket.timeout):
                    pass
                time.sleep(0.1)
        denied = ready and request("prepare") == b"ERR rejected\n"
        no_journal = not os.path.lexists(STATE + "/restore-journal.json")
        print("U2_NATIVE_SERVICE status=" +
              ("ready" if ready else "unavailable") +
              " prepare=" + ("denied" if denied else "unexpected") +
              " journal=" + ("absent" if no_journal else "present"), flush=True)
    finally:
        if loaded:
            result = subprocess.run([LAUNCHCTL, "bootout", "system/" + LABEL],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=8)
            if result.returncode != 0:
                print("U2_NATIVE_SERVICE cleanup-required", flush=True)
                raise OSError("bootout failed")
        for _ in range(20):
            if not os.path.lexists(SOCKET):
                break
            time.sleep(0.1)
        if os.path.lexists(STATE + "/restore-journal.json"):
            print("U2_NATIVE_SERVICE cleanup-required", flush=True)
            raise OSError("journal remains")
        if os.path.lexists(SOCKET):
            remaining = subprocess.run(
                [LAUNCHCTL, "print", "system/" + LABEL],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            info = os.lstat(SOCKET)
            check = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                connected = check.connect_ex(SOCKET) == 0
            finally:
                check.close()
            if (remaining.returncode == 0 or
                    not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or
                    stat.S_IMODE(info.st_mode) != 0o600 or connected):
                print("U2_NATIVE_SERVICE cleanup-required", flush=True)
                raise OSError("live or changed socket")
            os.unlink(SOCKET)
        if os.path.lexists(LOCK):
            exact_remove(LOCK, hashlib.sha256(b"").hexdigest(), 0o600)
        os.rmdir(STATE)
        exact_remove(PLIST, plist_digest, 0o644)
        exact_remove(BINARY, DIGEST, 0o755)
        print("U2_NATIVE_SERVICE staged-files=removed", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_NATIVE_SERVICE rejected", flush=True)
        raise SystemExit(1)
