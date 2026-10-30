#!/var/jb/usr/bin/python3
"""Test a read-only native U2 snapshot under rootless launchd, then clean up.

The pinned Mac runner sends the exact signed binary on stdin. This script
creates one fixed root-owned executable and launchd plist, bootstraps a
one-shot job that reads target identity and live USB registry properties,
then boots it out and removes those exact files and its bounded stdout file.
It never calls a USB mutation API or modifies SSH, the stock USB plist, or any existing service. If bootout or
verified cleanup fails, it retains paths and reports cleanup-required so a
later agent can use the cleanup ledger rather than deleting blindly.
"""

import hashlib
import os
import plistlib
import stat
import subprocess
import sys
import time


DIGEST = "de7c2f408120b12209e0cb4c02fad3d3fa88cc386100a91c783cc0d5f1fc2d9f"
BINARY = "/var/jb/usr/libexec/.mac2jb-u2-native-snapshot-de7c2f408120"
PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.nativesnapshot.plist"
OUTPUT = "/var/mobile/Media/.mac2jb-u2-native-launch-output-de7c2f408120"
LABEL = "dev.mac2jb.u2.nativesnapshot"
LAUNCHCTL = "/var/jb/bin/launchctl"
EXPECTED = b"U2_NATIVE_SNAPSHOT target=expected controller=one live=dict:16 source=expected\n"


def exclusive(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as target:
            if target.write(data) != len(data):
                raise OSError("short stage write")
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        os.unlink(path)
        raise


def exact_remove(path, digest=None, allowed=None):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0:
        raise OSError("unsafe cleanup file")
    if info.st_size > 1024 * 1024:
        raise OSError("oversized cleanup file")
    with open(path, "rb") as source:
        data = source.read()
    if digest is not None and hashlib.sha256(data).hexdigest() != digest:
        raise OSError("changed cleanup file")
    if allowed is not None and data not in allowed:
        raise OSError("changed output")
    os.unlink(path)


def main():
    if os.geteuid() != 0:
        raise OSError("root required")
    binary = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(binary) > 1024 * 1024 or hashlib.sha256(binary).hexdigest() != DIGEST:
        raise OSError("binary mismatch")
    for parent in ("/var/jb/usr/libexec", "/var/jb/Library/LaunchDaemons",
                   "/var/mobile/Media"):
        info = os.lstat(parent)
        if not stat.S_ISDIR(info.st_mode):
            raise OSError("unsafe parent")
    if os.path.lexists(OUTPUT):
        raise OSError("output already exists")
    config = {
        "Label": LABEL,
        "ProgramArguments": [BINARY, "--snapshot"],
        "RunAtLoad": True,
        "KeepAlive": False,
        "StandardOutPath": OUTPUT,
        "UserName": "root",
    }
    plist = plistlib.dumps(config, fmt=plistlib.FMT_XML)
    plist_digest = hashlib.sha256(plist).hexdigest()
    exclusive(BINARY, binary, 0o755)
    try:
        exclusive(PLIST, plist, 0o644)
    except BaseException:
        exact_remove(BINARY, DIGEST)
        raise
    loaded = False
    try:
        result = subprocess.run([LAUNCHCTL, "bootstrap", "system", PLIST],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=8)
        loaded = result.returncode == 0
        content = b""
        if loaded:
            for _ in range(20):
                try:
                    with open(OUTPUT, "rb") as source:
                        content = source.read(4097)
                except FileNotFoundError:
                    pass
                if content:
                    break
                time.sleep(0.1)
        verdict = "alive" if loaded and content == EXPECTED else "not-admitted"
        print("U2_LAUNCHD_SNAPSHOT " + verdict, flush=True)
    finally:
        if loaded:
            result = subprocess.run([LAUNCHCTL, "bootout", "system/" + LABEL],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=8)
            if result.returncode != 0:
                print("U2_LAUNCHD_SNAPSHOT cleanup-required", flush=True)
                raise OSError("bootout failed")
        exact_remove(OUTPUT, allowed=(b"", EXPECTED))
        exact_remove(PLIST, plist_digest)
        exact_remove(BINARY, DIGEST)
        print("U2_LAUNCHD_SNAPSHOT staged-files=removed", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_LAUNCHD_SNAPSHOT rejected", flush=True)
        raise SystemExit(1)
