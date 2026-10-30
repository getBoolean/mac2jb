#!/usr/bin/env python3
"""Stage the readiness-gated U2 candidate after full external preflight.

Requires full USB/pairing/charging/NCM packet proof, exact four old-journal
archives and Mac backups, absent active journal, all old jobs absent, and an
exact signed v7 binary. Runs the on-device helper's read-only
inspect mode first, then its guarded stage mode. The stage only writes its
three ledgered paths and starts an idle supervised service; it never sends
prepare/publish/restore or calls the USB controller. It rechecks external
state afterward and leaves any interrupted stage for exact-path inspection.
"""

import hashlib
from pathlib import Path
import plistlib
import runpy
import shlex
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
DEVICE = ROOT / "scripts/ipad-hardware/device"
BINARY = ROOT / "build/ipad-hardware/u2-native-noop-trial-v7-ready-gated"
BINARY_SHA256 = "87f0b112378b6e38b7d90f770aa20a047f26814170edaa2bd63388aec0b1c380"
SOURCE = DEVICE / "u2-stage-native-noop-trial-v7.py"
SOURCE_SHA256 = "cc3a782e504ce0f1f858ee90dfc7201ad24cd734e2178fa33f490f15608d1470"
CHECKER = HOST / "check-u2-post-v5-reboot.py"
CHECKER_SHA256 = "a2d65fdf4d8d419e05badcc03fa42f858e12417464380e5d2418e5063aca24ef"
CLEAN = HOST / "clean-u2-v4-v5-archived-trials-wifi.py"
CLEAN_SHA256 = "5c9dab02d324ca3d3f9f80e8568231075c69a5d61a2a329be604ea8a89e603d2"
WIRELESS = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
HELPER = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))


def checked(path, digest, maximum):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= maximum):
        raise ValueError("unsafe v7 stage input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("v7 stage input changed")
    return data


def external():
    result = subprocess.run(["/usr/bin/python3", str(CHECKER),
                             "--archived"], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=70)
    if (result.returncode or len(result.stdout) > 512 or
            b"network-packet=reply usbmux=one pairing=valid " not in result.stdout or
            b" journal=archived-active-absent\n" not in result.stdout):
        raise ValueError("current-boot external state changed")


def ssh():
    address = WIRELESS["read_address"]()
    if address is None:
        raise ValueError("pinned Wi-Fi address unavailable")
    for path, digest in ((HELPER["IDENTITY"], HELPER["IDENTITY_SHA256"]),
                         (HELPER["KNOWN_HOSTS"], HELPER["KNOWN_HOSTS_SHA256"])):
        HELPER["checked_local"](path, digest, 0o600)
    return ["/usr/bin/ssh", *HELPER["ssh_options"](),
            "-o", "HostKeyAlias=" + WIRELESS["HOST_KEY_ALIAS"],
            "-o", "AddressFamily=inet", "-T", "-p", "22",
            "root@" + address]


def remote(command, source, binary, action):
    launch = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii"))
    result = subprocess.run([*command, launch + " " + action], input=binary,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=35)
    if result.returncode or len(result.stdout) > 256:
        raise ValueError("v7 device stage failed")
    return result.stdout


def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--inspect"):
        raise ValueError("invalid mode")
    binary = checked(BINARY, BINARY_SHA256, 4 * 1024 * 1024)
    source = checked(SOURCE, SOURCE_SHA256, 32 * 1024)
    checked(CHECKER, CHECKER_SHA256, 32 * 1024)
    checked(CLEAN, CLEAN_SHA256, 32 * 1024)
    verified = subprocess.run(["/usr/bin/codesign", "--verify", "--strict",
                               str(BINARY)], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=8)
    entitlements = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(BINARY)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
    if (verified.returncode or entitlements.returncode or
            plistlib.loads(entitlements.stdout) != {
                "platform-application": True,
                "com.apple.private.usbdevice.setdescription": True}):
        raise ValueError("v7 binary signature changed")
    clean = subprocess.run(["/usr/bin/python3", str(CLEAN), "--verify"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=70)
    if clean.returncode or clean.stdout != (
            b"U2_V4V5_CLEAN verified trial-stages=removed archives=retained "
            b"base=retained external=equal usb-write=none\n"):
        raise ValueError("old trial state changed")
    external()
    command = ssh()
    if remote(command, source, binary, "--inspect") != (
            b"U2_NOOP_STAGE_V7 preflight=ready binary=exact archives=retained\n"):
        raise ValueError("v7 stage inspection changed")
    if len(sys.argv) == 2:
        print("U2_NOOP_STAGE_V7 inspect=ready external=equal journal=absent")
        return
    external()
    if remote(command, source, binary, "--stage") != (
            b"U2_NOOP_STAGE_V7 trial=ready journal=absent archives=retained\n"):
        raise ValueError("v7 stage result changed")
    external()
    print("U2_NOOP_STAGE_V7 trial=ready journal=absent "
          "archives=retained external=equal usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            plistlib.InvalidFileException, subprocess.TimeoutExpired):
        print("U2_NOOP_STAGE_V7 rejected; inspect exact job, files and journal")
        raise SystemExit(1)
