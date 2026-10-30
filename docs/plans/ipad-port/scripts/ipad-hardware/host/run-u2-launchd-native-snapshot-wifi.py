#!/usr/bin/env python3
"""Run the fixed read-only native snapshot under rootless launchd over pinned Wi-Fi.

The Mac validates the exact signed binary, its two entitlements, the exact
device-side read-only snapshot/cleanup program, and the pinned SSH host/key. The iPad program
uses a one-shot launchd job and removes its own verified files. This test reads one USB controller registry description without mutating it;
it leaves no service installed when cleanup reports success. Its possible leftover paths are in the cleanup ledger.
"""

import hashlib
from pathlib import Path
import plistlib
import re
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
BINARY = ROOT / "build/ipad-hardware/u2-native-snapshot"
BINARY_SHA256 = "de7c2f408120b12209e0cb4c02fad3d3fa88cc386100a91c783cc0d5f1fc2d9f"
DEVICE = ROOT / "scripts/ipad-hardware/device/u2-launchd-native-snapshot.py"
DEVICE_SHA256 = "1f960ab0c7ee16d0e9318924f92f82f7d66adafeb058f354abc78627f9dcc562"
WIRELESS = ROOT / "scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
OUTPUT = re.compile(
    rb"U2_LAUNCHD_SNAPSHOT (?:alive|not-admitted)\n"
    rb"U2_LAUNCHD_SNAPSHOT staged-files=removed\n\Z"
)


def checked(path, digest, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("unsafe source")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("source changed")
    return data


def main():
    binary = checked(BINARY, BINARY_SHA256, 1024 * 1024)
    source = checked(DEVICE, DEVICE_SHA256, 32 * 1024)
    signature = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(BINARY)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
    entitlements = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(BINARY)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
    if (signature.returncode != 0 or entitlements.returncode != 0 or
            plistlib.loads(entitlements.stdout) != {
                "platform-application": True,
                "com.apple.private.usbdevice.setdescription": True}):
        raise ValueError("native signature changed")
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe private address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    remote = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii"))
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, remote]
    result = subprocess.run(command, input=binary, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30)
    if result.returncode != 0 or not OUTPUT.fullmatch(result.stdout):
        raise ValueError("launchd test or cleanup failed; inspect ledger paths")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, plistlib.InvalidFileException,
            subprocess.TimeoutExpired):
        print("U2_LAUNCHD_SNAPSHOT rejected")
        raise SystemExit(1)
