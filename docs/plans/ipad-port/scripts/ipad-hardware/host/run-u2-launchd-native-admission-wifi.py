#!/usr/bin/env python3
"""Run the fixed harmless native launchd admission test over pinned Wi-Fi.

The Mac validates the exact signed binary, its two entitlements, the exact
device-side cleanup program, and the pinned SSH host/key. The iPad program
uses a one-shot launchd job and removes its own verified files. This test
does not touch a USB controller or leave a service installed when cleanup
reports success. Its possible leftover paths are in the cleanup ledger.
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
BINARY = ROOT / "build/ipad-hardware/u2-native-admission-smoke"
BINARY_SHA256 = "459d1e3f4f0f9c1792920f6dcdd548fecb94753de0d36c1af5e2b6e2b0e2c83c"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-launchd-native-admission.py"
DEVICE_SHA256 = "c096b042904adae00f67b57deedbdad9caa70f2b3cd5998526d84e9c8e8e62d4"
WIRELESS = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
OUTPUT = re.compile(
    rb"U2_LAUNCHD_ADMISSION (?:alive|not-admitted)\n"
    rb"U2_LAUNCHD_ADMISSION staged-files=removed\n\Z"
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
        print("U2_LAUNCHD_ADMISSION rejected")
        raise SystemExit(1)
