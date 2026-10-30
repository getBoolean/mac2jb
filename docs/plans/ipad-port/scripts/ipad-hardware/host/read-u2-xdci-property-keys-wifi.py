#!/usr/bin/env python3
"""Run the bounded read-only XDCI ancestor property-key probe over pinned Wi-Fi.

The on-device source is sent in memory through the existing pinned root SSH
transport. This wrapper validates every returned line before displaying it.
No device file, registry property, USB state, or service is changed.
"""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-readonly-xdci-property-keys.py"
SOURCE_SHA256 = "010dc291b44c5116d695ff2a849828a4c1e56eaea72db1e1666cf917085f63b2"
CLASSES = (
    "AppleT8112USBXDCI", "AppleARMIODevice", "AppleT811xIO",
    "IOPlatformDevice", "AppleARMPE", "IOPlatformExpertDevice",
    "IORegistryEntry",
)
NAME = rb"[A-Za-z0-9_. /-]{1,100}"
KIND = rb"(?:bool|integer|string|dictionary|data|array|other)"
SERVICE = re.compile(rb"U2_XDCI_SERVICE depth=([0-6]) class=([A-Za-z0-9_]{1,100}) keys=([0-9]|[1-2][0-9]|3[0-2])\n")
KEY = re.compile(rb"U2_XDCI_KEY depth=([0-6]) name=(" + NAME + rb") type=" + KIND + rb"\n")
POWER = re.compile(rb"U2_XDCI_POWER_KEY depth=([0-6]) name=(" + NAME + rb") type=" + KIND + rb"\n")


def validate(output):
    lines = output.splitlines(keepends=True)
    if len(output) > 8192 or not lines or lines[0] != b"U2_XDCI_SCAN count=7\n":
        raise ValueError("invalid scan header")
    offset = 1
    for depth, class_name in enumerate(CLASSES):
        if offset >= len(lines):
            raise ValueError("missing service")
        match = SERVICE.fullmatch(lines[offset])
        if not match or int(match[1]) != depth or match[2] != class_name.encode():
            raise ValueError("service changed")
        offset += 1
        key_count = int(match[3])
        seen = set()
        for _ in range(key_count):
            if offset >= len(lines):
                raise ValueError("missing key")
            key = KEY.fullmatch(lines[offset])
            if not key or int(key[1]) != depth or key[2] in seen:
                raise ValueError("invalid key")
            seen.add(key[2])
            offset += 1
            if key[2] == b"IOPowerManagement" and lines[offset - 1].endswith(b"type=dictionary\n"):
                nested = 0
                while offset < len(lines):
                    power = POWER.fullmatch(lines[offset])
                    if not power:
                        break
                    if int(power[1]) != depth or nested >= 24:
                        raise ValueError("invalid power key")
                    nested += 1
                    offset += 1
    if lines[offset:] != [b"U2_XDCI_SCAN done\n"]:
        raise ValueError("invalid scan ending")


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 8192:
        raise ValueError("unsafe source")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("source changed")
    wireless = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22", "root@" + address,
               "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii"))]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=20)
    if result.returncode != 0:
        raise ValueError("device probe failed")
    validate(result.stdout)
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_XDCI_SCAN rejected")
        raise SystemExit(1)
