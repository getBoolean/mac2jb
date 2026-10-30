#!/usr/bin/env python3
"""Run the exact read-only Type-C property-key scan over pinned root Wi-Fi.

Verifies the payload, SSH identity and host pin, then validates all categorical
output before printing. No registry values or device identifiers are emitted.
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
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-readonly-typec-property-keys.py"
SOURCE_SHA256 = "3294b2c38dc48825f454330db0e4c8539d82d5a6cf71426172b30ba93b44854a"
CLASSES = (
    "AppleTCControllerType10", "IOAccessoryUSBConnectShim",
    "IOPortTransportStateUSB2", "IOPortTransportStateUSB3",
    "AppleT8112TypeCPhy", "AppleT8112USBXDCI",
)
NAME = rb"[A-Za-z0-9_. /-]{1,100}"
KIND = rb"(?:bool|integer|string|dictionary|data|array|other)"
SERVICE = re.compile(rb"U2_TYPEC_SERVICE class=([A-Za-z0-9_]{1,100}) keys=([0-9]|[1-3][0-9]|4[0-8])\n")
KEY = re.compile(rb"U2_TYPEC_KEY class=([A-Za-z0-9_]{1,100}) name=(" + NAME + rb") type=(" + KIND + rb")\n")
SUBKEY = re.compile(rb"U2_TYPEC_SUBKEY class=([A-Za-z0-9_]{1,100}) parent=(" + NAME + rb") name=(" + NAME + rb") type=" + KIND + rb"\n")
REJECTION = re.compile(rb"U2_TYPEC_SCAN rejected stage=(?:setup|[0-5]) reason=(?:privilege|matching|query|absent|cardinality|match-limit|class-identity|properties|property-limit|key-limit|deadline|output-limit|internal)\n")


def validate(output):
    if len(output) > 16384:
        raise ValueError("oversize scan")
    lines = output.splitlines(keepends=True)
    if not lines or lines[0] != b"U2_TYPEC_SCAN count=6\n":
        raise ValueError("invalid scan header")
    offset = 1
    for class_name in CLASSES:
        if offset >= len(lines):
            raise ValueError("missing service")
        service = SERVICE.fullmatch(lines[offset])
        if not service or service[1] != class_name.encode():
            raise ValueError("service class changed")
        offset += 1
        seen = set()
        for _ in range(int(service[2])):
            if offset >= len(lines):
                raise ValueError("missing key")
            key = KEY.fullmatch(lines[offset])
            if not key or key[1] != class_name.encode() or key[2] in seen:
                raise ValueError("invalid key")
            seen.add(key[2])
            offset += 1
            if key[3] == b"dictionary":
                nested = set()
                while offset < len(lines):
                    subkey = SUBKEY.fullmatch(lines[offset])
                    if not subkey:
                        break
                    if (subkey[1] != class_name.encode() or subkey[2] != key[2] or
                            subkey[3] in nested or len(nested) >= 16):
                        raise ValueError("invalid nested key")
                    nested.add(subkey[3])
                    offset += 1
    if lines[offset:] != [b"U2_TYPEC_SCAN done\n"]:
        raise ValueError("incomplete scan")


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 12288:
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
        if result.returncode == 1 and REJECTION.fullmatch(result.stdout):
            print(result.stdout.decode("ascii"), end="")
            raise SystemExit(1)
        raise ValueError("device scan failed")
    validate(result.stdout)
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_TYPEC_SCAN rejected")
        raise SystemExit(1)
