#!/usr/bin/env python3
"""Read one bounded Type-C/XDCI scalar snapshot through pinned root Wi-Fi.

Validates the exact on-device payload and complete categorical output before
printing. This does not interpret integer enums or change the target.
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
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-readonly-typec-scalar-state.py"
SOURCE_SHA256 = "519b572e73b410f548b313cad1f799a69db3d324a6dc361dfd03cfce08a56547"
FIELDS = (
    ("AppleTCControllerType10", (
        ("ConnectionActive", "bool", 0),
        ("IOAccessoryUSBActive", "bool", 0),
        ("IOAccessoryUSBSuperSpeedActive", "bool", 0),
        ("IOAccessoryUSBPower", "bool", 0),
        ("PlugOrientation", "integer", 255),
        ("IOAccessoryUSBConnectType", "integer", 255),
    )),
    ("IOPortTransportStateUSB2", (
        ("Active", "bool", 0), ("DataRole", "integer", 255),
        ("DataRate", "integer", 4294967295),
        ("TRM_State", "integer", 65535),
        ("TRM_TransportRestricted", "bool", 0),
    )),
    ("IOPortTransportStateUSB3", (
        ("Active", "bool", 0), ("DataRole", "integer", 255),
        ("DataRate", "integer", 4294967295),
        ("TRM_State", "integer", 65535),
        ("TRM_TransportRestricted", "bool", 0),
    )),
    ("AppleT8112USBXDCI", (
        ("OnBus", "bool", 0),
        ("SelectedConfiguration", "integer", 255),
    )),
)
REJECTION = re.compile(rb"U2_TYPEC_SCALARS rejected stage=(?:setup|[0-3]) reason=(?:privilege|matching|query|absent|cardinality|match-limit|class-identity|properties|current-state|deadline|output-limit|internal)\n")


def scalar_value(raw, kind, maximum):
    if raw in (b"missing", b"other"):
        return
    if kind == "bool":
        if raw not in (b"yes", b"no"):
            raise ValueError("invalid boolean")
        return
    if raw == b"out-of-range":
        return
    if not re.fullmatch(rb"(?:0|[1-9][0-9]{0,9})", raw) or int(raw) > maximum:
        raise ValueError("invalid integer")


def validate(output):
    if len(output) > 4096:
        raise ValueError("oversize snapshot")
    lines = output.splitlines(keepends=True)
    if not lines or lines[0] != b"U2_TYPEC_SCALARS count=4\n":
        raise ValueError("invalid header")
    offset = 1
    for class_name, fields in FIELDS:
        expected = ("U2_TYPEC_SERVICE class=" + class_name + "\n").encode()
        if offset >= len(lines) or lines[offset] != expected:
            raise ValueError("service changed")
        offset += 1
        for name, kind, maximum in fields:
            prefix = ("U2_TYPEC_VALUE class=" + class_name + " key=" + name +
                      " value=").encode()
            if offset >= len(lines) or not lines[offset].startswith(prefix) or not lines[offset].endswith(b"\n"):
                raise ValueError("field changed")
            scalar_value(lines[offset][len(prefix):-1], kind, maximum)
            offset += 1
        if class_name == "AppleTCControllerType10":
            for name in ("CurrentPowerState", "ChildProxyPowerState"):
                prefix = ("U2_TYPEC_POWER key=" + name + " value=").encode()
                if offset >= len(lines) or not lines[offset].startswith(prefix) or not lines[offset].endswith(b"\n"):
                    raise ValueError("power field changed")
                scalar_value(lines[offset][len(prefix):-1], "integer", 255)
                offset += 1
    if lines[offset:] != [b"U2_TYPEC_SCALARS done\n"]:
        raise ValueError("incomplete snapshot")


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
        raise ValueError("device snapshot failed")
    validate(result.stdout)
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_TYPEC_SCALARS rejected")
        raise SystemExit(1)
