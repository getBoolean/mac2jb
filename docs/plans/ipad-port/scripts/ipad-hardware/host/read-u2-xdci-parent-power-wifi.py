#!/usr/bin/env python3
"""Run a hash-pinned, read-only XDCI ancestor power probe over pinned Wi-Fi."""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-readonly-xdci-parent-power.py"
SOURCE_SHA256 = "f8dc403b904e95bcef2970ae4fee1dc136f59b07212f3ee39d1437b62aa30763"
RECEIPT = re.compile(rb"U2_XDCI_PARENT_POWER OnBus=(yes|no) SelectedConfiguration=(0|[1-9][0-9]{0,2}) CurrentPowerState=(0|[1-9][0-9]{0,4}) ChildProxyPowerState=(negative|above-range|0|[1-9][0-9]{0,4})\nU2_XDCI_PARENT_POWER TypeCSharesAncestor=(yes|no)\n\Z")
REJECTION = re.compile(rb"U2_XDCI_PARENT_POWER rejected stage=(setup|match|xdci|ancestor|power-dictionary|power-current|power-child|typec)\n\Z")


def validate(output):
    match = RECEIPT.fullmatch(output)
    if (not match or int(match[2]) > 255 or int(match[3]) > 65535 or
            (match[4].isdigit() and int(match[4]) > 65535)):
        raise ValueError("invalid power receipt")


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 16384:
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
                            timeout=20, check=False)
    if result.returncode != 0:
        if REJECTION.fullmatch(result.stdout):
            print(result.stdout.decode("ascii"), end="")
        raise ValueError("device probe failed")
    validate(result.stdout)
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_XDCI_PARENT_POWER rejected")
        raise SystemExit(1)
