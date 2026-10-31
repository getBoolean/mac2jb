#!/usr/bin/env python3
"""Install the exact publication-disabled native watchdog over pinned Wi-Fi.

The Mac checks the .deb digest, the fixed device installer source, and the
existing SSH key/host pin. The device installer refuses any existing package
or state, installs the exact rootless package, attests installed code/plist,
starts the separately supervised job, proves prepare is denied, and removes
its staged .deb. It makes reversible persistent package/service changes
recorded in the cleanup ledger but does not publish a USB description.
"""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
PACKAGE = ROOT / "build/ipad-hardware/mac2jb-u2-native-watchdog_0.1.0_iphoneos-arm64.deb"
PACKAGE_SHA256 = "6f328b46fcfd683a8b0c29c898663f5640e5ef53b39ccbe185adfd2320b307e3"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-install-native-inert-package.py"
DEVICE_SHA256 = "686757b546a197c558b919d83bc49858eefa240b8fce85482f3418f0753e875d"
WIRELESS = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
SUCCESS = b"U2_NATIVE_INSTALL package=attested service=ready publication=disabled stage=removed\n"


def checked(path, digest, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("unsafe input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("input changed")
    return data


def main():
    package = checked(PACKAGE, PACKAGE_SHA256, 1024 * 1024)
    source = checked(DEVICE, DEVICE_SHA256, 32 * 1024)
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
    result = subprocess.run(command, input=package, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=50)
    if result.stdout == SUCCESS and result.returncode == 0:
        print(SUCCESS.decode("ascii"), end="")
        return
    if (len(result.stdout) <= 200 and
            re.fullmatch(rb"(?:U2_NATIVE_INSTALL (?:install-failed stage-retained|rejected)\n){1,2}",
                         result.stdout)):
        print(result.stdout.decode("ascii"), end="")
    raise ValueError("package install or attestation failed; inspect cleanup ledger")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("U2_NATIVE_INSTALL rejected")
        raise SystemExit(1)
