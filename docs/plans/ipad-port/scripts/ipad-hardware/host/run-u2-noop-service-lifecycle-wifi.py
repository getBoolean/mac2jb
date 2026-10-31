#!/usr/bin/env python3
"""Stage or clean the exact supervised U2 no-op trial service over Wi-Fi.

`stage` requires the full external baseline and absent journal, pins the
signed trial binary and device helper, then stages a distinct rootless
launchd service while preserving the installed disabled package. It does not
prepare a journal or call SetDescription. `cleanup` requires a clean external
state and no journal, returns to the installed disabled service, and removes
only the two exact trial files. Both paths verify pinned SSH inputs; all
persistent iPad paths and reversal conditions are in the cleanup ledger.
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
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
TRIAL = ROOT / "build/ipad-hardware/u2-native-noop-trial"
TRIAL_SHA256 = "b91b3dc74bc27374687337e29b81df170773cf28dde252e220fe850e6ac45844"
STAGE = DEVICE / "u2-stage-native-noop-trial.py"
STAGE_SHA256 = "d3910ef347a47ce4b2339220ccdd36678cb5984ca74ae29225add027077d88b2"
CLEAN = DEVICE / "u2-clean-native-noop-trial.py"
CLEAN_SHA256 = "4b49997c172f03361274ff76281e2d7390776074f66bcfb393697bca26d9ecd3"
CHECKER = HOST / "check-u2-external-current.py"
WIRELESS = HOST / "check-pinned-wireless-ssh.py"
HELPER = HOST / "backup-clienttruth-over-root-ssh.py"


def checked(path, digest, maximum):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= maximum):
        raise ValueError("unsafe lifecycle input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("lifecycle input changed")
    return data


def preflight():
    result = subprocess.run(
        ["/usr/bin/python3", str(CHECKER), "--expect-journal=absent"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if (result.returncode != 0 or
            b"usb-network-driver=absent journal=absent\n" not in result.stdout):
        raise ValueError("external baseline unavailable")


def ssh():
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe private address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    return ["/usr/bin/ssh", *helper["ssh_options"](),
            "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
            "-o", "AddressFamily=inet", "-T", "-p", "22", "root@" + address]


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("stage", "cleanup"):
        raise ValueError("invalid lifecycle action")
    action = sys.argv[1]
    preflight()
    command = ssh()
    if action == "stage":
        binary = checked(TRIAL, TRIAL_SHA256, 4 * 1024 * 1024)
        signature = subprocess.run(["/usr/bin/codesign", "--verify", "--strict",
                                    str(TRIAL)], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=8)
        entitlements = subprocess.run(
            ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(TRIAL)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
        if (signature.returncode != 0 or entitlements.returncode != 0 or
                plistlib.loads(entitlements.stdout) != {
                    "platform-application": True,
                    "com.apple.private.usbdevice.setdescription": True}):
            raise ValueError("trial signature changed")
        source = checked(STAGE, STAGE_SHA256, 32 * 1024)
        remote = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii"))
        expected = b"U2_NOOP_STAGE trial=ready journal=absent original=installed-disabled\n"
        result = subprocess.run([*command, remote], input=binary,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=40)
    else:
        source = checked(CLEAN, CLEAN_SHA256, 32 * 1024)
        expected = b"U2_NOOP_CLEAN original=disabled trial=removed journal=absent\n"
        result = subprocess.run(
            [*command, "/var/jb/usr/bin/python3 -I -S -B -"], input=source,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    if result.returncode != 0 or result.stdout != expected:
        raise ValueError("device lifecycle rejected; inspect cleanup ledger")
    preflight()
    print(expected.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, TypeError, KeyError,
            plistlib.InvalidFileException, subprocess.TimeoutExpired):
        print("U2_NOOP_LIFECYCLE rejected; inspect device job and ledger")
        raise SystemExit(1)
