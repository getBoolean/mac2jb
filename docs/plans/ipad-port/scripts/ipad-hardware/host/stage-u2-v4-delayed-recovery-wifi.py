#!/usr/bin/env python3
"""Prepare an exact v4 broker for one delayed same-boot v7 restore.

This checks the private v7 journal backup, matching boot, off-bus condition,
signed v4 binary, exact active journal and idle v7 service. Inspect is fully
read-only. Stage only boots out v7, writes the ledgered v4 binary/plist and
starts v4 idle on the same journal. It does not send `restore` or make a USB
controller call. The later restore is a separate exact command.
"""

import hashlib
import json
import os
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
SOURCE = DEVICE / "u2-stage-v4-delayed-recovery.py"
SOURCE_SHA = "d18c69f59300c257421c1360adf01c5b4b0f86e66a485357c581cf7deff93829"
V7_STATUS = DEVICE / "u2-readonly-trial-v7-status.py"
V7_STATUS_SHA = "9cbbbe457427540e72a6c5aaaaff487ba6f1c4f316478911a5129553ce2b3780"
V4_BINARY = ROOT / "build/ipad-hardware/u2-native-noop-trial-v4-clone"
V4_SHA = "cedaa71736aaf0d27f886b5cade552bfd6ee5ff3fde4e9c8eaaac071a8db34c7"
BACKUP = ROOT / "build/ipad-hardware/u2-v7-journal-backup/restore-journal.recovery-required-v7.json"
JOURNAL_SHA = "9be6c2b6bad2783f80445981f88fc159ed8c8c3d8c9e56ebf4c762a8665556c1"
CHECKER = runpy.run_path(str(HOST / "check-u2-v7-current.py"))
RECOVERY = runpy.run_path(str(HOST / "diagnose-u2-recovery-stage.py"))


def checked(path, digest, maximum, private=False):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= maximum or
            (private and (info.st_uid != os.getuid() or
                          stat.S_IMODE(info.st_mode) != 0o600))):
        raise ValueError("unsafe exact input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("exact input changed")
    return data


def ssh():
    wireless = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    return ["/usr/bin/ssh", *helper["ssh_options"](),
            "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
            "-o", "AddressFamily=inet", "-T", "-p", "22", "root@" + address]


def remote(command, source, action, data=b"", timeout=25):
    line = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii")) + " " + action
    result = subprocess.run([*command, line], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout)
    if result.returncode or len(result.stdout) > 256:
        raise ValueError("remote recovery stage rejected")
    return result.stdout


def preflight(command):
    backup = checked(BACKUP, JOURNAL_SHA, 2_000_000, private=True)
    if not backup.startswith(b"{"):
        raise ValueError("backup envelope changed")
    reference = CHECKER["reference"]()
    boot = json.loads(reference["snapshot.json"])["snapshot"]["identity"]["boot_session"]
    if RECOVERY["read_boot_token"]() != boot or CHECKER["journal"]("recoveryRequired") != JOURNAL_SHA:
        raise ValueError("same-boot failed journal changed")
    status = checked(V7_STATUS, V7_STATUS_SHA, 16 * 1024)
    if remote(command, status, "--status") != (
            b"U2_TRIAL_V7 job=loaded running=yes binary=exact plist=exact "
            b"socket=responding phase=recoveryRequired publication=enabled archives=retained\n"):
        raise ValueError("v7 broker state changed")
    bus = subprocess.run(["/opt/homebrew/bin/go", "run", str(HOST / "run-readonly-controller-property-keys-wifi.go"),
                          "--bus"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if bus.returncode or bus.stdout != (
            b"CONTROLLER_BUS query=ok state=disconnected onbus=no speed=4 config=0\n"):
        raise ValueError("controller state changed")
    raw = subprocess.run(["/usr/bin/python3", str(HOST / "diagnose-usb-recognition.py")],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
    if raw.returncode or b"USBMUX query=ok count=0\nIOREG raw-ipad=no " not in raw.stdout:
        raise ValueError("Mac USB state changed")
    binary = checked(V4_BINARY, V4_SHA, 4 * 1024 * 1024)
    signature = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(V4_BINARY)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
    entitlements = subprocess.run(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(V4_BINARY)],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
    if (signature.returncode or entitlements.returncode or
            plistlib.loads(entitlements.stdout) != {
                "platform-application": True,
                "com.apple.private.usbdevice.setdescription": True}):
        raise ValueError("v4 signature changed")
    return binary


def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--inspect"):
        raise ValueError("invalid mode")
    source = checked(SOURCE, SOURCE_SHA, 16 * 1024)
    command = ssh()
    binary = preflight(command)
    if remote(command, source, "--inspect", binary) != (
            b"U2_DELAYED_RECOVERY_STAGE inspect=ready journal=exact v7=idle v4=absent\n"):
        raise ValueError("device inspect changed")
    if len(sys.argv) == 2:
        print("U2_DELAYED_RECOVERY_STAGE inspect=ready journal=exact usb=offbus ipad-write=none")
        return
    expected = (b"U2_DELAYED_RECOVERY_STAGE verify=v4-idle journal=exact controller-write=none\n"
                b"U2_DELAYED_RECOVERY_STAGE v4=idle journal=exact controller-write=none\n")
    if remote(command, source, "--stage", binary, timeout=35) != expected:
        raise ValueError("v4 idle stage incomplete; inspect exact paths")
    if remote(command, source, "--verify") != expected.splitlines(keepends=True)[0]:
        raise ValueError("v4 idle verification changed")
    if RECOVERY["read_boot_token"]() != json.loads(CHECKER["reference"]()["snapshot.json"])["snapshot"]["identity"]["boot_session"]:
        raise ValueError("boot changed after idle stage")
    print("U2_DELAYED_RECOVERY_STAGE v4=idle journal=exact controller-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            plistlib.InvalidFileException, subprocess.TimeoutExpired):
        print("U2_DELAYED_RECOVERY_STAGE rejected; inspect journal and jobs")
        raise SystemExit(1)
