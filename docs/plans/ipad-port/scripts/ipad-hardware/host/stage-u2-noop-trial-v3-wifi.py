#!/usr/bin/env python3
"""Stage the explicit-bus-cycle U2 candidate after full same-boot preflight.

Requires current-boot semantic USB/pairing/charging/NCM packet proof, exact
old-journal archives and Mac backups, absent active journal, all old jobs
absent, and an exact signed v3 binary. Runs the on-device helper's read-only
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
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
BINARY = ROOT / "build/ipad-hardware/u2-native-noop-trial-v3-buscycle"
BINARY_SHA256 = "c98b4ee9d6405036d38d9a05df87a388dd6db63c77452b8c72383dd4276febd7"
SOURCE = DEVICE / "u2-stage-native-noop-trial-v3.py"
SOURCE_SHA256 = "d6fedd6985b285f6c096972d3e755231b3d67ac17dc2a593e1f6a95f928d2a33"
CHECKER = HOST / "check-u2-v3-current.py"
CHECKER_SHA256 = "c90396d4631cfe28e010f29a2157e0391c36e855cd65db349e4c265c39d0d269"
WIRELESS = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
HELPER = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))


def checked(path, digest, maximum):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= maximum):
        raise ValueError("unsafe v3 stage input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("v3 stage input changed")
    return data


def external():
    result = subprocess.run(["/usr/bin/python3", str(CHECKER),
                             "--expect-journal=absent"], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=70)
    if (result.returncode or len(result.stdout) > 512 or
            b"network-packet=reply usbmux=one pairing=valid " not in result.stdout or
            b" journal=absent\n" not in result.stdout):
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
        raise ValueError("v2 device stage failed")
    return result.stdout


def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--inspect"):
        raise ValueError("invalid mode")
    binary = checked(BINARY, BINARY_SHA256, 4 * 1024 * 1024)
    source = checked(SOURCE, SOURCE_SHA256, 32 * 1024)
    checked(CHECKER, CHECKER_SHA256, 32 * 1024)
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
        raise ValueError("v3 binary signature changed")
    checked(ROOT / "build/ipad-hardware/u2-oldboot-archive/restore-journal.oldboot.json",
            "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39",
            2_000_000)
    checked(ROOT / "build/ipad-hardware/u2-v2-oldboot-archive/restore-journal.oldboot-v2.json",
            "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0",
            2_000_000)
    if subprocess.run(["/usr/bin/python3", str(
            HOST / "run-u2-readonly-default-description-wifi.py"), "--archives"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20).stdout != (
            b"U2_ARCHIVES first=exact v2=exact active=absent\n"):
        raise ValueError("old journal archives changed")
    if subprocess.run(["/usr/bin/python3", str(
            HOST / "run-u2-readonly-default-description-wifi.py"), "--v2-postreboot"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20).stdout != (
            b"U2_V2_POSTREBOOT job=absent binary=absent plist=absent "
            b"socket=absent phase=unavailable original-job=absent\n"):
        raise ValueError("old trial stage remains")
    external()
    command = ssh()
    if remote(command, source, binary, "--inspect") != (
            b"U2_NOOP_STAGE_V3 preflight=ready binary=exact archives=retained\n"):
        raise ValueError("v3 stage inspection changed")
    if len(sys.argv) == 2:
        print("U2_NOOP_STAGE_V3 inspect=ready external=equal journal=absent")
        return
    external()
    if remote(command, source, binary, "--stage") != (
            b"U2_NOOP_STAGE_V3 trial=ready journal=absent archives=retained\n"):
        raise ValueError("v3 stage result changed")
    external()
    print("U2_NOOP_STAGE_V3 trial=ready journal=absent "
          "archives=retained external=equal usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            plistlib.InvalidFileException, subprocess.TimeoutExpired):
        print("U2_NOOP_STAGE_V3 rejected; inspect exact job, files and journal")
        raise SystemExit(1)
