#!/usr/bin/env python3
"""Stage the corrected U2 no-op service after full same-boot preflight.

Requires current-boot semantic USB/pairing/charging/NCM packet proof, exact
old-journal archive and Mac backup, absent active journal, both old jobs
absent, and an exact signed v2 binary. Runs the on-device helper's read-only
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


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
DEVICE = ROOT / "scripts/ipad-hardware/device"
BINARY = ROOT / "build/ipad-hardware/u2-native-noop-trial-v2"
BINARY_SHA256 = "7e85c5f94ee2a6715e6c52179370f4594aa2f986f3feefda07b544750a290df6"
SOURCE = DEVICE / "u2-stage-native-noop-trial-v2.py"
SOURCE_SHA256 = "77042b753964402f5ca2a982372cede76bf86ab53d18d8b8f2ad5da7d9a05cab"
CHECKER = HOST / "check-u2-recovered-current.py"
ARCHIVE = runpy.run_path(str(HOST / "archive-u2-old-boot-journal-wifi.py"))
WIRELESS = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
HELPER = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))


def checked(path, digest, maximum):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= maximum):
        raise ValueError("unsafe v2 stage input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("v2 stage input changed")
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
    binary = checked(BINARY, BINARY_SHA256, 4 * 1024 * 1024)
    source = checked(SOURCE, SOURCE_SHA256, 32 * 1024)
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
        raise ValueError("v2 binary signature changed")
    archive_source = checked(ARCHIVE["SOURCE"], ARCHIVE["SOURCE_SHA256"], 16 * 1024)
    if ARCHIVE["ssh"]("--verify", archive_source, 256) != (
            b"U2_OLD_JOURNAL archive=verified active=absent trial=absent\n"):
        raise ValueError("old journal archive changed")
    external()
    command = ssh()
    if remote(command, source, binary, "--inspect") != (
            b"U2_NOOP_STAGE_V2 preflight=ready binary=exact archive=retained\n"):
        raise ValueError("v2 stage inspection changed")
    external()
    if remote(command, source, binary, "--stage") != (
            b"U2_NOOP_STAGE_V2 trial=ready journal=absent old-archive=retained\n"):
        raise ValueError("v2 stage result changed")
    external()
    print("U2_NOOP_STAGE_V2 trial=ready journal=absent "
          "old-archive=retained external=equal usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            plistlib.InvalidFileException, subprocess.TimeoutExpired):
        print("U2_NOOP_STAGE_V2 rejected; inspect exact job, files and journal")
        raise SystemExit(1)
