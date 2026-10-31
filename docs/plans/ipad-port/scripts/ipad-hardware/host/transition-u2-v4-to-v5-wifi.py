#!/usr/bin/env python3
"""Stage v5 idle after exact v4 state and external USB proof.

Inspect mode is read-only. Stage mode boots out only the idle v4 job and
starts the signed v5 service, retaining the old v4 binary/plist for reversal.
The on-device helper makes no controller call and creates no journal. This
host verifies full USB/NCM/pairing/power state before and after the change.
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
BINARY = ROOT / "build/ipad-hardware/u2-native-noop-trial-v5-postclone"
BINARY_SHA256 = "54e29b7635bae3a700366100333aa10849321c69e23ac90d26f41240bce83387"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-transition-v4-to-v5.py"
SOURCE_SHA256 = "8167d340b0e635b1c7e365e09b7a948d9c0e44fa99ac9c59aa48b0ebeb1cc356"
CHECKER = HOST / "check-u2-v4-current.py"
CHECKER_SHA256 = "f0b6cfbe7aca08cb10fc4dcce68d39ca0fe77cd3880cb802a3a6a8531cf9b3f1"
WIRELESS = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
HELPER = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
EXPECTED_EXTERNAL = (b"U2_V4_CURRENT boot=same live=original-plus-flag "
                     b"configs=5 resolved-strings=23 renumbered=14 "
                     b"interfaces=equal scalars=equal network-binding=equal "
                     b"network-packet=reply usbmux=one pairing=valid "
                     b"power=charging-or-full journal=absent\n")


def checked(path, digest, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise ValueError("unsafe transition input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("transition input changed")
    return data


def command(args, timeout=30):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout)
    if result.returncode or len(result.stdout) > 512:
        raise ValueError("transition preflight failed")
    return result.stdout


def external():
    if command(["/usr/bin/python3", str(CHECKER),
                "--expect-journal=absent"], timeout=70) != EXPECTED_EXTERNAL:
        raise ValueError("current external state changed")


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


def remote(identity, source, binary, action):
    launch = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii"))
    result = subprocess.run([*identity, launch + " " + action], input=binary,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=35)
    if result.returncode or len(result.stdout) > 256:
        raise ValueError("v5 device transition failed")
    return result.stdout


def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] not in
                                ("--inspect", "--resume-inspect", "--resume")):
        raise ValueError("invalid mode")
    resume = len(sys.argv) == 2 and sys.argv[1] in ("--resume-inspect", "--resume")
    inspect = len(sys.argv) == 2 and sys.argv[1] in ("--inspect", "--resume-inspect")
    binary = checked(BINARY, BINARY_SHA256, 4 * 1024 * 1024)
    source = checked(SOURCE, SOURCE_SHA256, 32 * 1024)
    checked(CHECKER, CHECKER_SHA256, 32 * 1024)
    verified = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(BINARY)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
    entitlements = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(BINARY)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
    if (verified.returncode or entitlements.returncode or
            plistlib.loads(entitlements.stdout) != {
                "platform-application": True,
                "com.apple.private.usbdevice.setdescription": True}):
        raise ValueError("v5 binary signature changed")
    if resume:
        if command(["/usr/bin/python3", str(
                HOST / "check-u2-v5-transition-state-wifi.py")]) != (
                b"U2_V5_TRANSITION_STATE old-job=no new-job=no old-binary=regular "
                b"new-binary=absent old-plist=regular new-plist=absent "
                b"socket=socket journal=absent\n"):
            raise ValueError("resume state changed")
    elif command(["/usr/bin/python3", str(HOST / "check-u2-v4-service-wifi.py")]) != (
            b"U2_TRIAL_V4 job=loaded running=yes binary=exact plist=exact "
            b"socket=responding phase=absent publication=enabled archives=retained\n"):
        raise ValueError("v4 stage changed")
    if command(["/usr/bin/python3", str(HOST / "check-u2-three-archives-wifi.py")]) != (
            b"U2_ARCHIVES_THREE first=exact v2=exact v3=exact active=absent\n"):
        raise ValueError("old archives changed")
    external()
    identity = ssh()
    inspect_action = "--inspect-resume" if resume else "--inspect"
    expected_inspect = (b"U2_TRANSITION_V5 inspect=resume-ready old=booted-out "
                        b"new=absent archives=retained\n") if resume else (
                        b"U2_TRANSITION_V5 inspect=ready old=idle "
                        b"new=absent archives=retained\n")
    if remote(identity, source, binary, inspect_action) != expected_inspect:
        raise ValueError("v5 transition inspection changed")
    if inspect:
        print("U2_TRANSITION_V5 inspect=ready external=equal journal=absent")
        return
    external()
    if remote(identity, source, binary, "--resume" if resume else "--stage") != (
            b"U2_TRANSITION_V5 trial=idle journal=absent old=retained archives=retained\n"):
        raise ValueError("v5 transition result changed")
    external()
    if command(["/usr/bin/python3", str(HOST / "check-u2-v5-service-wifi.py")]) != (
            b"U2_TRIAL_V5 job=loaded running=yes binary=exact plist=exact "
            b"socket=responding phase=absent publication=enabled archives=retained\n"):
        raise ValueError("v5 service not exact and idle")
    print("U2_TRANSITION_V5 trial=idle old=retained journal=absent "
          "archives=retained external=equal usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            plistlib.InvalidFileException, subprocess.TimeoutExpired):
        print("U2_TRANSITION_V5 rejected; inspect jobs, exact paths and journal")
        raise SystemExit(1)
