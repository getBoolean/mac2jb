#!/usr/bin/env python3
"""Issue one delayed v4 restore over Wi-Fi and observe Mac USB return.

Requires the exact failed v7 journal, its durable Mac backup, the same-boot
reference, and an idle signed v4 broker. A passive Mac USB monitor is armed
before the sole `restore` request. This script never retries a controller
call. It preserves the journal and private evidence whether USB returns or
not; confirmation is a later separate step after independent comparison.
"""

import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import runpy
import select
import shlex
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
DEVICE = ROOT / "scripts/ipad-hardware/device"
BUILD = ROOT / "build/ipad-hardware"
TRIALS = BUILD / "u2-trials"
SOURCE = DEVICE / "u2-one-delayed-restore-v4.py"
SOURCE_SHA = "983684b47bf5a074ba43fe1db14a6ed5515ba32dd3191bc803cf60fda2f6f710"
STAGE = DEVICE / "u2-stage-v4-delayed-recovery.py"
STAGE_SHA = "d18c69f59300c257421c1360adf01c5b4b0f86e66a485357c581cf7deff93829"
MONITOR = HOST / "u2-usb-return-observer.py"
MONITOR_SHA = "3104f3dd67b5f60a086f8129d8d2b1dbb363d86a785297e0c26518f2356da463"
BACKUP = BUILD / "u2-v7-journal-backup/restore-journal.recovery-required-v7.json"
JOURNAL_SHA = "9be6c2b6bad2783f80445981f88fc159ed8c8c3d8c9e56ebf4c762a8665556c1"
CHECKER = HOST / "check-u2-v7-current.py"
CHECKER_SHA = "7449f291dced3f7e2c8df83d87b434e3f881db5ce9877d78942d1b01d90ec71b"
CHECK = runpy.run_path(str(CHECKER))
RECOVERY = runpy.run_path(str(HOST / "diagnose-u2-recovery-stage.py"))
WINDOW_SECONDS = 20


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


def remote(command, source, action, timeout=15):
    line = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii")) + " " + action
    result = subprocess.run([*command, line], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout)
    if result.returncode or len(result.stdout) > 256:
        raise ValueError("remote read-only state rejected")
    return result.stdout


def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short private evidence write")
        os.fsync(fd)
    finally:
        os.close(fd)


def arm_monitor(vendor, product):
    process = subprocess.Popen(
        ["/usr/bin/python3", str(MONITOR), f"0x{vendor:04x}",
         f"0x{product:04x}", str(WINDOW_SECONDS)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        ready, _, _ = select.select([process.stdout], [], [], 8)
        line = process.stdout.readline() if ready else b""
        record = json.loads(line)
        if (record.get("type") != "ready" or record.get("windowSeconds") != WINDOW_SECONDS or
                record.get("target", {}).get("vendorID") != f"0x{vendor:04x}" or
                record.get("target", {}).get("productID") != f"0x{product:04x}" or
                record.get("initial") != "absent"):
            raise ValueError("monitor target changed")
        return process, line
    except BaseException:
        process.kill()
        process.communicate(timeout=3)
        raise


def preflight(command, source, stage):
    checked(CHECKER, CHECKER_SHA, 32 * 1024)
    checked(BACKUP, JOURNAL_SHA, 2_000_000, private=True)
    reference = CHECK["reference"]()
    boot = json.loads(reference["snapshot.json"])["snapshot"]["identity"]["boot_session"]
    if RECOVERY["read_boot_token"]() != boot or CHECK["journal"]("recoveryRequired") != JOURNAL_SHA:
        raise ValueError("failed journal or boot changed")
    if remote(command, stage, "--verify") != (
            b"U2_DELAYED_RECOVERY_STAGE verify=v4-idle journal=exact controller-write=none\n"):
        raise ValueError("v4 broker not idle")
    usb = subprocess.run(["/usr/bin/python3", str(HOST / "diagnose-usb-recognition.py")],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
    if usb.returncode or b"USBMUX query=ok count=0\nIOREG raw-ipad=no " not in usb.stdout:
        raise ValueError("Mac USB data already returned")
    scalars = json.loads((BUILD / "u2-v7-baseline/host-usb-scalars.json").read_bytes())["fields"]
    vendor, product = scalars["idVendor"], scalars["idProduct"]
    if not (0 < vendor <= 65535 and 0 < product <= 65535):
        raise ValueError("invalid target scalar")
    return boot, vendor, product


def main():
    if len(sys.argv) != 1:
        raise ValueError("fixed one-shot command")
    source = checked(SOURCE, SOURCE_SHA, 8 * 1024)
    stage = checked(STAGE, STAGE_SHA, 16 * 1024)
    checked(MONITOR, MONITOR_SHA, 32 * 1024)
    command = ssh()
    boot, vendor, product = preflight(command, source, stage)
    if not TRIALS.is_dir() or stat.S_IMODE(TRIALS.stat().st_mode) != 0o700:
        raise ValueError("unsafe trial evidence directory")
    trial = TRIALS / ("recovery-v7-" + str(time.time_ns()))
    trial.mkdir(mode=0o700)
    result = None
    timed_out_output = b""
    monitor, ready = arm_monitor(vendor, product)
    try:
        try:
            result = subprocess.run([*command, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"],
                                    input=source, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=30)
        except subprocess.TimeoutExpired as error:
            timed_out_output = error.stdout or b""
    finally:
        try:
            tail, _ = monitor.communicate(timeout=WINDOW_SECONDS + 5)
            lifecycle = ready + tail
        except subprocess.TimeoutExpired:
            monitor.kill()
            tail, _ = monitor.communicate(timeout=3)
            lifecycle = ready + tail
    private_file(trial / "restore-client.txt", (result.stdout if result else timed_out_output)[:512])
    private_file(trial / "lifecycle.ndjson", lifecycle)
    try:
        records = [json.loads(line) for line in lifecycle.splitlines()]
        summary = [item for item in records if item.get("type") == "summary"]
        arrived = any(item.get("type") == "event" and item.get("kind") == "arrived"
                      for item in records)
        complete = (len(summary) == 1 and summary[0].get("windowCompleted") is True and
                    summary[0].get("targetPresent") is True and monitor.returncode == 0)
    except (ValueError, TypeError):
        arrived = complete = False
    if (result is None or result.returncode or result.stdout !=
            b"U2_DELAYED_RESTORE api=success journal=awaitingVerification\n"):
        print("U2_DELAYED_RESTORE api=unverified journal=retained private-evidence=" + trial.name)
        raise ValueError("single restore API failed")
    if not complete or not arrived or RECOVERY["read_boot_token"]() != boot:
        print("U2_DELAYED_RESTORE external=unverified journal=retained private-evidence=" + trial.name)
        raise ValueError("USB lifecycle did not recover")
    checked_output = subprocess.run(["/usr/bin/python3", str(CHECKER),
                                     "--expect-journal=awaitingVerification"],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=70)
    if checked_output.returncode or not re.match(
            rb"U2_V7_CURRENT boot=same live=(?:original|original-plus-flag) "
            rb"configs=5 resolved-strings=23 ", checked_output.stdout):
        print("U2_DELAYED_RESTORE external=unverified journal=retained private-evidence=" + trial.name)
        raise ValueError("full external recovery failed")
    private_file(trial / "postcheck.txt", checked_output.stdout)
    print("U2_DELAYED_RESTORE external=verified journal=awaitingVerification "
          "private-evidence=" + trial.name)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired, plistlib.InvalidFileException):
        print("U2_DELAYED_RESTORE rejected; no retry; journal retained")
        raise SystemExit(1)
