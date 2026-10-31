#!/usr/bin/env python3
"""Preserve the failed v3 journal after independently verified reboot recovery.

Inspect mode only reads iPad and Mac state. Archive mode first streams the
exact journal to an exclusive owner-only Mac backup and fsyncs it. It then
rechecks USB/NCM/SSH recovery before the pinned device helper boots out only
the exact v3 and publication-disabled jobs, hard-links the journal under a
fixed old-boot name, fsyncs, unlinks the active name, and fsyncs again. The
helper never calls a USB controller API or discards journal bytes. All three
old failed-trial journals and the Mac backup remain for later cleanup.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-archive-v3-old-boot-journal.py"
SOURCE_SHA256 = "f6ec112daa191a4bf07f19d590f53921c335b92b3ed8de310eebb0c2f6b25747"
CHECKER = HOST / "check-u2-post-v3-reboot.py"
CHECKER_SHA256 = "76a7b85c44fd8633214d1a43a32d4fe35d96a1067ae9998f0b2010100f0fd71d"
STATUS = HOST / "check-u2-v3-postreboot-service-wifi.py"
STATUS_SHA256 = "0d747d8466b92a5f9e3d0b70d6b6c0e873d19640a6788f554f25a220cdf823fd"
EXPECTED_JOURNAL = "b8e66632f52f59ac13d389f650e71840d90226096bbe0945aeb881562ee7fe3d"
DEST = ROOT / "build/ipad-hardware/u2-v3-oldboot-archive"
WIRELESS = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
HELPER = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
EXPECTED_CHECK = (b"U2_POST_V3_REBOOT boot=new live=original configs=5 "
                  b"resolved-strings=23 renumbered=12 interfaces=equal "
                  b"scalars=equal network-binding=equal network-packet=reply "
                  b"usbmux=one pairing=valid power=charging-or-full "
                  b"journal=retained-exact\n")
STAGE = "initial"


def checked(path, digest, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise ValueError("unsafe source")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("source changed")
    return data


def command(args, maximum=1024, timeout=30):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout)
    if result.returncode or len(result.stdout) > maximum:
        raise ValueError("read-only preflight unavailable")
    return result.stdout


def preflight():
    checked(CHECKER, CHECKER_SHA256, 16 * 1024)
    checked(STATUS, STATUS_SHA256, 16 * 1024)
    if command(["/usr/bin/python3", str(CHECKER)], timeout=60) != EXPECTED_CHECK:
        raise ValueError("postreboot external state changed")
    status = command(["/usr/bin/python3", str(STATUS)], maximum=256)
    if not re.fullmatch(
            rb"U2_V3_POSTREBOOT job=(?:running|loaded-stopped) binary=regular "
            rb"plist=regular socket=(?:socket|absent) "
            rb"phase=(?:unavailable|awaitingVerification) "
            rb"original-job=(?:running|loaded-stopped|absent)\n", status):
        raise ValueError("v3 watchdog state changed")
    if command(["/usr/bin/python3", str(
            HOST / "run-u2-readonly-default-description-wifi.py"),
            "--native-journal"]) != (
            "U2_NATIVE_JOURNAL phase=awaitingVerification sha256=" +
            EXPECTED_JOURNAL + "\n").encode("ascii"):
        raise ValueError("v3 journal changed")


def ssh(mode, payload, maximum):
    address = WIRELESS["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((HELPER["IDENTITY"], HELPER["IDENTITY_SHA256"]),
                         (HELPER["KNOWN_HOSTS"], HELPER["KNOWN_HOSTS_SHA256"])):
        HELPER["checked_local"](path, digest, 0o600)
    args = ["/usr/bin/ssh", *HELPER["ssh_options"](),
            "-o", "HostKeyAlias=" + WIRELESS["HOST_KEY_ALIAS"],
            "-o", "AddressFamily=inet", "-T", "-p", "22",
            "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-", mode]
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=25)
    if result.returncode or not 0 < len(result.stdout) <= maximum:
        raise ValueError("v3 archive remote step failed")
    return result.stdout


def exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short private backup write")
        os.fsync(fd)
    finally:
        os.close(fd)


def backup_metadata():
    return json.dumps({
        "version": 1, "journal_sha256": EXPECTED_JOURNAL,
        "archive_helper_sha256": SOURCE_SHA256,
        "checker_sha256": CHECKER_SHA256,
        "status_sha256": STATUS_SHA256,
        "recovery": "postreboot-only",
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def verify_backup():
    info = DEST.lstat()
    names = {path.name for path in DEST.iterdir()}
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700 or
            names != {"restore-journal.oldboot-v3.json", "backup.json"}):
        raise ValueError("unsafe backup directory")
    for name, digest in (
            ("restore-journal.oldboot-v3.json", EXPECTED_JOURNAL),
            ("backup.json", hashlib.sha256(backup_metadata()).hexdigest())):
        path = DEST / name
        details = path.lstat()
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or
                details.st_nlink != 1 or stat.S_IMODE(details.st_mode) != 0o600 or
                hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError("private backup changed")


def durable_backup(journal):
    if not DEST.exists() and not DEST.is_symlink():
        os.mkdir(DEST, 0o700)
        exclusive(DEST / "restore-journal.oldboot-v3.json", journal)
        exclusive(DEST / "backup.json", backup_metadata())
        fd = os.open(DEST, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    verify_backup()


def main():
    global STAGE
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode not in ("--inspect", "--archive") or len(sys.argv) != 2:
        raise ValueError("invalid mode")
    payload = checked(SOURCE, SOURCE_SHA256, 16 * 1024)
    STAGE = "preflight"
    preflight()
    STAGE = "copy"
    journal = ssh("--copy", payload, 2_000_000)
    if hashlib.sha256(journal).hexdigest() != EXPECTED_JOURNAL:
        raise ValueError("v3 journal copy changed")
    if mode == "--inspect":
        print("U2_V3_OLD_JOURNAL inspect=ready external=postreboot-equal "
              "journal=exact stage=known usb-write=none")
        return
    STAGE = "backup"
    durable_backup(journal)
    STAGE = "second-preflight"
    preflight()
    STAGE = "archive"
    if ssh("--archive", payload, 256) != (
            b"U2_V3_OLD_JOURNAL archive=retained active=absent "
            b"trial=booted-out old-archives=retained\n"):
        raise ValueError("v3 device archive changed")
    STAGE = "verify"
    if ssh("--verify", payload, 256) != (
            b"U2_V3_OLD_JOURNAL archive=verified active=absent "
            b"trial=absent old-archives=retained\n"):
        raise ValueError("v3 device archive verification failed")
    if command(["/usr/bin/python3", str(
            HOST / "run-u2-readonly-default-description-wifi.py"),
            "--native-journal"]) != b"U2_NATIVE_JOURNAL phase=absent sha256=none\n":
        raise ValueError("active journal still present")
    verify_backup()
    print("U2_V3_OLD_JOURNAL archived=verified mac-backup=durable "
          "trial=booted-out active=absent usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_V3_OLD_JOURNAL rejected stage=" + STAGE +
              "; inspect backup and device state")
        raise SystemExit(1)
