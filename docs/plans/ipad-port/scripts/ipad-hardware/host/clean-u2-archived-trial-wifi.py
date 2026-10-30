#!/usr/bin/env python3
"""Remove the exact stopped U2 trial stage after its journal was archived.

The host checks the durable Mac journal backup and independent iPad archive,
then runs the digest-pinned device helper's read-only inspect mode. Its clean
mode unlinks only the exact old trial binary, plist and stale broker socket.
Both U2 jobs must already be booted out. The installed disabled package and
archived journal remain. No USB controller or stock system file is changed.
"""

import hashlib
import os
from pathlib import Path
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-clean-archived-trial.py"
SOURCE_SHA256 = "9efb253550c3ffe6b1621ce47c93d0e20003610835a4ed25fdf7ac21667509a2"
ARCHIVE = runpy.run_path(str(HOST / "archive-u2-old-boot-journal-wifi.py"))
BACKUP = ROOT / "build/ipad-hardware/u2-oldboot-archive/restore-journal.oldboot.json"


def command(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=20)
    if result.returncode or len(result.stdout) > 512:
        raise ValueError("cleanup precondition unavailable")
    return result.stdout


def main():
    info = SOURCE.lstat()
    if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16 * 1024):
        raise ValueError("unsafe cleanup helper")
    payload = SOURCE.read_bytes()
    if hashlib.sha256(payload).hexdigest() != SOURCE_SHA256:
        raise ValueError("cleanup helper changed")
    backup = BACKUP.lstat()
    if (not stat.S_ISREG(backup.st_mode) or backup.st_uid != os.getuid() or
            backup.st_nlink != 1 or
            stat.S_IMODE(backup.st_mode) != 0o600 or
            hashlib.sha256(BACKUP.read_bytes()).hexdigest() !=
            ARCHIVE["EXPECTED_JOURNAL"]):
        raise ValueError("old journal Mac backup changed")
    archived = ARCHIVE["SOURCE"].read_bytes()
    if hashlib.sha256(archived).hexdigest() != ARCHIVE["SOURCE_SHA256"]:
        raise ValueError("archive verifier source changed")
    if ARCHIVE["ssh"]("--verify", archived, 256) != (
            b"U2_OLD_JOURNAL archive=verified active=absent trial=absent\n"):
        raise ValueError("old journal archive changed")
    inspect = ARCHIVE["ssh"]("--inspect", payload, 256)
    if inspect != (b"U2_ARCHIVED_TRIAL_CLEAN stage=exact socket=stale "
                   b"archive=retained jobs=absent\n"):
        raise ValueError("old trial stage changed")
    usb = command(["/usr/bin/python3", str(HOST / "diagnose-usb-recognition.py")])
    if b"USBMUX query=ok count=1\n" not in usb or b"IOREG raw-ipad=yes " not in usb:
        raise ValueError("Mac USB data unavailable")
    if ARCHIVE["ssh"]("--clean", payload, 256) != (
            b"U2_ARCHIVED_TRIAL_CLEAN stage=removed socket=removed "
            b"archive=retained jobs=absent\n"):
        raise ValueError("old trial cleanup result changed")
    if ARCHIVE["ssh"]("--verify", archived, 256) != (
            b"U2_OLD_JOURNAL archive=verified active=absent trial=absent\n"):
        raise ValueError("old archive changed after cleanup")
    trial = command(["/usr/bin/python3", str(
        HOST / "run-u2-readonly-default-description-wifi.py"), "--trial-status"])
    if (b"job=absent running=no binary=absent plist=absent socket=absent "
            not in trial or b" original-job=absent\n" not in trial):
        raise ValueError("old trial paths remain")
    print("U2_ARCHIVED_TRIAL_CLEAN stage=removed archive=retained "
          "installed-package=retained usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_ARCHIVED_TRIAL_CLEAN rejected; inspect exact paths")
        raise SystemExit(1)
