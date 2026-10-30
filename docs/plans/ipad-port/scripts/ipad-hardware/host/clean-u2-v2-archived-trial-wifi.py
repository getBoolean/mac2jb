#!/usr/bin/env python3
"""Clean the stopped v2 trial stage after exact old-boot journal archival.

The host verifies the private Mac backup, both on-device journal archives,
absent active journal and launchd jobs, exact v2 binary/plist, and stale
socket. It then removes only that binary, plist and socket and verifies their
absence. No USB controller or system configuration file is changed.
"""

import hashlib
from pathlib import Path
import runpy
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-clean-v2-archived-trial.py"
SOURCE_SHA256 = "418545aafe3876ea657e8adc04676328e5ccf54bc68e60094c78c0c22b706d7c"
ARCHIVE = runpy.run_path(str(HOST / "archive-u2-v2-old-boot-journal-wifi.py"))


def command(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=20)
    if result.returncode or len(result.stdout) > 512:
        raise ValueError("cleanup precondition unavailable")
    return result.stdout


def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--inspect"):
        raise ValueError("invalid mode")
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16 * 1024:
        raise ValueError("unsafe cleanup helper")
    payload = SOURCE.read_bytes()
    if hashlib.sha256(payload).hexdigest() != SOURCE_SHA256:
        raise ValueError("cleanup helper changed")
    ARCHIVE["verified_backup"]()
    archived = ARCHIVE["SOURCE"].read_bytes()
    if hashlib.sha256(archived).hexdigest() != ARCHIVE["SOURCE_SHA256"]:
        raise ValueError("archive verifier changed")
    if ARCHIVE["ssh"]("--verify", archived, 256) != (
            b"U2_V2_OLD_JOURNAL archive=verified active=absent "
            b"trial=absent first-archive=retained\n"):
        raise ValueError("v2 archive changed")
    inspect = ARCHIVE["ssh"]("--inspect", payload, 256)
    if inspect not in (
            b"U2_V2_ARCHIVED_TRIAL_CLEAN stage=exact socket=stale "
            b"archives=retained jobs=absent\n",
            b"U2_V2_ARCHIVED_TRIAL_CLEAN stage=exact socket=absent "
            b"archives=retained jobs=absent\n"):
        raise ValueError("v2 stage changed")
    usb = command(["/usr/bin/python3", str(HOST / "diagnose-usb-recognition.py")])
    if b"USBMUX query=ok count=1\n" not in usb or b"IOREG raw-ipad=yes " not in usb:
        raise ValueError("Mac USB data unavailable")
    if len(sys.argv) == 2:
        print("U2_V2_ARCHIVED_TRIAL_CLEAN inspect=ready archives=retained "
              "jobs=absent usb=healthy")
        return
    if ARCHIVE["ssh"]("--clean", payload, 256) != (
            b"U2_V2_ARCHIVED_TRIAL_CLEAN stage=removed socket=removed "
            b"archives=retained jobs=absent\n"):
        raise ValueError("v2 cleanup result changed")
    if command(["/usr/bin/python3", str(
            HOST / "run-u2-readonly-default-description-wifi.py"),
            "--native-journal"]) != b"U2_NATIVE_JOURNAL phase=absent sha256=none\n":
        raise ValueError("active journal returned after cleanup")
    trial = command(["/usr/bin/python3", str(
        HOST / "run-u2-readonly-default-description-wifi.py"), "--v2-postreboot"])
    if trial != (b"U2_V2_POSTREBOOT job=absent binary=absent plist=absent "
                 b"socket=absent phase=unavailable original-job=absent\n"):
        raise ValueError("v2 stage paths remain")
    print("U2_V2_ARCHIVED_TRIAL_CLEAN stage=removed archives=retained "
          "installed-package=retained usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_V2_ARCHIVED_TRIAL_CLEAN rejected; inspect exact paths")
        raise SystemExit(1)
