#!/usr/bin/env python3
"""Guarded new-boot archival of the exact failed v4-repeat U2 journal.

--fixture runs entirely on the Mac. --inspect and --verify are target read-only.
--archive boots out the loaded U2 jobs (v7, v4, original) and hard-links then
unlinks the active journal under one fixed archive name. Preconditions: exact
byte-equal private Mac backup, the Wi-Fi restore kit holding the same bytes,
healthy Mac USB (one USBMux device, raw iPad at configuration 5) and a
configured XDCI controller, before and after. No USB controller call.
"""

import base64
import hashlib
import json
from pathlib import Path
import runpy
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
BUILD = ROOT / "build/ipad-hardware"
SOURCE = DEVICE / "u2-archive-v4-repeat-old-boot-journal.py"
EXPECTED = "639c07c183ebc4e0f8c07b099416d8c66c7ebefb92a5d2227bc19068008d1729"
BACKUP = BUILD / "u2-v4-repeat-journal-backup/restore-journal.awaiting-verification-v4-repeat.json"
KIT_PATH = "/var/jb/var/lib/mac2jb-u2-native/restore-journal.json"
ARCHIVED_PATH = "/var/jb/var/lib/mac2jb-u2-native/restore-journal.oldboot-v4r-639c07c1.json"
TAG = b"U2_V4R_OLD_JOURNAL "
EXPECT = {
    "--inspect": TAG + b"inspect=ready jobs=known socket=owned journal=exact old-archives=retained\n",
    "--archive": TAG + b"archive=retained active=absent jobs=booted-out old-archives=retained\n",
    "--verify": TAG + b"archive=verified active=absent jobs=absent old-archives=retained\n",
}


def backups():
    info = BACKUP.lstat()
    data = BACKUP.read_bytes()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or
            hashlib.sha256(data).hexdigest() != EXPECTED):
        raise ValueError("private Mac journal backup changed")
    kits = sorted((BUILD / "u2-wifi-restore-kit").iterdir())
    kit = json.loads((kits[-1] / "manifest.json").read_bytes())
    # Before archival the journal is the active name; afterwards, the archive.
    entry = [e for e in kit["device"]
             if e["path"] in (KIT_PATH, ARCHIVED_PATH) and e.get("sha256") == EXPECTED]
    copy = kits[-1] / "device" / entry[0]["path"].lstrip("/") if len(entry) == 1 else None
    if copy is None or hashlib.sha256(copy.read_bytes()).hexdigest() != EXPECTED:
        raise ValueError("restore kit lacks the exact journal")
    return data


def external():
    usb = subprocess.run([sys.executable, str(HOST / "diagnose-usb-recognition.py")],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    if (usb.returncode or b"USBMUX query=ok count=1\n" not in usb.stdout or
            b"raw-ipad=yes current-configuration=5" not in usb.stdout):
        raise ValueError("Mac USB not healthy")
    census = subprocess.run([sys.executable, str(HOST / "read-u2-xdci-child-census-wifi.py")],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if census.returncode or b"DeviceState=configured OnBus=yes SelectedConfiguration=5" not in census.stdout:
        raise ValueError("controller not configured")
    return census.stdout


def remote(mode, payload):
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    result = subprocess.run([*ssh, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-", mode],
                            input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=40)
    if result.returncode or result.stdout != EXPECT[mode]:
        raise ValueError("remote archive state changed (%s)" % mode)


def fixture(data):
    device = runpy.run_path(str(SOURCE))
    device["exact_bytes"](data, EXPECTED)
    wrong = bytearray(data)
    wrong[-1] ^= 1
    try:
        device["exact_bytes"](wrong, EXPECTED)
        raise AssertionError("wrong journal accepted")
    except ValueError:
        pass
    payload = json.loads(base64.b64decode(json.loads(data)["payload"]))
    device["validate_old_boot"].__globals__["boot_token"] = lambda: payload["recipe"]["bootSession"]
    try:
        device["validate_old_boot"](data)
        raise AssertionError("journal's own boot accepted as old")
    except ValueError:
        pass
    for good in (("running", "loaded-stopped", "loaded-stopped"), ("absent", "running", "absent"),
                 ("loaded-stopped", "running", "absent")):
        device["preflight_jobs"](good)
    for bad in (("running", "running", "absent"), ("absent", "absent", "absent")):
        try:
            device["preflight_jobs"](bad)
            raise AssertionError("bad job layout accepted")
        except ValueError:
            pass
    print("U2_V4R_ARCHIVE_FIXTURE wrong-journal=rejected same-boot=rejected "
          "job-layouts=checked mac-backup=exact device-action=none")


def main(mode):
    data = backups()
    payload = SOURCE.read_bytes()
    if mode == "--fixture":
        fixture(data)
        return
    if mode == "--verify":
        external()
        remote("--verify", payload)
        print("U2_V4R_OLD_JOURNAL verified active=absent external=healthy")
        return
    before = external()
    remote("--inspect", payload)
    if mode == "--inspect":
        print("U2_V4R_OLD_JOURNAL inspect=ready boot=new journal=exact external=healthy backups=exact")
        return
    remote("--archive", payload)
    remote("--verify", payload)
    if external() != before:
        raise ValueError("controller census changed during archive")
    print("U2_V4R_OLD_JOURNAL archived=verified active=absent external=healthy backups=exact")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("--fixture", "--inspect", "--archive", "--verify"):
            raise ValueError("fixed mode required")
        main(sys.argv[1])
    except (OSError, ValueError, TypeError, KeyError, IndexError, UnicodeError,
            AssertionError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print("U2_V4R_OLD_JOURNAL rejected (%s); exact journal and Mac backups retained" % error)
        raise SystemExit(1)
