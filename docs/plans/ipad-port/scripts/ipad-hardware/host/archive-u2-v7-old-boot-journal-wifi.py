#!/usr/bin/env python3
"""Guarded new-boot archival of the exact failed v7 U2 journal.

--fixture runs entirely on the Mac. --inspect and --verify are target read-only.
--archive boots out the exact v7, original, and v4 jobs and hard-links then unlinks the
active journal under one fixed archive name. It is for a future owner-approved
new boot with full USB/NCM/pairing/power recovery, never the current v7 boot.
"""

import hashlib
import json
from pathlib import Path
import runpy
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
DEVICE = ROOT / "scripts/ipad-hardware/device"
SOURCE = DEVICE / "u2-archive-v7-old-boot-journal.py"
SOURCE_SHA256 = "818717eb5cf37cdac6f4f0052168abc51bb24b64a1fa6c3a54c9e943b9f3a416"
AUDIT = runpy.run_path(str(HOST / "audit-u2-v4-repeat.py"))
STAGE = runpy.run_path(str(HOST / "stage-u2-noop-trial-v4-wifi.py"))
EXPECTED = AUDIT["PRIOR_JOURNAL_SHA256"]
EXPECT_INSPECT = (b"U2_V7_OLD_JOURNAL inspect=ready jobs=known socket=owned "
                  b"journal=exact old-archives=retained\n")
EXPECT_ARCHIVE = (b"U2_V7_OLD_JOURNAL archive=retained active=absent "
                  b"jobs=booted-out old-archives=retained\n")
EXPECT_VERIFY = (b"U2_V7_OLD_JOURNAL archive=verified active=absent "
                 b"jobs=absent old-archives=retained\n")


def source():
    info = SOURCE.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= 32 * 1024):
        raise ValueError("unsafe archive source")
    data = SOURCE.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError("archive source changed")
    return data


def remote(mode, payload):
    command = STAGE["ssh"]()
    result = subprocess.run(
        [*command, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-", mode],
        input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=30)
    expected = {"--inspect": EXPECT_INSPECT, "--archive": EXPECT_ARCHIVE,
                "--verify": EXPECT_VERIFY}[mode]
    if result.returncode or result.stdout != expected:
        raise ValueError("remote archive state changed")


def external(archived):
    AUDIT["preserved_prior_journal"]()
    boot, old = AUDIT["new_boot"]()  # Reject the current v7 kernel boot.
    if archived:
        check = AUDIT["journal_absent"]
    else:
        checker = runpy.run_path(str(HOST / "check-u2-v7-current.py"))
        def check():
            if checker["journal"]("awaitingVerification") != EXPECTED:
                raise ValueError("active v7 journal changed")
    return AUDIT["capture_one"](boot, old, check)


def fixture():
    payload = source()
    device = runpy.run_path(str(SOURCE))
    data = AUDIT["PRIOR_JOURNAL_BACKUP"].read_bytes()
    device["exact_bytes"](data, EXPECTED)
    wrong = bytearray(data)
    wrong[-1] ^= 1
    try:
        device["exact_bytes"](wrong, EXPECTED)
    except ValueError:
        pass
    else:
        raise ValueError("wrong archive accepted")
    prior = runpy.run_path(str(HOST / "check-u2-v7-current.py"))["reference"]()
    old_boot = json.loads(prior["snapshot.json"])["snapshot"]["identity"]["boot_session"]
    device["validate_old_boot"].__globals__["boot_token"] = lambda: old_boot
    try:
        device["validate_old_boot"](data)
    except ValueError:
        pass
    else:
        raise ValueError("current boot accepted")
    for states in (("running", "loaded-stopped", "loaded-stopped"),
                   ("absent", "running", "absent")):
        device["preflight_jobs"](states)
    for states in (("running", "running", "loaded-stopped"),
                   ("running", "loaded-stopped", "running"),
                   ("absent", "loaded-stopped", "absent")):
        try:
            device["preflight_jobs"](states)
        except ValueError:
            pass
        else:
            raise ValueError("unexpected U2 job layout accepted")
    print("U2_V7_ARCHIVE_FIXTURE current-boot=rejected wrong-archive=rejected "
          "wrong-jobs=rejected exact-mac-backup=yes device-action=none")


def main(mode):
    payload = source()
    AUDIT["preserved_prior_journal"]()
    if mode == "--fixture":
        fixture()
        return
    if mode == "--verify":
        external(True)
        remote("--verify", payload)
        external(True)
        print("U2_V7_OLD_JOURNAL verified=exact active=absent external=equal")
        return
    before = external(False)
    remote("--inspect", payload)
    if mode == "--inspect":
        print("U2_V7_OLD_JOURNAL inspect=ready boot=new journal=exact "
              "external=equal mac-backup=exact")
        return
    if before != external(False):
        raise ValueError("external state changed before archive")
    remote("--inspect", payload)
    remote("--archive", payload)
    remote("--verify", payload)
    after = external(True)
    if before != after:
        raise ValueError("external state changed during archive")
    print("U2_V7_OLD_JOURNAL archived=verified active=absent "
          "external=equal mac-backup=exact")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in (
                "--fixture", "--inspect", "--archive", "--verify"):
            raise ValueError("fixed mode required")
        main(sys.argv[1])
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            UnicodeError, subprocess.TimeoutExpired, json.JSONDecodeError):
        print("U2_V7_OLD_JOURNAL rejected; exact journal and Mac backup retained")
        raise SystemExit(1)
