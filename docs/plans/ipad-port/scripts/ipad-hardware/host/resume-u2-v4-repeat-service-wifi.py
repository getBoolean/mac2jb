#!/usr/bin/env python3
"""Guarded future bootstrap of the retained exact v4 U2 broker.

Inspect checks the archived v7 journal, fresh baseline, and exact inactive v4
stage. Stage bootstraps only the retained v4 plist. Neither mode sends a
broker request or calls the USB controller. Never run on the current v7 boot.
"""

from contextlib import redirect_stdout
import hashlib
import io
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
SOURCE = DEVICE / "u2-resume-v4-repeat-service.py"
SOURCE_SHA256 = "34e72018a82e4c4ad13168d1d46c4aa1425a70d9fc24c6dd68638586d9c5bab2"
AUDIT = runpy.run_path(str(HOST / "audit-u2-v4-repeat.py"))
ARCHIVE = runpy.run_path(str(HOST / "archive-u2-v7-old-boot-journal-wifi.py"))
STAGE = runpy.run_path(str(HOST / "stage-u2-noop-trial-v4-wifi.py"))
EXPECTED = {
    "--inspect": b"U2_V4_REPEAT_SERVICE inspect=ready journal=absent archive=exact\n",
    "--stage": b"U2_V4_REPEAT_SERVICE staged=exact journal=absent archive=exact\n",
    "--verify": b"U2_V4_REPEAT_SERVICE verified=exact journal=absent archive=exact\n",
}


def source():
    info = SOURCE.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= 32 * 1024):
        raise ValueError("unsafe service source")
    data = SOURCE.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError("service source changed")
    return data


def remote(mode, payload):
    result = subprocess.run(
        [*STAGE["ssh"](), "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-", mode],
        input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=20)
    if result.returncode or result.stdout != EXPECTED[mode]:
        raise ValueError("exact v4 service state changed")


def archived_external():
    output = io.StringIO()
    with redirect_stdout(output):
        ARCHIVE["main"]("--verify")
    if output.getvalue() != "U2_V7_OLD_JOURNAL verified=exact active=absent external=equal\n":
        raise ValueError("v7 archive attestation changed")


def main(mode, manifest):
    payload = source()
    if not re.fullmatch(r"[0-9a-f]{64}", manifest):
        raise ValueError("pinned baseline digest required")
    archived_external()
    AUDIT["preflight"](manifest)
    remote("--inspect", payload)
    if mode == "--inspect":
        print("U2_V4_REPEAT_SERVICE inspect=ready archive=exact baseline=pinned")
        return
    archived_external()
    AUDIT["preflight"](manifest)
    remote("--inspect", payload)
    remote("--stage", payload)
    remote("--verify", payload)
    AUDIT["preflight"](manifest)
    print("U2_V4_REPEAT_SERVICE staged=exact archive=exact baseline=pinned "
          "controller-call=none")


if __name__ == "__main__":
    try:
        if (len(sys.argv) != 3 or sys.argv[1] not in ("--inspect", "--stage") or
                not sys.argv[2].startswith("--manifest-sha256=")):
            raise ValueError("fixed mode and pinned baseline required")
        main(sys.argv[1], sys.argv[2].split("=", 1)[1])
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            UnicodeError, subprocess.TimeoutExpired):
        print("U2_V4_REPEAT_SERVICE rejected; no broker request issued")
        raise SystemExit(1)
