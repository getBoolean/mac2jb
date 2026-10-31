#!/usr/bin/env python3
"""Run the exact read-only U2 job/socket classifier over pinned Wi-Fi SSH."""

import hashlib
from pathlib import Path
import re
import runpy
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-v7-postreboot-jobs.py"
SOURCE_SHA256 = "dcd7e838876b3cf456e32237c05d0cc20e3ce6bd0f6516fc5b9692c0b0cb5776"
STAGE = runpy.run_path(str(HOST / "stage-u2-noop-trial-v4-wifi.py"))
LINE = (rb"U2_V7_POSTREBOOT_JOBS round=([12]) "
        rb"v7=(absent|running|loaded-stopped) "
        rb"v4=(absent|running|loaded-stopped) "
        rb"original=(absent|running|loaded-stopped) "
        rb"socket=(absent|owned|unexpected) "
        rb"phase=(unavailable|refused|timeout|unresponsive|unexpected|awaitingVerification)\n")


def main():
    info = SOURCE.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= 16 * 1024):
        raise ValueError("unsafe probe source")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("probe source changed")
    result = subprocess.run(
        [*STAGE["ssh"](), "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"],
        input=source, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=35)
    if result.returncode or len(result.stdout) > 512:
        raise ValueError("remote probe failed")
    matches = list(re.finditer(LINE, result.stdout))
    if (len(matches) != 2 or matches[0].start() != 0 or
            matches[0].end() != matches[1].start() or
            matches[1].end() != len(result.stdout) or
            matches[0].group(1) != b"1" or matches[1].group(1) != b"2"):
        raise ValueError("remote probe output changed")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("U2_V7_POSTREBOOT_JOBS rejected")
        raise SystemExit(1)
