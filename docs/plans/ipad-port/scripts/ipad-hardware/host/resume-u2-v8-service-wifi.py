#!/usr/bin/env python3
"""Run device/u2-resume-v8-service.py over pinned root Wi-Fi SSH (--inspect|--resume).

Effect: --inspect is read-only; --resume bootstraps only the exact staged v8
broker idle (removing a verified stale socket). Requires healthy Mac USB and a
configured XDCI before and after. No USB controller call.
"""

from pathlib import Path
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-resume-v8-service.py"
ARCHIVE = runpy.run_path(str(HOST / "archive-u2-v8-old-boot-journal-wifi.py"))


def main(mode):
    before = ARCHIVE["external"]()
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    for step in (("--inspect",) if mode == "--inspect" else ("--inspect", "--resume")):
        result = subprocess.run([*ssh, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-", step],
                                input=PAYLOAD.read_bytes(), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=60)
        print(result.stdout.decode("ascii", "replace"), end="")
        if result.returncode:
            raise ValueError("device step failed")
    if ARCHIVE["external"]() != before:
        raise ValueError("controller census changed")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("--inspect", "--resume"):
            raise ValueError("usage: --inspect|--resume")
        main(sys.argv[1])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("U2_V8_RESUME rejected (%s)" % error)
        raise SystemExit(1)
