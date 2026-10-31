#!/usr/bin/env python3
"""Swap the v8 broker for the v9 auto-heal broker over pinned root Wi-Fi SSH.

Effect: makes a fresh Wi-Fi restore kit first (journal and every U2 file),
then runs device/u2-transition-v8-to-v9.py --inspect and, with --transition,
the transition itself, streaming the exact Mac-built v9 binary. Requires
healthy Mac USB before and after. No USB controller call.
"""

import hashlib
from pathlib import Path
import runpy
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-transition-v8-to-v9.py"
BINARY = ROOT / "build/ipad-hardware/u2-native-noop-trial-v9-auto-heal"
BINARY_SHA = "507b5889012f5f3177cab9443bc1b0c92f50cc79b39aff4012887eedca1733cc"
TRIAL = runpy.run_path(str(HOST / "run-u2-native-noop-trial-v8-wifi.py"))


def main(mode):
    binary = BINARY.read_bytes()
    if hashlib.sha256(binary).hexdigest() != BINARY_SHA:
        raise ValueError("v9 binary changed")
    if not TRIAL["usb_present"]():
        raise ValueError("Mac USB not healthy")
    backup = subprocess.run([sys.executable, str(HOST / "backup-u2-wifi-restore-kit.py")],
                            stdout=subprocess.PIPE, timeout=400)
    print(backup.stdout.decode(), end="")
    if backup.returncode:
        raise ValueError("backup failed")
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    source = shlex.quote(PAYLOAD.read_bytes().decode("ascii"))
    for step in (("--inspect",) if mode == "--inspect" else ("--inspect", "--transition")):
        result = subprocess.run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + source + " " + step],
                                input=binary, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=90)
        print(result.stdout.decode("ascii", "replace"), end="")
        if result.returncode:
            raise ValueError("device step failed")
    if not TRIAL["usb_present"]():
        raise ValueError("Mac USB not healthy afterwards")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("--inspect", "--transition"):
            raise ValueError("usage: --inspect|--transition")
        main(sys.argv[1])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("U2_V8_TO_V9 rejected (%s)" % error)
        raise SystemExit(1)
