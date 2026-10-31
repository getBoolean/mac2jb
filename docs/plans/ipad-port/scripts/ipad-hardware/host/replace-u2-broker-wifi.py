#!/usr/bin/env python3
"""Swap one allowlisted U2 broker for another over pinned root Wi-Fi SSH (usage: OLD NEW).

Effect: makes a fresh Wi-Fi restore kit first (journal and every U2 file),
then runs device/u2-replace-broker.py --inspect and, with --transition,
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
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-replace-broker.py"
BINARIES = {"v12": ("u2-native-noop-trial-v12-learned-profile", "9629611372c6f570db18064a2cfcd077601f59a1b5a2a4644dbc3bdbefe37a3e"),
            "v11": ("u2-native-noop-trial-v11-auto-heal-restart", "8fdb044ff8840084e27e896432de060deecd6cdc9d27913b9ae3f379077b3736")}
SUPPORT = runpy.run_path(str(HOST / "u2_trial_support.py"))


def main(mode, old, new):
    name, digest = BINARIES[new]
    binary = (ROOT / "build/ipad-hardware" / name).read_bytes()
    if hashlib.sha256(binary).hexdigest() != digest:
        raise ValueError("new binary changed")
    if not SUPPORT["usb_present"]():
        raise ValueError("Mac USB not healthy")
    backup = subprocess.run([sys.executable, str(HOST / "backup-u2-wifi-restore-kit.py")],
                            stdout=subprocess.PIPE, timeout=400)
    print(backup.stdout.decode(), end="")
    if backup.returncode:
        raise ValueError("backup failed")
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    source = shlex.quote(PAYLOAD.read_bytes().decode("ascii"))
    for step in (("--inspect",) if mode == "--inspect" else ("--inspect", "--replace")):
        result = subprocess.run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + source + " " + step +
                                 " " + old + " " + new],
                                input=binary, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=90)
        print(result.stdout.decode("ascii", "replace"), end="")
        if result.returncode:
            raise ValueError("device step failed")
    if not SUPPORT["usb_present"]():
        raise ValueError("Mac USB not healthy afterwards")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4 or sys.argv[1] not in ("--inspect", "--replace"):
            raise ValueError("usage: --inspect|--replace OLD NEW")
        main(*sys.argv[1:4])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("U2_REPLACE rejected (%s)" % error)
        raise SystemExit(1)
