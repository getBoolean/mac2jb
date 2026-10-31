#!/usr/bin/env python3
"""Retire exact old U2 launchd plists on the iPad over pinned root Wi-Fi SSH.

Effect: requires the latest restore kit to hold byte-exact copies of each
named plist, then runs device/u2-remove-old-u2-plists.py --inspect and, with
--remove, unlinks only those plists. Usage: --inspect|--remove LABEL...
"""

import hashlib
import json
from pathlib import Path
import runpy
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-remove-old-u2-plists.py"
KITS = ROOT / "build/ipad-hardware/u2-wifi-restore-kit"


def kit_has(label):
    kit = sorted(KITS.iterdir())[-1]
    path = "/var/jb/Library/LaunchDaemons/%s.plist" % label
    entries = [e for e in json.loads((kit / "manifest.json").read_bytes())["device"] if e["path"] == path]
    copy = kit / "device" / path.lstrip("/")
    return len(entries) == 1 and hashlib.sha256(copy.read_bytes()).hexdigest() == entries[0]["sha256"]


def main(mode, labels):
    if not labels or not all(kit_has(label) for label in labels):
        raise ValueError("restore kit lacks an exact plist backup")
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    source = PAYLOAD.read_bytes().decode("ascii")
    for step in (("--inspect",) if mode == "--inspect" else ("--inspect", "--remove")):
        result = subprocess.run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source) +
                                 " " + " ".join([step, *map(shlex.quote, labels)])],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
        out = result.stdout.decode("ascii", "replace")
        print(out, end="")
        if result.returncode:
            raise ValueError("device step failed")


if __name__ == "__main__":
    try:
        if len(sys.argv) < 3 or sys.argv[1] not in ("--inspect", "--remove"):
            raise ValueError("usage: --inspect|--remove LABEL...")
        main(sys.argv[1], sys.argv[2:])
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        print("U2_PLIST_RETIRE rejected (%s)" % error)
        raise SystemExit(1)
