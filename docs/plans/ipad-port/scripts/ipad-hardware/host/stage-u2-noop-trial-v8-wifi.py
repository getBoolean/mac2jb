#!/usr/bin/env python3
"""Stage the signed v8 U2 broker idle over pinned root Wi-Fi SSH.

Effect: `--inspect` is read-only. `--stage` streams the exact Mac-built v8
binary to device/u2-stage-native-noop-trial-v8.py, which creates only the v8
binary and launchd plist (and removes a verified stale broker socket), then
bootstraps the v8 job idle. Requires healthy Mac USB and a configured XDCI
before and after. Sends no prepare/publish/restore and makes no USB call.
"""

import hashlib
from pathlib import Path
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-stage-native-noop-trial-v8.py"
BINARY = ROOT / "build/ipad-hardware/u2-native-noop-trial-v8-wifi-restore"
BINARY_SHA256 = "404f34aa0656222762f7ed228907f7b7940d6462dc2a03db88a5942693b2132c"
ARCHIVE = runpy.run_path(str(HOST / "archive-u2-v4-repeat-old-boot-journal-wifi.py"))


def main(mode):
    binary = BINARY.read_bytes()
    if hashlib.sha256(binary).hexdigest() != BINARY_SHA256:
        raise ValueError("v8 binary changed")
    before = ARCHIVE["external"]()
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    payload = PAYLOAD.read_bytes().decode("ascii")
    import shlex
    for step in (("--inspect",) if mode == "--inspect" else ("--inspect", "--stage")):
        result = subprocess.run([*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(payload) + " " + step],
                                input=binary, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
        out = result.stdout.decode("ascii", "replace")
        print(out, end="")
        if result.returncode or "rejected" in out:
            raise ValueError("device stage step failed: " + step)
    if ARCHIVE["external"]() != before:
        raise ValueError("controller census changed")
    print("U2_V8_STAGE %s external=healthy" % ("inspected" if mode == "--inspect" else "staged"))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("--inspect", "--stage"):
            raise ValueError("fixed mode required")
        main(sys.argv[1])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("U2_V8_STAGE rejected (%s)" % error)
        raise SystemExit(1)
