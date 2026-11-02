#!/usr/bin/env python3
"""Read the broker journal phase and file SHA-256 over pinned root Wi-Fi SSH (read-only).

Effect: streams the hash-pinned device/u2-readonly-native-journal-state.py to
the device's Python as root and prints its one categorical line,
`U2_NATIVE_JOURNAL phase=<phase> sha256=<digest|none>`. No device write.
Usage: --native-journal (kept for callers of the former multi-mode reader).
"""

import hashlib
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-native-journal-state.py"
PAYLOAD_SHA256 = "471459fc3a266d4005448fbe5f257e889c4e5dbfc69c55ec45272d93c779ecd7"
RESULT = re.compile(
    rb"U2_NATIVE_JOURNAL phase=(?:absent|prepared|published|restoring|awaitingVerification|recoveryRequired|restored) "
    rb"sha256=(?:none|[0-9a-f]{64})\n\Z")


def main():
    if sys.argv[1:] != ["--native-journal"]:
        raise ValueError("usage: --native-journal")
    info = PAYLOAD.lstat()
    source = PAYLOAD.read_bytes()
    if not stat.S_ISREG(info.st_mode) or hashlib.sha256(source).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("payload digest changed")
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    result = subprocess.run([*ssh, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"], input=source,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode or not RESULT.fullmatch(result.stdout):
        raise ValueError("journal state unavailable")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("U2_NATIVE_JOURNAL rejected")
        raise SystemExit(1)
