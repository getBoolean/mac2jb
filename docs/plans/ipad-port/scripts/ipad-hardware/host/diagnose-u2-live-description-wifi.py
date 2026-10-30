#!/usr/bin/env python3
"""Compare the current iPad live USB dictionary with private U2 originals.

Sends the fixed read-only description-copy payload over pinned root Wi-Fi SSH,
parses its private length-framed binary plists only in Mac memory, and prints
only equality and changed-key categories. It never prints identifiers or
description values, writes no file, opens no USB user client, and does not
alter the retained recovery journal.
"""

import base64
import hashlib
import json
from pathlib import Path
import plistlib
import runpy
import stat
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[6]
SOURCE = ROOT / "scripts/ipad-hardware/device/u1-readonly-controller-description-copy.py"
SOURCE_SHA256 = "b2470a242e1984b746bddf92cd15a1570766bdf6dd6fcbeadc3efb0c3b5f650a"
WIRELESS = ROOT / "scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
BASE = ROOT / "build/ipad-hardware/u2-baseline/current.json"
DEFAULT = ROOT / "build/ipad-hardware/controller-descriptions/default.bplist"
MAGIC = b"MAC2JB-U1-DESC\0"


def capture():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024:
        raise ValueError("unsafe source")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("source changed")
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=source, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20)
    output = result.stdout
    if result.returncode != 0 or len(output) > 1024 * 1024 or not output.startswith(MAGIC):
        raise ValueError("description stream unavailable")
    length_default, length_live = struct.unpack_from(">II", output, len(MAGIC))
    offset = len(MAGIC) + 8
    if (not 8 <= length_default <= 512 * 1024 or
            not 8 <= length_live <= 512 * 1024 or
            len(output) != offset + length_default + length_live):
        raise ValueError("description framing")
    default_bytes = output[offset:offset + length_default]
    live_bytes = output[offset + length_default:]
    if (not isinstance(plistlib.loads(default_bytes), dict) or
            not isinstance(plistlib.loads(live_bytes), dict)):
        raise ValueError("description type")
    return default_bytes, live_bytes


def main():
    default_bytes, live_bytes = capture()
    default = plistlib.loads(default_bytes)
    live = plistlib.loads(live_bytes)
    baseline = json.loads(BASE.read_bytes())
    original = plistlib.loads(base64.b64decode(
        baseline["snapshot"]["live_b64"], validate=True))
    saved_default = plistlib.loads(DEFAULT.read_bytes())
    if not all(isinstance(item, dict) for item in (default, live, original)):
        raise ValueError("description type")
    changed = sorted(key for key in original if key not in live or live[key] != original[key])
    extra = sorted(set(live) - set(original))
    print("U2_LIVE_DESCRIPTION default=" + ("equal" if default == saved_default else "changed") +
          " original-fields=" + ("equal" if not changed else "changed") +
          " original-count=" + str(len(original)) +
          " current-count=" + str(len(live)))
    print("U2_LIVE_DESCRIPTION changed-keys=" + (",".join(changed) if changed else "none") +
          " extra-keys=" + (",".join(extra) if extra else "none"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            plistlib.InvalidFileException, subprocess.TimeoutExpired):
        print("U2_LIVE_DESCRIPTION rejected")
        raise SystemExit(1)
