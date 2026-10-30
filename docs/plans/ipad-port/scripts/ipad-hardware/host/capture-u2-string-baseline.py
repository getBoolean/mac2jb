#!/usr/bin/env python3
"""Save private stock USB string values after verified physical recovery.

The old trial must already pass the read-only post-reboot recovery checker.
Only then does the Mac helper send bounded standard IN GET_DESCRIPTOR(STRING)
requests without USBDeviceOpen. This exclusively saves an owner-only Mac
baseline and manifest; it writes nothing on the iPad, never publishes a USB
description, and never clears the retained old-boot journal. No string values
or device identifiers are printed. A repeated run refuses existing files.
"""

import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
BASE = ROOT / "build/ipad-hardware/u2-baseline"
RECOVERY = HOST / "check-u2-postreboot-recovery.py"
PROBE = runpy.run_path(str(HOST / "probe-u2-readonly-string-descriptors.py"))
STRINGS = BASE / "string-descriptors.bin"
MANIFEST = BASE / "string-descriptors-manifest.json"
EXPECTED_RECOVERY = (
    b"U2_POSTREBOOT new-boot=yes live=original raw-configs=byte-equal "
    b"host-interfaces=equal usb-scalars=equal usbmux=one trust=valid "
    b"power=external usb-network-driver=absent old-journal=retained\n"
)


def recovered():
    result = subprocess.run(["/usr/bin/python3", str(RECOVERY)],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=70)
    if result.returncode != 0 or result.stdout != EXPECTED_RECOVERY:
        raise ValueError("post-reboot stock recovery unverified")


def exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short private baseline write")
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    if (stat.S_IMODE(BASE.stat().st_mode) != 0o700 or
            STRINGS.exists() or MANIFEST.exists()):
        raise ValueError("unsafe or existing string baseline")
    PROBE["pinned"](PROBE["SOURCE"], PROBE["SOURCE_SHA256"], 32 * 1024)
    PROBE["pinned"](PROBE["BINARY"], PROBE["BINARY_SHA256"], 1024 * 1024)
    recovered()
    PROBE["connection"]()
    PROBE["host_usb_ready"]()
    result = subprocess.run([str(PROBE["BINARY"]), "--strings"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=20)
    if result.returncode != 0 or len(result.stdout) > 32 * 1024:
        raise ValueError("USB string read unavailable")
    language, values = PROBE["strings"](result.stdout)
    PROBE["connection"]()
    PROBE["host_usb_ready"]()
    recovered()
    digest = hashlib.sha256(result.stdout).hexdigest()
    manifest = json.dumps({
        "version": 1,
        "strings_sha256": digest,
        "raw_config_sha256": "bffeea0b79d6c571b0164b2a2b84f8939148e45b51a63591cb0ad2bec15a599f",
        "helper_source_sha256": PROBE["SOURCE_SHA256"],
        "helper_binary_sha256": PROBE["BINARY_SHA256"],
        "recovery_check_sha256": hashlib.sha256(EXPECTED_RECOVERY).hexdigest(),
        "language": language,
        "string_count": len(values),
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    exclusive(STRINGS, result.stdout)
    exclusive(MANIFEST, manifest)
    directory = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print("U2_STRING_BASELINE stock-recovered=yes resolved-count=" +
          str(len(values)) + " sha256=" + digest + " journal=retained")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_STRING_BASELINE rejected")
        raise SystemExit(1)
