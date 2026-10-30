#!/usr/bin/env python3
"""Compare current USB descriptors to the recovered stock string baseline.

Requires the private owner-only string baseline captured after verified stock
recovery. Reads current Mac raw configuration descriptors nonexclusively,
then sends only bounded standard IN GET_DESCRIPTOR(STRING) requests without
USBDeviceOpen. It checks raw descriptors twice around the string requests to
reject an unstable observation. It prints no string/device values, writes no
file, runs no iPad script, and never confirms or clears a restore journal.
This proves only descriptor/string semantics, not host driver or pairing
restoration; the full U2 external checker remains a separate requirement.
"""

import hashlib
import json
from pathlib import Path
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
BASE = ROOT / "build/ipad-hardware/u2-baseline"
PROBE = runpy.run_path(str(HOST / "probe-u2-readonly-string-descriptors.py"))
SEMANTICS = runpy.run_path(str(HOST / "u2-string-semantics.py"))
RAW = runpy.run_path(str(HOST / "capture-u2-raw-configs.py"))
STRINGS = BASE / "string-descriptors.bin"
MANIFEST = BASE / "string-descriptors-manifest.json"
BASELINE_RAW_SHA256 = "bffeea0b79d6c571b0164b2a2b84f8939148e45b51a63591cb0ad2bec15a599f"
RECOVERY_LINE = runpy.run_path(str(HOST / "capture-u2-string-baseline.py"))["EXPECTED_RECOVERY"]


def private(path, maximum):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) != 0o600 or
            not 0 < info.st_size <= maximum):
        raise ValueError("unsafe private string baseline")
    return path.read_bytes()


def baseline():
    if stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError("unsafe baseline directory")
    manifest = json.loads(private(MANIFEST, 4096))
    required = {"version", "strings_sha256", "raw_config_sha256",
                "helper_source_sha256", "helper_binary_sha256",
                "recovery_check_sha256", "language", "string_count"}
    if (set(manifest) != required or manifest["version"] != 1 or
            manifest["raw_config_sha256"] != BASELINE_RAW_SHA256 or
            manifest["helper_source_sha256"] != PROBE["SOURCE_SHA256"] or
            manifest["helper_binary_sha256"] != PROBE["BINARY_SHA256"] or
            manifest["recovery_check_sha256"] !=
            hashlib.sha256(RECOVERY_LINE).hexdigest()):
        raise ValueError("string baseline manifest mismatch")
    saved = private(STRINGS, 32 * 1024)
    if hashlib.sha256(saved).hexdigest() != manifest["strings_sha256"]:
        raise ValueError("string baseline digest mismatch")
    language, values = PROBE["strings"](saved)
    if language != manifest["language"] or len(values) != manifest["string_count"]:
        raise ValueError("string baseline count mismatch")
    raw = private(BASE / "raw-configs.bin", 128 * 1024)
    if hashlib.sha256(raw).hexdigest() != BASELINE_RAW_SHA256:
        raise ValueError("raw baseline digest mismatch")
    return raw, saved


def main():
    before_raw, before_strings = baseline()  # Missing baseline stops before USB.
    PROBE["pinned"](PROBE["SOURCE"], PROBE["SOURCE_SHA256"], 32 * 1024)
    PROBE["pinned"](PROBE["BINARY"], PROBE["BINARY_SHA256"], 1024 * 1024)
    PROBE["connection"]()
    PROBE["host_usb_ready"]()
    current_raw = RAW["capture"]()[0]
    result = subprocess.run([str(PROBE["BINARY"]), "--strings"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=20)
    if result.returncode != 0 or len(result.stdout) > 32 * 1024:
        raise ValueError("current USB string read unavailable")
    PROBE["strings"](result.stdout)
    if RAW["capture"]()[0] != current_raw:
        raise ValueError("raw descriptors changed during string capture")
    PROBE["connection"]()
    PROBE["host_usb_ready"]()
    comparison = SEMANTICS["compare"](
        before_raw, before_strings, current_raw, result.stdout)
    print("U2_RESOLVED_STRINGS semantics=equal configurations=" +
          str(comparison["configurations"]) + " references=" +
          str(comparison["resolved_references"]) + " renumbered=" +
          str(comparison["renumbered_references"]) +
          " connection=healthy")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_RESOLVED_STRINGS rejected")
        raise SystemExit(1)
