#!/usr/bin/env python3
"""Lock the drift-free boot-session derivation across all four sites.

kern.boottime is a `struct timeval`. Wall-clock time-sync rewrites its
sub-second tv_usec field *without* a reboot. The broker and every helper that
re-derives the boot session must therefore digest only tv_sec - the first 8
bytes - so the session is stable within a boot and changes only across a real
reboot. A site that digests the whole value orphans the journal on the next
time-sync; a site that slices differently from the others can never match.

This test is offline and never contacts the iPad. It checks two things:

  1. Behaviour - digesting the first 8 bytes is invariant to tv_usec and
     sensitive to tv_sec, which is the property the fix exists to guarantee.
  2. Structure - each of the four derivation sites slices to 8 bytes and none
     still hashes the whole kern.boottime buffer, so a regression at any one
     site fails here instead of silently on the device.
"""

import hashlib
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
SWIFT = ROOT / "ios/watchdog/TargetUSBRestoreSnapshot.swift"


def timeval(sec, usec):
    # Darwin arm64 struct timeval: 8-byte tv_sec, 4-byte tv_usec, 4 pad.
    return struct.pack("<qII", sec, usec, 0)


def derive(buffer):
    return hashlib.sha256(buffer[:8]).hexdigest()


def check_behaviour():
    base = timeval(1793526959, 123456)
    drifted = timeval(1793526959, 987654)   # same boot, time-sync moved usec
    rebooted = timeval(1793530000, 123456)  # a later boot
    assert derive(base) == derive(drifted), "usec drift must not change the session"
    assert derive(base) != derive(rebooted), "a new tv_sec must change the session"
    # The whole-buffer hash - the bug - would have split base from drifted.
    assert (hashlib.sha256(base).hexdigest()
            != hashlib.sha256(drifted).hexdigest()), "fixture does not exercise drift"


def check_structure():
    # (path, slice-marker that must be present, whole-buffer pattern that must be gone)
    sites = [
        (DEVICE / "u2_target_snapshot.py",
         r"boot_time\[:8\]",
         r"sha256\(\s*_sysctl\(b[\"']kern\.boottime[\"']\)\s*\)"),
        (HOST / "diagnose-u2-recovery-stage.py",
         r"b\[:8\]",
         r"sha256\(\s*m\[['\"]_sysctl['\"]\]\(b'kern\.boottime'\)\s*\)"),
        (DEVICE / "u3-archive-old-boot-journal.py",
         r"buffer\.raw\[:8\]",
         r"buffer\.raw\[:length\.value\]"),
        (SWIFT,
         r"boot\.prefix\(8\)",
         r"digest\(boot\)"),
    ]
    for path, present, absent in sites:
        text = path.read_text(encoding="utf-8")
        assert re.search(present, text), "%s lost its 8-byte slice (%s)" % (path.name, present)
        assert not re.search(absent, text), "%s still hashes the whole buffer (%s)" % (path.name, absent)


def main():
    check_behaviour()
    check_structure()
    print("U2_BOOT_SESSION_DERIVATION ok tv_sec-only across 4 sites")


if __name__ == "__main__":
    main()
