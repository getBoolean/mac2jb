#!/usr/bin/env python3
"""Compare installed U1 code and entitlement profiles without contacting iPad.

This reads the two private TrollStore-aware attestation manifests, checks that
the original and platform-added executable code prefixes match for baseline
and set-description pairs, and classifies exact entitlement-key differences.
It prints no identifiers or hashes. Runtime admission results remain separate
evidence; this host-only check makes no causal kernel-policy claim.
"""

import json
from pathlib import Path
import re


BUILD = Path(__file__).resolve().parents[6] / "build/ipad-hardware"
TOOLBOX = BUILD / "installed-toolbox-attestation/attestation-manifest.json"
ADMISSION = BUILD / "installed-admission-attestation.json"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def read(path):
    if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= 2 * 1024 * 1024:
        raise ValueError("unsafe private manifest")
    return json.loads(path.read_text())


def main():
    original = read(TOOLBOX)["code"]
    added = read(ADMISSION)["code"]
    pairs = (
        ("mac2jb-u1-baseline", "mac2jb-u1-platform-only"),
        ("Probes/mac2jb-u1-setdescription", "Probes/mac2jb-u1-platform-setdescription"),
    )
    for old_name, new_name in pairs:
        old = original[old_name]
        new = added[new_name]
        left, right = old["codePrefixSha256"], new["prefixSha256"]
        if not DIGEST.fullmatch(left) or left != right:
            raise ValueError("code prefix mismatch")
    baseline = original[pairs[0][0]]["entitlements"]
    platform = added[pairs[0][1]]["entitlements"]
    setdesc = original[pairs[1][0]]["entitlements"]
    platform_setdesc = added[pairs[1][1]]["entitlements"]
    if (not isinstance(platform, list) or not isinstance(platform_setdesc, list) or
            set(setdesc) != {"com.apple.private.usbdevice.setdescription"} or
            set(platform_setdesc) != {"com.apple.private.usbdevice.setdescription", "platform-application"} or
            setdesc["com.apple.private.usbdevice.setdescription"] is not True or
            len(platform_setdesc) != 2):
        raise ValueError("set-description entitlement drift")
    if (set(baseline) != {"com.apple.private.security.container-required", "get-task-allow"} or
            set(platform) != {"com.apple.private.security.container-required", "platform-application"} or
            baseline["get-task-allow"] is not False or
            len(platform) != 2):
        raise ValueError("baseline entitlement drift")
    print("ADMISSION_DIFFERENTIAL code-prefixes=equal setdescription-delta=platform baseline-delta=platform-plus-get-task-allow")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print("ADMISSION_DIFFERENTIAL rejected")
        raise SystemExit(1)
