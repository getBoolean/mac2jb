#!/usr/bin/env python3
"""Attest one installed SpringBoard R2 bundle before any launch.

This Mac-only validator requires the exact three-file installed app layout,
expected TrollStore Info.plist transformation, matching pre-signature code,
alternate SHA-256 CodeDirectory page/special-slot hashes, and exact ordinary
entitlements. It emits a small private manifest; it never contacts the iPad.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[5]
BUILD = ROOT / "build/ipad-hardware"
MAIN = "mac2jb-u1-springboard-r2"
PROFILES = {
    "baseline": (
        "Mac2JBU1-R2Baseline.app", b"dev.mac2jb.u1probe.r2baseline",
        "MAC2JBU1R2Baseline", "565ad2fd8b4d90130fd29e562ad446911a5364be67f7c8e1b3547b43b8f06c1a",
    ),
    "setdescription": (
        "Mac2JBU1-R2SetDescription.app", b"dev.mac2jb.u1probe.r2setdescription",
        "MAC2JBU1R2SetDescription", "0424a37259f8c873d474dcd1965ccdcc386f0d39814f408869432f2aa235d65d",
    ),
}
BASE_PATH = ROOT / "scripts/ipad-hardware/validate-installed-toolbox-archive.py"
BASE_SHA = "f972938f0bd81228c63893325b35a81f1066f030f0b453832d93c0539bb56a72"
TROLL_PATH = ROOT / "scripts/ipad-hardware/validate-installed-toolbox-trollstore.py"
TROLL_SHA = "4b82e513f5573c01867ef2747fac540583a1ca48ccb15880583595b06fd882f0"
ORDINARY_PATH = ROOT / "scripts/ipad-hardware/validate-installed-ordinary-admission.py"
ORDINARY_SHA = "dd6cf2507e224f3b12b17af6d3cf985a5d9b0a052d53f78ee90caaa9dee13906"


def require(value, message):
    if not value:
        raise ValueError(message)


def pinned(path, expected, name):
    require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
            name + " source changed")
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, name + " unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run(profile, check=False):
    app_name, app_id, bundle_name, package_sha = PROFILES[profile]
    archive_path = BUILD / ("installed-springboard-r2-" + profile + "-archive.tar")
    package_path = BUILD / ("mac2jb-u1-springboard-r2-" + profile + ".tipa")
    manifest_path = BUILD / ("installed-springboard-r2-" + profile + "-attestation.json")
    if not check and (manifest_path.exists() or manifest_path.is_symlink()):
        raise ValueError("manifest already exists")
    base = pinned(BASE_PATH, BASE_SHA, "u1_marker_base")
    troll = pinned(TROLL_PATH, TROLL_SHA, "u1_marker_trollstore")
    ordinary = pinned(ORDINARY_PATH, ORDINARY_SHA, "u1_marker_signature")
    ordinary.APP_ID = app_id
    base.APP_NAME = app_name
    base.EXPECTED_DIRECTORY_METADATA = {
        "": (0o755, 0, 0),
        "_CodeSignature": (0o755, base.EXPECTED_CHILD_UID, base.EXPECTED_CHILD_GID),
    }
    base.EXPECTED_FILES = {
        "Info.plist": 0o644,
        MAIN: 0o755,
        "_CodeSignature/CodeResources": 0o644,
    }
    base.EXPECTED_INFO = {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleDisplayName": "MAC2JB U1 R2 " + profile,
        "CFBundleExecutable": MAIN,
        "CFBundleIdentifier": app_id.decode(),
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": bundle_name,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "0.1.0",
        "CFBundleSupportedPlatforms": ["iPhoneOS"],
        "CFBundleVersion": "1",
        "LSRequiresIPhoneOS": True,
        "MinimumOSVersion": "17.0",
        "SBAppUsesLocalNotifications": 1,
        "UIDeviceFamily": [2],
        "UIRequiredDeviceCapabilities": ["arm64"],
    }
    require(hashlib.sha256(package_path.read_bytes()).hexdigest() == package_sha,
            "package digest mismatch")
    with zipfile.ZipFile(package_path) as package:
        names = package.namelist()
        expected = {"Payload/" + app_name + "/" + name
                    for name in base.EXPECTED_FILES}
        require(len(names) == len(expected) and set(names) == expected,
                "package member set mismatch")
        original = package.read("Payload/" + app_name + "/" + MAIN)
    archive = base.read_archive(archive_path)
    members, family = base.parse_archive(archive)
    info = members["Info.plist"].content
    resources = members["_CodeSignature/CodeResources"].content
    base.validate_info_plist(info)
    base.validate_code_resources(resources)
    installed = members[MAIN].content
    old_prefix, old_off, _ = troll.macho_prefix(original)
    new_prefix, new_off, signature = troll.macho_prefix(installed)
    require(old_off == new_off and old_prefix == new_prefix,
            "installed code changed outside signature-size fields")
    entitlements, cdhash = ordinary.signed_metadata(
        installed, new_off, signature, info, resources, True)
    expected_entitlements = {
        "application-identifier": "TROLLTROLL.*",
        "com.apple.developer.team-identifier": "TROLLTROLL",
        "get-task-allow": False,
        "keychain-access-groups": ["TROLLTROLL.*", "com.apple.token"],
        "com.apple.private.security.container-required": app_id.decode(),
    }
    if profile == "setdescription":
        expected_entitlements["com.apple.private.usbdevice.setdescription"] = True
    require(base.exact_value(entitlements, expected_entitlements),
            "installed entitlement mismatch")
    manifest = {
        "status": "installed-code-and-entitlements-matched",
        "sourceFamily": family,
        "archiveSha256": hashlib.sha256(archive).hexdigest(),
        "packageSha256": package_sha,
        "binarySha256": hashlib.sha256(installed).hexdigest(),
        "prefixSha256": hashlib.sha256(new_prefix).hexdigest(),
        "alternateCodeDirectorySha256": cdhash,
        "entitlements": sorted(entitlements),
    }
    data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if check:
        require(manifest_path.read_bytes() == data, "attestation manifest differs")
    else:
        fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(fd, data) != len(data):
                raise OSError("partial manifest")
            os.fsync(fd)
        finally:
            os.close(fd)
    print("SPRINGBOARD_R2_ATTEST profile=" + profile + " code=matched entitlements=matched layout=exact")


if __name__ == "__main__":
    try:
        if len(sys.argv) not in (2, 3) or sys.argv[1] not in PROFILES or (
                len(sys.argv) == 3 and sys.argv[2] != "--check"):
            raise ValueError("unexpected arguments")
        run(sys.argv[1], len(sys.argv) == 3)
    except Exception:
        print("SPRINGBOARD_R2_ATTEST rejected", file=sys.stderr)
        raise SystemExit(1)
