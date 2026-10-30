#!/usr/bin/env python3
"""Attest the installed SpringBoard marker bundle before any launch.

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
ARCHIVE = BUILD / "installed-springboard-marker-archive.tar"
PACKAGE = BUILD / "mac2jb-u1-springboard-marker.tipa"
MANIFEST = BUILD / "installed-springboard-marker-attestation.json"
APP_NAME = "Mac2JBU1-SpringBoardMarker.app"
APP_ID = b"dev.mac2jb.u1probe.springboardmarker"
MAIN = "mac2jb-u1-springboard-marker"
PACKAGE_SHA = "2f76c3dca4ea0b19fa352fc274f1bfd5b65a9fc74d39fcd70247e65852965c72"
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


def run(check=False):
    if not check and (MANIFEST.exists() or MANIFEST.is_symlink()):
        raise ValueError("manifest already exists")
    base = pinned(BASE_PATH, BASE_SHA, "u1_marker_base")
    troll = pinned(TROLL_PATH, TROLL_SHA, "u1_marker_trollstore")
    ordinary = pinned(ORDINARY_PATH, ORDINARY_SHA, "u1_marker_signature")
    ordinary.APP_ID = APP_ID
    base.APP_NAME = APP_NAME
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
        "CFBundleDisplayName": "MAC2JB U1 SpringBoard Marker",
        "CFBundleExecutable": MAIN,
        "CFBundleIdentifier": APP_ID.decode(),
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "MAC2JBU1SpringBoardMarker",
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
    require(hashlib.sha256(PACKAGE.read_bytes()).hexdigest() == PACKAGE_SHA,
            "package digest mismatch")
    with zipfile.ZipFile(PACKAGE) as package:
        names = package.namelist()
        expected = {"Payload/" + APP_NAME + "/" + name
                    for name in base.EXPECTED_FILES}
        require(len(names) == len(expected) and set(names) == expected,
                "package member set mismatch")
        original = package.read("Payload/" + APP_NAME + "/" + MAIN)
    archive = base.read_archive(ARCHIVE)
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
        "com.apple.private.security.container-required": APP_ID.decode(),
    }
    require(base.exact_value(entitlements, expected_entitlements),
            "installed entitlement mismatch")
    manifest = {
        "status": "installed-code-and-entitlements-matched",
        "sourceFamily": family,
        "archiveSha256": hashlib.sha256(archive).hexdigest(),
        "packageSha256": PACKAGE_SHA,
        "binarySha256": hashlib.sha256(installed).hexdigest(),
        "prefixSha256": hashlib.sha256(new_prefix).hexdigest(),
        "alternateCodeDirectorySha256": cdhash,
        "entitlements": sorted(entitlements),
    }
    data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if check:
        require(MANIFEST.read_bytes() == data, "attestation manifest differs")
    else:
        fd = os.open(MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(fd, data) != len(data):
                raise OSError("partial manifest")
            os.fsync(fd)
        finally:
            os.close(fd)
    print("MARKER_ATTEST code=matched entitlements=matched layout=exact")


if __name__ == "__main__":
    try:
        if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--check"):
            raise ValueError("unexpected arguments")
        run(len(sys.argv) == 2)
    except Exception:
        print("MARKER_ATTEST rejected", file=sys.stderr)
        raise SystemExit(1)
