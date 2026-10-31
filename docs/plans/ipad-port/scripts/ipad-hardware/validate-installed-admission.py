#!/usr/bin/env python3
"""Attest TrollStore-transformed admission code before either probe runs.

What this Mac-local code does: pin the strict U1 tar parser and signature
normalizer, accept only the exact new app layout and expected TrollStore
metadata, compare every pre-signature executable byte to the signed package
apart from its three signature-size fields, validate the installed alternate
SHA-256 CodeDirectory's page/special-slot hashes, and require the two exact
effective entitlement profiles. It publishes a small private categorical
manifest only after all checks pass. It never contacts or changes the iPad.
"""

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import plistlib
import struct
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[5]
BUILD = ROOT / "build/ipad-hardware"
ARCHIVE = BUILD / "installed-admission-archive.tar"
PACKAGE = BUILD / "mac2jb-u1-platform-admission.tipa"
MANIFEST = BUILD / "installed-admission-attestation.json"
BASE_PATH = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/validate-installed-toolbox-archive.py"
BASE_SHA = "f972938f0bd81228c63893325b35a81f1066f030f0b453832d93c0539bb56a72"
TROLL_PATH = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/validate-installed-toolbox-trollstore.py"
TROLL_SHA = "b25bfd33150151177aafff61351c5361ed93cbedb7fc40deb56e7364fed0715b"
PACKAGE_SHA = "e91aa892c3c1a80db00ae8884e8dbacb31fe9e03a3ac551c3f244c6ca975d85a"
APP_ID = b"dev.mac2jb.u1probe.admission"
APP_NAME = "Mac2JBU1-Admission.app"
MAIN = "mac2jb-u1-platform-only"
CHILD = "Probes/mac2jb-u1-platform-setdescription"


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


def signed_metadata(binary, dataoff, signature, info, resources, main):
    require(len(signature) >= 12 and struct.unpack_from(">I", signature)[0] == 0xFADE0CC0,
            "signature superblob mismatch")
    length, count = struct.unpack_from(">II", signature, 4)
    require(length == len(signature) and 1 <= count <= 16 and 12 + count * 8 <= length,
            "signature index mismatch")
    blobs = {}
    for index in range(count):
        slot, offset = struct.unpack_from(">II", signature, 12 + index * 8)
        require(slot not in blobs and 12 + count * 8 <= offset <= length - 8,
                "signature slot mismatch")
        blob_length = struct.unpack_from(">I", signature, offset + 4)[0]
        require(8 <= blob_length <= length - offset, "signature blob extent mismatch")
        blobs[slot] = signature[offset:offset + blob_length]
    require(all(slot in blobs for slot in (4096, 5, 2, 7)),
            "required signature slots missing")
    directory = blobs[4096]
    require(len(directory) >= 44 and struct.unpack_from(">I", directory)[0] == 0xFADE0C02,
            "alternate CodeDirectory missing")
    hashoff, identoff, special, code, limit = struct.unpack_from(">IIIII", directory, 16)
    hashsize, hashtype, _platform, pageshift = directory[36:40]
    require(hashsize == 32 and hashtype == 2 and pageshift == 12 and
            limit == dataoff and code == math.ceil(limit / 4096) and
            special >= 7 and 40 <= identoff < hashoff and
            hashoff >= special * 32 and hashoff + code * 32 <= len(directory),
            "alternate CodeDirectory layout mismatch")
    identifier = directory[identoff:hashoff].split(b"\0", 1)[0]
    require(identifier == APP_ID, "installed CodeDirectory identifier mismatch")
    for page in range(code):
        expected = directory[hashoff + page * 32:hashoff + (page + 1) * 32]
        actual = hashlib.sha256(binary[page * 4096:min((page + 1) * 4096, limit)]).digest()
        require(actual == expected, "installed code page hash mismatch")
    for slot in (2, 5, 7):
        expected = directory[hashoff - slot * 32:hashoff - (slot - 1) * 32]
        require(hashlib.sha256(blobs[slot]).digest() == expected,
                "installed signature special-slot hash mismatch")
    for slot, payload in ((1, info), (3, resources)):
        expected = directory[hashoff - slot * 32:hashoff - (slot - 1) * 32]
        require((hashlib.sha256(payload).digest() == expected
                 if main else expected == bytes(32)),
                "installed app resource hash mismatch")
    entitlement_blob = blobs[5]
    require(struct.unpack_from(">I", entitlement_blob)[0] == 0xFADE7171,
            "entitlement slot mismatch")
    return plistlib.loads(entitlement_blob[8:]), hashlib.sha256(directory).hexdigest()


def run(check=False):
    if not check and (MANIFEST.exists() or MANIFEST.is_symlink()):
        raise ValueError("manifest already exists")
    base = pinned(BASE_PATH, BASE_SHA, "u1_admission_base")
    troll = pinned(TROLL_PATH, TROLL_SHA, "u1_admission_trollstore")
    base.APP_NAME = APP_NAME
    base.EXPECTED_FILES = {
        "Info.plist": 0o644, MAIN: 0o755, CHILD: 0o755,
        "_CodeSignature/CodeResources": 0o644,
    }
    base.EXPECTED_INFO = {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleDisplayName": "MAC2JB U1 Admission",
        "CFBundleExecutable": MAIN,
        "CFBundleIdentifier": APP_ID.decode(),
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "MAC2JBU1Admission",
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
        originals = {name: package.read("Payload/" + APP_NAME + "/" + name)
                     for name in (MAIN, CHILD)}
    archive = base.read_archive(ARCHIVE)
    members, family = base.parse_archive(archive)
    info = members["Info.plist"].content
    resources = members["_CodeSignature/CodeResources"].content
    base.validate_info_plist(info)
    base.validate_code_resources(resources)
    expected_entitlements = {
        MAIN: {
            "platform-application": True,
            "com.apple.private.security.container-required": APP_ID.decode(),
        },
        CHILD: {
            "platform-application": True,
            "com.apple.private.usbdevice.setdescription": True,
        },
    }
    code = {}
    for name in (MAIN, CHILD):
        installed = members[name].content
        original = originals[name]
        old_prefix, old_off, _ = troll.macho_prefix(original)
        new_prefix, new_off, signature = troll.macho_prefix(installed)
        require(old_off == new_off and old_prefix == new_prefix,
                "installed code changed outside signature-size fields")
        entitlements, cdhash = signed_metadata(installed, new_off, signature,
                                                info, resources, name == MAIN)
        require(base.exact_value(entitlements, expected_entitlements[name]),
                "installed entitlement profile mismatch")
        code[name] = {
            "binarySha256": hashlib.sha256(installed).hexdigest(),
            "prefixSha256": hashlib.sha256(new_prefix).hexdigest(),
            "alternateCodeDirectorySha256": cdhash,
            "entitlements": sorted(entitlements),
        }
    manifest = {
        "status": "installed-code-and-entitlements-matched",
        "sourceFamily": family,
        "archiveSha256": hashlib.sha256(archive).hexdigest(),
        "packageSha256": PACKAGE_SHA,
        "code": code,
    }
    data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if check:
        require(MANIFEST.read_bytes() == data, "attestation manifest differs")
        print("ADMISSION_ATTEST code=matched entitlements=matched layout=exact")
        return
    fd = os.open(MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    print("ADMISSION_ATTEST code=matched entitlements=matched layout=exact")


if __name__ == "__main__":
    try:
        if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--check"):
            raise ValueError("unexpected arguments")
        run(len(sys.argv) == 2)
    except Exception as error:
        print("ADMISSION_ATTEST rejected:", str(error), file=sys.stderr)
        raise SystemExit(1)
