#!/usr/bin/env python3
"""Attest TrollStore-transformed U1 code without requiring Mac trust of its signer.

What this code does:
1. Pins the original strict archive parser and exact signed toolbox package.
2. Reuses the strict archive layout, ownership, mode, plist, and publication
   checks. For each installed Mach-O, compares every byte before its code
   signature with the packaged executable, allowing only TrollStore's three
   observed load-command size fields to change.
3. Validates the installed alternate SHA-256 CodeDirectory's page hashes,
   identifier, entitlement blob and special-slot hashes, including Info.plist
   and CodeResources. It records normalized evidence in private Mac storage.

TrollStore's CoreTrust bypass signature is not trusted by macOS codesign;
this validator makes no Mac trust-chain claim. It establishes installed code
and effective entitlement identity before the separately controlled launch.
No iPad command or write occurs in this Mac-local validator.
"""

import hashlib
import importlib.util
import math
from pathlib import Path
import plistlib
import struct
import sys
import zipfile


ROOT = Path("/Volumes/WD_SN770_1T/dev/GitHub/mac2jb")
BASE_PATH = ROOT / "scripts/ipad-hardware/validate-installed-toolbox-archive.py"
BASE_SHA = "f972938f0bd81228c63893325b35a81f1066f030f0b453832d93c0539bb56a72"
PACKAGE = ROOT / "build/ipad-hardware/mac2jb-u1-stdout-toolbox.tipa"
PACKAGE_SHA = "c97a5d9f60a67329b3b1946e478e95f1afc903d51a7cb7902d8dbdc9a4309f13"


def pinned_module():
    if hashlib.sha256(BASE_PATH.read_bytes()).hexdigest() != BASE_SHA:
        raise RuntimeError("strict archive parser changed")
    spec = importlib.util.spec_from_file_location("u1_strict_archive", BASE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("strict archive parser unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


base = pinned_module()
APP_NAME = base.APP_NAME
EXPECTED_FILES = base.EXPECTED_FILES
EXPECTED_DIRECTORY_METADATA = base.EXPECTED_DIRECTORY_METADATA
EXPECTED_INFO = base.EXPECTED_INFO
EXPECTED_CODE = base.EXPECTED_CODE
EXPECTED_CHILD_UID = base.EXPECTED_CHILD_UID
EXPECTED_CHILD_GID = base.EXPECTED_CHILD_GID
MAX_MEMBER_SIZE = base.MAX_MEMBER_SIZE
Rejection = base.Rejection


def require(ok, message):
    if not ok:
        raise Rejection(message)


def package_code():
    data = PACKAGE.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PACKAGE_SHA,
            "package artifact changed")
    with zipfile.ZipFile(PACKAGE) as archive:
        names = archive.namelist()
        expected = {"Payload/" + APP_NAME + "/" + name
                    for name in EXPECTED_FILES}
        require(set(names) == expected and len(names) == len(expected),
                "package file set changed")
        return {name: archive.read("Payload/" + APP_NAME + "/" + name)
                for name in EXPECTED_CODE}


def macho_prefix(data):
    require(len(data) >= 32 and data[:4] == b"\xcf\xfa\xed\xfe",
            "Mach-O header mismatch")
    ncmds, sizecmds = struct.unpack_from("<II", data, 16)
    require(0 < ncmds <= 256 and 0 < sizecmds <= 16384 and
            32 + sizecmds <= len(data), "Mach-O commands exceed bound")
    offset = 32
    linkedit = []
    signatures = []
    for _ in range(ncmds):
        require(offset + 8 <= 32 + sizecmds, "truncated load command")
        command, size = struct.unpack_from("<II", data, offset)
        require(size >= 8 and size % 8 == 0 and offset + size <= 32 + sizecmds,
                "invalid load command size")
        if command == 0x19 and data[offset + 8:offset + 24].rstrip(b"\0") == b"__LINKEDIT":
            require(size >= 72, "short LINKEDIT command")
            linkedit.append(offset)
        if command == 0x1D:
            require(size == 16, "invalid code-signature command")
            signatures.append(offset)
        offset += size
    require(offset == 32 + sizecmds and len(linkedit) == 1 and len(signatures) == 1,
            "ambiguous Mach-O commands")
    link, sign = linkedit[0], signatures[0]
    fileoff = struct.unpack_from("<Q", data, link + 40)[0]
    filesize = struct.unpack_from("<Q", data, link + 48)[0]
    vmsize = struct.unpack_from("<Q", data, link + 32)[0]
    dataoff, datasize = struct.unpack_from("<II", data, sign + 8)
    require(fileoff < dataoff and fileoff + filesize == len(data) and
            vmsize >= filesize and vmsize % 4096 == 0 and
            dataoff >= 32 + sizecmds and 0 < datasize <= 131072 and
            dataoff + datasize <= len(data) and
            len(data) - dataoff - datasize <= 15 and
            not any(data[dataoff + datasize:]),
            "invalid LINKEDIT or signature extent")
    prefix = bytearray(data[:dataoff])
    for position, count in ((link + 32, 8), (link + 48, 8), (sign + 12, 4)):
        prefix[position:position + count] = bytes(count)
    return bytes(prefix), dataoff, data[dataoff:dataoff + datasize]


def signed_metadata(binary, dataoff, signature, info, resources, main_executable):
    require(len(signature) >= 12 and
            struct.unpack_from(">I", signature)[0] == 0xFADE0CC0,
            "invalid signature superblob")
    length, count = struct.unpack_from(">II", signature, 4)
    require(length == len(signature) and 1 <= count <= 16 and
            12 + count * 8 <= length, "invalid signature index")
    blobs = {}
    for index in range(count):
        slot, offset = struct.unpack_from(">II", signature, 12 + index * 8)
        require(slot not in blobs and 12 + count * 8 <= offset <= length - 8,
                "duplicate or invalid signature slot")
        blob_length = struct.unpack_from(">I", signature, offset + 4)[0]
        require(8 <= blob_length <= length - offset, "invalid signature blob")
        blobs[slot] = signature[offset:offset + blob_length]
    require(4096 in blobs and 5 in blobs and 2 in blobs and 7 in blobs,
            "required signature slots missing")
    cd = blobs[4096]
    require(len(cd) >= 44 and struct.unpack_from(">I", cd)[0] == 0xFADE0C02,
            "missing alternate CodeDirectory")
    hashoff, identoff, special, code, limit = struct.unpack_from(">IIIII", cd, 16)
    hashsize, hashtype, _platform, pageshift = cd[36:40]
    require(hashsize == 32 and hashtype == 2 and pageshift == 12 and
            limit == dataoff and code == math.ceil(limit / 4096) and
            special >= 7 and 40 <= identoff < hashoff and
            hashoff >= special * 32 and hashoff + code * 32 <= len(cd),
            "alternate CodeDirectory layout mismatch")
    identifier = cd[identoff:hashoff].split(b"\0", 1)[0]
    require(identifier == b"dev.mac2jb.u1probe.toolbox",
            "installed code identifier mismatch")
    for page in range(code):
        expected = cd[hashoff + page * 32:hashoff + (page + 1) * 32]
        actual = hashlib.sha256(binary[page * 4096:min((page + 1) * 4096, limit)]).digest()
        require(actual == expected, "installed code page hash mismatch")
    for slot, payload in ((2, blobs[2]), (5, blobs[5]), (7, blobs[7])):
        expected = cd[hashoff - slot * 32:hashoff - (slot - 1) * 32]
        require(hashlib.sha256(payload).digest() == expected,
                "installed signature special-slot hash mismatch")
    for slot, payload in ((1, info), (3, resources)):
        expected = cd[hashoff - slot * 32:hashoff - (slot - 1) * 32]
        require((hashlib.sha256(payload).digest() == expected
                 if main_executable else expected == bytes(32)),
                "installed app-resource hash mismatch")
    entblob = blobs[5]
    require(struct.unpack_from(">I", entblob)[0] == 0xFADE7171,
            "invalid entitlement blob")
    try:
        entitlements = plistlib.loads(entblob[8:])
    except (ValueError, TypeError, plistlib.InvalidFileException) as error:
        raise Rejection("invalid installed entitlements") from error
    return identifier.decode("ascii"), entitlements, hashlib.sha256(cd).hexdigest()


def validate_reconstructed_app(app_path, _staging):
    info = (app_path / "Info.plist").read_bytes()
    resources = (app_path / "_CodeSignature/CodeResources").read_bytes()
    base.validate_info_plist(info)
    base.validate_code_resources(resources)
    originals = package_code()
    records = {}
    for relative, (_old_identifier, expected_entitlements) in EXPECTED_CODE.items():
        installed = (app_path / relative).read_bytes()
        original = originals[relative]
        reference_prefix, reference_off, _reference_signature = macho_prefix(original)
        installed_prefix, installed_off, installed_signature = macho_prefix(installed)
        require(reference_off == installed_off and
                reference_prefix == installed_prefix,
                "installed code differs outside TrollStore signature fields")
        identifier, entitlements, directory_sha = signed_metadata(
            installed, installed_off, installed_signature, info, resources,
            relative == "mac2jb-u1-baseline")
        require(base.exact_value(entitlements, expected_entitlements),
                "installed entitlement profile mismatch")
        records[relative] = {
            "identifier": identifier,
            "entitlements": entitlements,
            "codePrefixSha256": hashlib.sha256(installed_prefix).hexdigest(),
            "alternateCodeDirectorySha256": directory_sha,
        }
    return records


base.validate_reconstructed_app = validate_reconstructed_app


if __name__ == "__main__":
    raise SystemExit(base.run(sys.argv[1:]))
