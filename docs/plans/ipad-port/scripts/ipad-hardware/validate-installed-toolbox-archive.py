#!/usr/bin/env python3
"""Attest an installed U1 toolbox archive before any bundled code is run.

The validator treats the streamed bundle as hostile input. It accepts only the
reviewed six-file app layout, exact TrollStore-adjusted metadata, mobile-owned
modes, valid nested code signatures, exact identifiers and entitlements, and
the reviewed signature-stripped Mach-O bytes. Evidence is published locally
with a Darwin no-replace rename only after every check succeeds.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import resource
import shutil
import signal
import stat
import struct
import subprocess
import sys


MAX_ARCHIVE_SIZE = 16 * 1024 * 1024
MAX_MEMBER_SIZE = 4 * 1024 * 1024
MAX_PLIST_SIZE = 256 * 1024
EXPECTED_CHILD_UID = 33
EXPECTED_CHILD_GID = 33
APP_NAME = "Mac2JBU1-Toolbox.app"
EXPECTED_CODE_HASH = "02d1977c74b492556c35ce8755d4d22bf72fc36dfba072e8623bbaadb17ce3d3"
CODESIGN = "/usr/bin/codesign"
RENAME_EXCL = 0x00000004

EXPECTED_DIRECTORY_METADATA = {
    # TrollStore's root helper copies the app as root, then its directory
    # enumerator chowns only descendants to 33:33. The app root is not yielded.
    "": (0o755, 0, 0),
    "Probes": (0o755, EXPECTED_CHILD_UID, EXPECTED_CHILD_GID),
    "_CodeSignature": (0o755, EXPECTED_CHILD_UID, EXPECTED_CHILD_GID),
}
EXPECTED_FILES = {
    "Info.plist": 0o644,
    "mac2jb-u1-baseline": 0o755,
    "Probes/mac2jb-u1-setdescription": 0o755,
    "Probes/mac2jb-u1-controller-client": 0o755,
    "Probes/mac2jb-u1-interface-client": 0o755,
    "_CodeSignature/CodeResources": 0o644,
}
EXPECTED_INFO = {
    "CFBundleDevelopmentRegion": "en",
    "CFBundleDisplayName": "MAC2JB U1 toolbox",
    "CFBundleExecutable": "mac2jb-u1-baseline",
    "CFBundleIdentifier": "dev.mac2jb.u1probe.toolbox",
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "MAC2JBU1Probe",
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
EXPECTED_CODE = {
    "mac2jb-u1-baseline": (
        "dev.mac2jb.u1probe.toolbox",
        {
            "com.apple.private.security.container-required": "dev.mac2jb.u1probe.toolbox",
            "get-task-allow": False,
        },
    ),
    "Probes/mac2jb-u1-setdescription": (
        "dev.mac2jb.u1probe.toolbox.setdescription",
        {"com.apple.private.usbdevice.setdescription": True},
    ),
    "Probes/mac2jb-u1-controller-client": (
        "dev.mac2jb.u1probe.toolbox.controller-client",
        {
            "com.apple.security.exception.iokit-user-client-class": [
                "IOUSBDeviceControllerUserClient"
            ],
            "platform-application": True,
        },
    ),
    "Probes/mac2jb-u1-interface-client": (
        "dev.mac2jb.u1probe.toolbox.interface-client",
        {
            "com.apple.security.exception.iokit-user-client-class": [
                "IOUSBDeviceInterfaceUserClient"
            ],
            "platform-application": True,
        },
    ),
}
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


class Rejection(Exception):
    """An input or local publication invariant was not satisfied."""


class Interrupted(Exception):
    """A handled termination signal interrupted validation."""


class RejectingDict(dict):
    def __setitem__(self, key: object, value: object) -> None:
        if key in self:
            raise Rejection("duplicate plist key")
        super().__setitem__(key, value)


@dataclass(frozen=True)
class Member:
    content: bytes
    mode: int
    uid: int
    gid: int


def octal_value(field: bytes) -> int:
    stripped = field.strip(b"\0 ")
    if not stripped or any(byte < 48 or byte > 55 for byte in stripped):
        raise Rejection("invalid octal field")
    return int(stripped, 8)


def text_field(field: bytes) -> str:
    nul = field.find(0)
    if nul >= 0:
        if any(field[nul:]):
            raise Rejection("nonzero field padding")
        field = field[:nul]
    try:
        return field.decode("ascii")
    except UnicodeDecodeError as error:
        raise Rejection("non-ASCII archive path") from error


def classify_root(root: str) -> str:
    parts = PurePosixPath(root).parts
    if len(parts) == 6 and parts[:4] == ("var", "containers", "Bundle", "Application"):
        identifier = parts[4]
        groups = identifier.split("-")
        widths = [8, 4, 4, 4, 12]
        if (
            parts[5] != APP_NAME
            or len(groups) != len(widths)
            or any(len(group) != width for group, width in zip(groups, widths))
            or any(character not in "0123456789abcdefABCDEF" for group in groups for character in group)
        ):
            raise Rejection("invalid container app root")
        return "container"
    if parts == ("Applications", APP_NAME):
        return "system"
    if parts == ("var", "jb", "Applications", APP_NAME):
        return "rootless"
    raise Rejection("unexpected app root")


def split_member(name: str) -> tuple[str, str, str]:
    if name.endswith("/"):
        name = name[:-1]
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or name != path.as_posix()
        or any(part in ("", ".", "..") for part in path.parts)
        or path.parts.count(APP_NAME) != 1
    ):
        raise Rejection("non-canonical member path")
    index = path.parts.index(APP_NAME)
    root = PurePosixPath(*path.parts[: index + 1]).as_posix()
    relative_path = PurePosixPath(*path.parts[index + 1 :])
    relative = "" if relative_path.as_posix() == "." else relative_path.as_posix()
    return root, relative, classify_root(root)


def read_archive(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise Rejection("archive is not a single-link regular file")
        if status.st_size < 1024 or status.st_size > MAX_ARCHIVE_SIZE or status.st_size % 512:
            raise Rejection("archive size is invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARCHIVE_SIZE:
                raise Rejection("archive exceeded size cap")
            chunks.append(chunk)
        data = b"".join(chunks)
        if len(data) != status.st_size:
            raise Rejection("archive changed during read")
        return data
    finally:
        os.close(descriptor)


def parse_archive(data: bytes) -> tuple[dict[str, Member], str]:
    zero = bytes(512)
    position = 0
    root: str | None = None
    source_family: str | None = None
    directories: set[str] = set()
    files: dict[str, Member] = {}
    seen: set[str] = set()

    while True:
        if position + 1024 > len(data):
            raise Rejection("archive has no terminal zero blocks")
        header = data[position : position + 512]
        if header == zero:
            if data[position + 512 : position + 1024] != zero:
                raise Rejection("archive has only one terminal zero block")
            if any(data[position + 1024 :]):
                raise Rejection("archive has trailing content")
            break
        if header[257:263] != b"ustar\0" or header[263:265] != b"00" or any(header[500:512]):
            raise Rejection("archive is not strict ustar")
        stored_checksum = octal_value(header[148:156])
        computed_checksum = sum(header[:148]) + 8 * 32 + sum(header[156:])
        if stored_checksum != computed_checksum:
            raise Rejection("archive checksum mismatch")
        member_type = header[156:157]
        if member_type not in (b"\0", b"0", b"5") or text_field(header[157:257]):
            raise Rejection("archive contains a non-file member")
        member_size = octal_value(header[124:136])
        mode = octal_value(header[100:108])
        uid = octal_value(header[108:116])
        gid = octal_value(header[116:124])
        name = text_field(header[0:100])
        prefix = text_field(header[345:500])
        if prefix:
            name = f"{prefix}/{name}"
        member_root, relative, family = split_member(name)
        canonical = f"{member_root}/{relative}" if relative else member_root
        if canonical in seen:
            raise Rejection("duplicate archive member")
        seen.add(canonical)
        if root is None:
            root, source_family = member_root, family
        elif member_root != root or family != source_family:
            raise Rejection("archive mixes app roots")
        data_start = position + 512
        data_end = data_start + member_size
        padded_end = data_start + ((member_size + 511) // 512 * 512)
        if padded_end > len(data) or any(data[data_end:padded_end]):
            raise Rejection("archive member extent is invalid")

        if member_type == b"5":
            if (
                member_size != 0
                or EXPECTED_DIRECTORY_METADATA.get(relative) != (mode, uid, gid)
            ):
                raise Rejection("unexpected directory metadata")
            directories.add(relative)
        else:
            if (
                relative not in EXPECTED_FILES
                or not 0 < member_size <= MAX_MEMBER_SIZE
                or EXPECTED_FILES[relative] != mode
                or uid != EXPECTED_CHILD_UID
                or gid != EXPECTED_CHILD_GID
            ):
                raise Rejection("unexpected regular-file metadata")
            files[relative] = Member(data[data_start:data_end], mode, uid, gid)
        position = padded_end

    if root is None or source_family is None:
        raise Rejection("archive contains no app")
    if directories != set(EXPECTED_DIRECTORY_METADATA) or set(files) != set(EXPECTED_FILES):
        raise Rejection("archive file set is incomplete")
    return files, source_family


def prevalidate_binary_plist(content: bytes) -> None:
    """Reject malformed, cyclic, hidden, or resource-amplifying bplist graphs."""
    if not content.startswith(b"bplist00"):
        return
    if len(content) < 40:
        raise Rejection("truncated binary plist")
    offset_size, reference_size, object_count, top_object, offset_table = struct.unpack(
        ">6xBBQQQ", content[-32:]
    )
    if offset_size not in (1, 2, 4, 8) or reference_size not in (1, 2, 4, 8):
        raise Rejection("invalid binary plist integer width")
    if not 0 < object_count <= 65536 or top_object >= object_count:
        raise Rejection("invalid binary plist object count")
    table_size = object_count * offset_size
    if offset_table < 8 or offset_table + table_size != len(content) - 32:
        raise Rejection("invalid binary plist offset table")
    offsets = [
        int.from_bytes(content[position : position + offset_size], "big")
        for position in range(offset_table, offset_table + table_size, offset_size)
    ]
    if len(set(offsets)) != object_count or any(
        value < 8 or value >= offset_table for value in offsets
    ):
        raise Rejection("invalid binary plist object offsets")
    references: dict[int, list[int]] = {index: [] for index in range(object_count)}
    extents: list[tuple[int, int]] = []
    reference_count = 0

    def sized_count(offset: int, token_low: int) -> tuple[int, int]:
        cursor = offset + 1
        if token_low < 15:
            return token_low, cursor
        if cursor >= offset_table:
            raise Rejection("truncated binary plist count")
        marker = content[cursor]
        marker_high, marker_low = marker & 0xF0, marker & 0x0F
        if marker_high != 0x10 or marker_low > 3:
            raise Rejection("invalid binary plist count marker")
        width = 1 << marker_low
        end = cursor + 1 + width
        if end > offset_table:
            raise Rejection("truncated binary plist count")
        return int.from_bytes(content[cursor + 1 : end], "big"), end

    for object_index, offset in enumerate(offsets):
        token = content[offset]
        token_high, token_low = token & 0xF0, token & 0x0F
        cursor = offset + 1
        if token in (0x00, 0x08, 0x09, 0x0F):
            end = cursor
        elif token_high == 0x10:
            if token_low > 3:
                raise Rejection("oversized binary plist integer")
            end = cursor + (1 << token_low)
        elif token == 0x22:
            end = cursor + 4
        elif token in (0x23, 0x33):
            end = cursor + 8
        elif token_high in (0x40, 0x50, 0x60, 0xA0, 0xD0):
            count, cursor = sized_count(offset, token_low)
            if count > 1048576:
                raise Rejection("oversized binary plist object")
            if token_high in (0x40, 0x50):
                end = cursor + count
            elif token_high == 0x60:
                end = cursor + (count * 2)
            else:
                multiplier = 2 if token_high == 0xD0 else 1
                end = cursor + (count * reference_size * multiplier)
                if end > offset_table:
                    raise Rejection("truncated binary plist references")
                object_references = [
                    int.from_bytes(content[position : position + reference_size], "big")
                    for position in range(cursor, end, reference_size)
                ]
                if any(reference >= object_count for reference in object_references):
                    raise Rejection("invalid binary plist reference")
                references[object_index] = object_references
                reference_count += len(object_references)
                if reference_count > 131072:
                    raise Rejection("oversized binary plist reference graph")
        elif token_high == 0x80:
            end = cursor + token_low + 1
        else:
            raise Rejection("unsupported binary plist object")
        if end > offset_table:
            raise Rejection("binary plist object exceeds object table")
        extents.append((offset, end))

    ordered_extents = sorted(extents)
    if ordered_extents[0][0] != 8 or ordered_extents[-1][1] != offset_table:
        raise Rejection("binary plist object table has hidden bytes")
    for (_start, end), (next_start, _next_end) in zip(
        ordered_extents, ordered_extents[1:]
    ):
        if end != next_start:
            raise Rejection("binary plist objects overlap or have gaps")

    visiting: set[int] = set()
    visited: set[int] = set()

    def visit(reference: int, depth: int) -> None:
        if depth > 128 or reference in visiting:
            raise Rejection("invalid binary plist graph")
        if reference in visited:
            return
        visiting.add(reference)
        for child in references[reference]:
            visit(child, depth + 1)
        visiting.remove(reference)
        visited.add(reference)

    visit(top_object, 0)
    if len(visited) != object_count:
        raise Rejection("binary plist contains unreachable objects")


def load_plist(content: bytes) -> object:
    if not 0 < len(content) <= MAX_PLIST_SIZE:
        raise Rejection("plist size is invalid")
    if not (content.startswith(b"bplist00") or content.lstrip().startswith(b"<?xml")):
        raise Rejection("plist encoding is unsupported")
    prevalidate_binary_plist(content)
    try:
        return plistlib.loads(content, dict_type=RejectingDict)
    except Rejection:
        raise
    except Exception as error:
        raise Rejection("plist decode failed") from error


def exact_value(actual: object, expected: object) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and set(actual) == set(expected) and all(
            exact_value(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(
            exact_value(left, right) for left, right in zip(actual, expected)
        )
    if type(actual) is not type(expected):
        return False
    return actual == expected


def validate_info_plist(content: bytes) -> None:
    value = load_plist(content)
    if not exact_value(value, EXPECTED_INFO):
        raise Rejection("Info.plist does not match the reviewed installed shape")


def validate_code_resources(content: bytes) -> None:
    value = load_plist(content)
    if not isinstance(value, dict) or not value:
        raise Rejection("CodeResources is not a nonempty plist dictionary")


def run_tool(arguments: list[str], timeout: float = 8.0) -> tuple[bytes, bytes]:
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait()
        raise
    if process.returncode != 0 or len(stdout) > MAX_MEMBER_SIZE or len(stderr) > MAX_MEMBER_SIZE:
        raise Rejection("local code-signature tool rejected evidence")
    return stdout, stderr


def code_identifier(path: Path) -> str:
    _stdout, stderr = run_tool([CODESIGN, "--display", "--verbose=4", str(path)])
    identifiers = [
        line.removeprefix(b"Identifier=").decode("ascii", "strict")
        for line in stderr.splitlines()
        if line.startswith(b"Identifier=")
    ]
    if len(identifiers) != 1:
        raise Rejection("code identifier is absent or ambiguous")
    return identifiers[0]


def code_entitlements(path: Path) -> object:
    stdout, _stderr = run_tool(
        [CODESIGN, "--display", "--entitlements", "-", "--xml", str(path)]
    )
    return load_plist(stdout)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def write_file(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("short local evidence write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_reconstructed_app(app_path: Path, staging: Path) -> dict[str, dict[str, object]]:
    validate_info_plist((app_path / "Info.plist").read_bytes())
    validate_code_resources((app_path / "_CodeSignature/CodeResources").read_bytes())
    for relative in EXPECTED_CODE:
        binary = app_path / relative
        descriptor = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if os.read(descriptor, 4) not in MACHO_MAGICS:
                raise Rejection("reviewed executable is not a Mach-O image")
        finally:
            os.close(descriptor)

    run_tool([CODESIGN, "--verify", "--deep", "--strict", "--all-architectures", str(app_path)])

    code_records: dict[str, dict[str, object]] = {}
    for index, (relative, (expected_identifier, expected_entitlements)) in enumerate(
        EXPECTED_CODE.items()
    ):
        binary = app_path / relative
        run_tool(
            [
                CODESIGN,
                "--verify",
                "--strict",
                "--all-architectures",
                str(binary),
            ]
        )
        identifier = code_identifier(binary)
        entitlements = code_entitlements(binary)
        if identifier != expected_identifier:
            raise Rejection("code identifier mismatch")
        if not exact_value(entitlements, expected_entitlements):
            raise Rejection("effective entitlement profile mismatch")

        stripped = staging / f".signature-stripped-{index}"
        write_file(stripped, binary.read_bytes())
        try:
            run_tool([CODESIGN, "--remove-signature", str(stripped)])
            stripped_hash = sha256_file(stripped)
        finally:
            try:
                stripped.unlink()
            except FileNotFoundError:
                pass
        if stripped_hash != EXPECTED_CODE_HASH:
            raise Rejection("signature-stripped code differs from the reviewed build")
        code_records[relative] = {
            "identifier": identifier,
            "entitlements": entitlements,
            "signatureStrippedSha256": stripped_hash,
        }
    return code_records


def entry_exists(name: str, parent_descriptor: int) -> bool:
    try:
        os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def remove_owned_staging(staging: Path, device: int, inode: int) -> None:
    try:
        status = os.lstat(staging)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(status.st_mode) and status.st_dev == device and status.st_ino == inode:
        shutil.rmtree(staging)


def rename_exclusive(
    parent_descriptor: int,
    staging_name: str,
    output_name: str,
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    try:
        function = library.renameatx_np
    except AttributeError as error:
        raise Rejection("Darwin no-replace rename is unavailable") from error
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    result = function(
        parent_descriptor,
        os.fsencode(staging_name),
        parent_descriptor,
        os.fsencode(output_name),
        RENAME_EXCL,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def preserve_evidence(
    output: Path,
    archive_data: bytes,
    members: dict[str, Member],
    source_family: str,
) -> None:
    if not output.is_absolute() or output.name in ("", ".", ".."):
        raise Rejection("output must be an absolute directory path")
    parent = output.parent
    parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    staging_name = f".{output.name}.staging"
    staging = parent / staging_name
    staging_device = -1
    staging_inode = -1
    published = False
    try:
        if entry_exists(output.name, parent_descriptor) or entry_exists(
            staging_name, parent_descriptor
        ):
            raise Rejection("output or fixed staging directory already exists")
        os.mkdir(staging_name, 0o700, dir_fd=parent_descriptor)
        staging_status = os.stat(staging_name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(staging_status.st_mode):
            raise Rejection("fixed staging path is not a directory")
        staging_device, staging_inode = staging_status.st_dev, staging_status.st_ino

        app_path = staging / APP_NAME
        app_path.mkdir(mode=0o700)
        (app_path / "Probes").mkdir(mode=0o700)
        (app_path / "_CodeSignature").mkdir(mode=0o700)
        for relative, member in members.items():
            write_file(app_path / relative, member.content)

        code_records = validate_reconstructed_app(app_path, staging)
        manifest_members = {
            relative: {
                "gid": member.gid,
                "mode": f"{member.mode:04o}",
                "sha256": hashlib.sha256(member.content).hexdigest(),
                "size": len(member.content),
                "uid": member.uid,
            }
            for relative, member in sorted(members.items())
        }
        manifest = {
            "appDirectory": APP_NAME,
            "archiveSha256": hashlib.sha256(archive_data).hexdigest(),
            "bundleIdentifier": EXPECTED_INFO["CFBundleIdentifier"],
            "code": code_records,
            "directories": {
                relative or ".": {
                    "gid": gid,
                    "mode": f"{mode:04o}",
                    "uid": uid,
                }
                for relative, (mode, uid, gid) in EXPECTED_DIRECTORY_METADATA.items()
            },
            "files": manifest_members,
            "schemaVersion": 2,
            "sourceFamily": source_family,
        }
        manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("ascii")
        write_file(staging / "attestation-manifest.json", manifest_data)

        fsync_directory(app_path / "Probes")
        fsync_directory(app_path / "_CodeSignature")
        fsync_directory(app_path)
        fsync_directory(staging)
        os.fsync(parent_descriptor)
        rename_exclusive(parent_descriptor, staging_name, output.name)
        published = True
        os.fsync(parent_descriptor)
    finally:
        if not published and staging_device >= 0:
            remove_owned_staging(staging, staging_device, staging_inode)
            os.fsync(parent_descriptor)
        os.close(parent_descriptor)


received_signal = 0


def handle_signal(signum: int, _frame: object) -> None:
    global received_signal
    received_signal = signum
    raise Interrupted()


def apply_resource_limits() -> None:
    for limit_name, desired in ((resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CPU, 20)):
        soft, hard = resource.getrlimit(limit_name)
        target = desired if hard == resource.RLIM_INFINITY else min(desired, hard)
        if soft == resource.RLIM_INFINITY or soft > target:
            resource.setrlimit(limit_name, (target, hard))


def run(arguments: list[str]) -> int:
    if len(arguments) != 2:
        print(
            "Usage: validate-installed-toolbox-archive.py ARCHIVE OUTPUT_DIRECTORY",
            file=sys.stderr,
        )
        return 64
    for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(handled_signal, handle_signal)
    try:
        apply_resource_limits()
        archive_data = read_archive(Path(arguments[0]))
        members, source_family = parse_archive(archive_data)
        preserve_evidence(Path(arguments[1]), archive_data, members, source_family)
    except Interrupted:
        return 128 + received_signal
    except (OSError, Rejection, UnicodeError, ValueError, subprocess.SubprocessError):
        print("Installed toolbox attestation rejected; no evidence was accepted.", file=sys.stderr)
        return 65
    except Exception:
        print("Installed toolbox attestation failed locally; no evidence was accepted.", file=sys.stderr)
        return 70
    print(f"PASS installed toolbox attestation {hashlib.sha256(archive_data).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
