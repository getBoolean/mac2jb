#!/usr/bin/env python3
"""Host-only hostile-input tests for installed-toolbox attestation."""

from __future__ import annotations

from io import BytesIO
import functools
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parents[6]
VALIDATOR = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/validate-installed-toolbox-archive.py"
UNSIGNED = ROOT / "build/ipad-hardware/mac2jb-ios-probe-stdout-unsigned"
PREFIX = (
    "var/containers/Bundle/Application/"
    "12345678-1234-1234-1234-123456789ABC/Mac2JBU1-Toolbox.app"
)
APP_NAME = "Mac2JBU1-Toolbox.app"
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
CODE_PROFILES = {
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
FILE_MODES = {
    "Info.plist": 0o644,
    **{relative: 0o755 for relative in CODE_PROFILES},
    "_CodeSignature/CodeResources": 0o644,
}


def checked(arguments: list[str]) -> None:
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", "replace"))


def sign(target: Path, identifier: str, entitlements: dict[str, object], root: Path) -> None:
    entitlement_path = root / f"entitlements-{target.name}.plist"
    entitlement_path.write_bytes(plistlib.dumps(entitlements, fmt=plistlib.FMT_XML))
    checked(
        [
            "/usr/bin/codesign",
            "--force",
            "--sign",
            "-",
            "--identifier",
            identifier,
            "--entitlements",
            str(entitlement_path),
            str(target),
        ]
    )
    entitlement_path.unlink()


def corrupt_code_directory_hash(path: Path) -> None:
    """Flip one signed code-slot hash while leaving code and metadata intact."""
    data = bytearray(path.read_bytes())
    if data[:4] != b"\xcf\xfa\xed\xfe":
        raise AssertionError("fixture is not the expected little-endian Mach-O 64 image")
    command_count = struct.unpack_from("<I", data, 16)[0]
    cursor = 32
    signature_offset = None
    signature_size = None
    for _index in range(command_count):
        command, command_size = struct.unpack_from("<II", data, cursor)
        if command_size < 8 or cursor + command_size > len(data):
            raise AssertionError("malformed fixture load command")
        if command == 0x1D:
            signature_offset, signature_size = struct.unpack_from("<II", data, cursor + 8)
            break
        cursor += command_size
    if signature_offset is None or signature_size is None:
        raise AssertionError("fixture has no embedded code signature")
    if signature_offset + signature_size > len(data):
        raise AssertionError("fixture code signature exceeds the file")
    magic, total_length, blob_count = struct.unpack_from(">III", data, signature_offset)
    if magic != 0xFADE0CC0 or total_length > signature_size:
        raise AssertionError("fixture signature is not an embedded superblob")
    code_directory = None
    for index in range(blob_count):
        _slot_type, relative_offset = struct.unpack_from(">II", data, signature_offset + 12 + index * 8)
        candidate = signature_offset + relative_offset
        if struct.unpack_from(">I", data, candidate)[0] == 0xFADE0C02:
            code_directory = candidate
            break
    if code_directory is None:
        raise AssertionError("fixture signature has no CodeDirectory")
    directory_length = struct.unpack_from(">I", data, code_directory + 4)[0]
    hash_offset = struct.unpack_from(">I", data, code_directory + 16)[0]
    code_slots = struct.unpack_from(">I", data, code_directory + 28)[0]
    hash_size = data[code_directory + 36]
    if (
        code_slots < 1
        or hash_size < 1
        or hash_offset + code_slots * hash_size > directory_length
    ):
        raise AssertionError("fixture CodeDirectory hash table is invalid")
    hash_position = code_directory + hash_offset + (code_slots - 1) * hash_size
    data[hash_position] ^= 0x01
    path.write_bytes(data)


def build_signed_app(root: Path, scenario: str = "valid") -> Path:
    if not UNSIGNED.is_file():
        raise AssertionError(
            "Missing reviewed stdout-only build; run collect-inventory.sh build-stdout-only first"
        )
    app = root / APP_NAME
    (app / "Probes").mkdir(parents=True)
    info = dict(EXPECTED_INFO)
    if scenario == "risky-info":
        info["LSSupportsOpeningDocumentsInPlace"] = True
    if scenario == "wrong-info-type":
        info["SBAppUsesLocalNotifications"] = True
    (app / "Info.plist").write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))

    for relative, (identifier, entitlements) in CODE_PROFILES.items():
        destination = app / relative
        source = Path("/bin/echo") if scenario == "wrong-code" and "interface" in relative else UNSIGNED
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
        actual_identifier = (
            "dev.mac2jb.u1probe.toolbox.wrong"
            if scenario == "wrong-identifier" and "setdescription" in relative
            else identifier
        )
        actual_entitlements = dict(entitlements)
        if scenario == "wrong-entitlement" and "controller-client" in relative:
            actual_entitlements["platform-application"] = False
        if relative != "mac2jb-u1-baseline":
            sign(destination, actual_identifier, actual_entitlements, root)

    baseline_identifier, baseline_entitlements = CODE_PROFILES["mac2jb-u1-baseline"]
    sign(app, baseline_identifier, baseline_entitlements, root)
    if scenario == "corrupt-inner-signature":
        corrupt_code_directory_hash(app / "Probes/mac2jb-u1-controller-client")
        # The outer app seal is valid for the corrupted bytes. The auxiliary's
        # own embedded signature is deliberately invalid and must be checked
        # separately rather than inferred from outer `--deep` verification.
        sign(app, baseline_identifier, baseline_entitlements, root)
    checked(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
    if scenario == "corrupt-inner-signature":
        direct = subprocess.run(
            [
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "--all-architectures",
                str(app / "Probes/mac2jb-u1-controller-client"),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        assert direct.returncode != 0, "inner-signature corruption did not invalidate code"
    return app


def bplist_huge_object_count() -> bytes:
    return b"bplist00" + struct.pack(">6xBBQQQ", 1, 1, 65537, 0, 8)


def bplist_overlapping_objects() -> bytes:
    objects = b"\x52ab"
    offsets = b"\x08\x09"
    return b"bplist00" + objects + offsets + struct.pack(">6xBBQQQ", 1, 1, 2, 0, 11)


def bplist_cycle() -> bytes:
    objects = b"\xa1\x00"
    return b"bplist00" + objects + b"\x08" + struct.pack(">6xBBQQQ", 1, 1, 1, 0, 10)


def bplist_excessive_depth() -> bytes:
    object_count = 130
    objects = bytearray()
    offsets: list[int] = []
    for index in range(object_count):
        offsets.append(8 + len(objects))
        if index == object_count - 1:
            objects.extend(b"\x00")
        else:
            objects.extend(b"\xa1" + bytes([index + 1]))
    offset_table = 8 + len(objects)
    table = b"".join(offset.to_bytes(2, "big") for offset in offsets)
    trailer = struct.pack(">6xBBQQQ", 2, 1, object_count, 0, offset_table)
    return b"bplist00" + bytes(objects) + table + trailer


MALFORMED_PLISTS = {
    "bplist-huge-count": bplist_huge_object_count,
    "bplist-overlap": bplist_overlapping_objects,
    "bplist-cycle": bplist_cycle,
    "bplist-depth": bplist_excessive_depth,
}


def archive_from_app(app: Path, scenario: str = "valid") -> bytes:
    stream = BytesIO()
    archive_format = tarfile.PAX_FORMAT if scenario == "pax" else tarfile.USTAR_FORMAT
    with tarfile.open(fileobj=stream, mode="w", format=archive_format) as archive:
        for relative in ("", "Probes", "_CodeSignature"):
            name = PREFIX if not relative else f"{PREFIX}/{relative}"
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            expected_owner = 0 if not relative else 33
            if scenario == "wrong-root-owner" and not relative:
                expected_owner = 33
            member.uid = expected_owner
            member.gid = expected_owner
            member.uname = "mobile"
            member.gname = "mobile"
            if scenario == "pax" and not relative:
                member.pax_headers = {"comment": "force-pax-header"}
            archive.addfile(member)

        for relative, expected_mode in FILE_MODES.items():
            if scenario == "missing" and relative == "Info.plist":
                continue
            content = (app / relative).read_bytes()
            if scenario == "not-macho" and relative.endswith("setdescription"):
                content = b"not a Mach-O image"
            elif scenario == "invalid-resources" and relative.endswith("CodeResources"):
                content += b"corrupt"
            elif scenario in MALFORMED_PLISTS and relative == "Info.plist":
                content = MALFORMED_PLISTS[scenario]()
            member = tarfile.TarInfo(f"{PREFIX}/{relative}")
            member.mode = 0o600 if scenario == "wrong-mode" and relative == "Info.plist" else expected_mode
            member.uid = 0 if scenario == "wrong-owner" and relative == "Info.plist" else 33
            member.gid = 33
            member.uname = "mobile"
            member.gname = "mobile"
            member.size = len(content)
            archive.addfile(member, BytesIO(content))

        if scenario == "extra":
            content = b"extra"
            member = tarfile.TarInfo(f"{PREFIX}/unexpected")
            member.mode = 0o644
            member.uid = 33
            member.gid = 33
            member.size = len(content)
            archive.addfile(member, BytesIO(content))
        if scenario == "symlink":
            member = tarfile.TarInfo(f"{PREFIX}/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            member.uid = 33
            member.gid = 33
            archive.addfile(member)
        if scenario == "traversal":
            member = tarfile.TarInfo(f"{PREFIX}/../outside")
            member.uid = 33
            member.gid = 33
            member.size = 1
            archive.addfile(member, BytesIO(b"x"))
        if scenario == "duplicate":
            content = (app / "Info.plist").read_bytes()
            member = tarfile.TarInfo(f"{PREFIX}/Info.plist")
            member.mode = 0o644
            member.uid = 33
            member.gid = 33
            member.size = len(content)
            archive.addfile(member, BytesIO(content))
    data = stream.getvalue()
    if scenario == "trailing-junk":
        data += b"x"
    if scenario == "truncated":
        data = data[:700]
    return data


@functools.lru_cache(maxsize=None)
def make_archive(scenario: str = "valid") -> bytes:
    signed_scenarios = {
        "wrong-code",
        "wrong-entitlement",
        "wrong-identifier",
        "risky-info",
        "wrong-info-type",
        "corrupt-inner-signature",
    }
    with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-fixture-") as directory:
        root = Path(directory)
        app = build_signed_app(root, scenario if scenario in signed_scenarios else "valid")
        return archive_from_app(app, scenario)


def run_validator(
    data: bytes,
    *,
    existing_output: bool = False,
    stale_staging: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    temporary = Path(tempfile.mkdtemp(prefix="mac2jb-toolbox-validator-test-"))
    archive = temporary / "input.tar"
    output = temporary / "evidence"
    archive.write_bytes(data)
    if existing_output:
        output.mkdir()
        (output / "sentinel").write_text("preserve", encoding="ascii")
    if stale_staging:
        staging = temporary / ".evidence.staging"
        staging.mkdir()
        (staging / "sentinel").write_text("preserve", encoding="ascii")
    result = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", str(VALIDATOR), str(archive), str(output)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    return result, temporary


def remove_test_directory(path: Path) -> None:
    subprocess.run(["/bin/rm", "-rf", str(path)], check=True)


def test_valid_archive_preserves_attested_bundle() -> None:
    result, temporary = run_validator(make_archive())
    try:
        assert result.returncode == 0, result.stderr
        assert result.stdout.startswith("PASS installed toolbox attestation ")
        output = temporary / "evidence"
        expected_files = sorted(
            [f"{APP_NAME}/{relative}" for relative in FILE_MODES]
            + ["attestation-manifest.json"]
        )
        actual_files = sorted(
            path.relative_to(output).as_posix()
            for path in output.rglob("*")
            if path.is_file()
        )
        assert actual_files == expected_files
        manifest = json.loads((output / "attestation-manifest.json").read_text())
        assert manifest["schemaVersion"] == 2
        assert manifest["bundleIdentifier"] == "dev.mac2jb.u1probe.toolbox"
        assert manifest["sourceFamily"] == "container"
        assert manifest["code"]["mac2jb-u1-baseline"]["entitlements"] == CODE_PROFILES[
            "mac2jb-u1-baseline"
        ][1]
        assert "12345678-1234-1234-1234-123456789ABC" not in json.dumps(manifest)
        for path in output.rglob("*"):
            expected_mode = 0o700 if path.is_dir() else 0o600
            assert path.stat().st_mode & 0o777 == expected_mode, path
    finally:
        remove_test_directory(temporary)


def test_signed_semantic_mismatches_fail_closed() -> None:
    scenarios = (
        "wrong-code",
        "wrong-entitlement",
        "wrong-identifier",
        "risky-info",
        "wrong-info-type",
        "not-macho",
        "invalid-resources",
        "corrupt-inner-signature",
    )
    for scenario in scenarios:
        result, temporary = run_validator(make_archive(scenario))
        try:
            assert result.returncode != 0, scenario
            assert not (temporary / "evidence").exists(), scenario
            assert not (temporary / ".evidence.staging").exists(), scenario
        finally:
            remove_test_directory(temporary)


def test_archive_structure_and_metadata_fail_closed() -> None:
    scenarios = (
        "extra",
        "symlink",
        "traversal",
        "duplicate",
        "pax",
        "trailing-junk",
        "truncated",
        "wrong-owner",
        "wrong-root-owner",
        "wrong-mode",
        "missing",
    )
    for scenario in scenarios:
        result, temporary = run_validator(make_archive(scenario))
        try:
            assert result.returncode != 0, scenario
            assert not (temporary / "evidence").exists(), scenario
            assert not (temporary / ".evidence.staging").exists(), scenario
        finally:
            remove_test_directory(temporary)


def test_malicious_binary_plist_graphs_fail_closed() -> None:
    for scenario in MALFORMED_PLISTS:
        result, temporary = run_validator(make_archive(scenario))
        try:
            assert result.returncode != 0, scenario
            assert not (temporary / "evidence").exists(), scenario
            assert not (temporary / ".evidence.staging").exists(), scenario
        finally:
            remove_test_directory(temporary)


def test_existing_output_and_stale_staging_are_preserved() -> None:
    result, temporary = run_validator(make_archive(), existing_output=True)
    try:
        assert result.returncode != 0
        assert (temporary / "evidence/sentinel").read_text() == "preserve"
    finally:
        remove_test_directory(temporary)
    result, temporary = run_validator(make_archive(), stale_staging=True)
    try:
        assert result.returncode != 0
        assert (temporary / ".evidence.staging/sentinel").read_text() == "preserve"
        assert not (temporary / "evidence").exists()
    finally:
        remove_test_directory(temporary)


def test_concurrent_output_creation_is_not_replaced() -> None:
    temporary = Path(tempfile.mkdtemp(prefix="mac2jb-toolbox-validator-race-"))
    archive = temporary / "input.tar"
    output = temporary / "evidence"
    staging = temporary / ".evidence.staging"
    archive.write_bytes(make_archive())
    process = subprocess.Popen(
        ["/usr/bin/python3", "-I", "-S", str(VALIDATOR), str(archive), str(output)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not staging.is_dir() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.001)
        assert staging.is_dir(), "validator published before the race could be exercised"
        output.mkdir()
        (output / "sentinel").write_text("preserve", encoding="ascii")
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode != 0, (stdout, stderr)
        assert (output / "sentinel").read_text() == "preserve"
        assert sorted(path.name for path in output.iterdir()) == ["sentinel"]
        assert not staging.exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        remove_test_directory(temporary)


def test_handled_signals_clean_staging_and_reap_work() -> None:
    helper = """import importlib.util, sys, time
spec = importlib.util.spec_from_file_location('validator_under_signal', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.run_tool = lambda *args, **kwargs: time.sleep(30)
raise SystemExit(module.run(sys.argv[2:]))
"""
    for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        temporary = Path(tempfile.mkdtemp(prefix="mac2jb-toolbox-validator-signal-"))
        archive = temporary / "input.tar"
        output = temporary / "evidence"
        staging = temporary / ".evidence.staging"
        archive.write_bytes(make_archive())
        process = subprocess.Popen(
            [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                helper,
                str(VALIDATOR),
                str(archive),
                str(output),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 10
            while not staging.is_dir() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.001)
            assert staging.is_dir(), handled_signal
            process.send_signal(handled_signal)
            stdout, stderr = process.communicate(timeout=10)
            assert process.returncode == 128 + handled_signal, (stdout, stderr)
            assert not output.exists()
            assert not staging.exists()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            remove_test_directory(temporary)


def main() -> None:
    test_valid_archive_preserves_attested_bundle()
    test_signed_semantic_mismatches_fail_closed()
    test_archive_structure_and_metadata_fail_closed()
    test_malicious_binary_plist_graphs_fail_closed()
    test_existing_output_and_stale_staging_are_preserved()
    test_concurrent_output_creation_is_not_replaced()
    test_handled_signals_clean_staging_and_reap_work()
    print(
        "PASS installed-toolbox validator tests "
        "(7 groups: real signed Mach-O, 23 rejection scenarios, race, HUP/INT/TERM)"
    )


if __name__ == "__main__":
    main()
