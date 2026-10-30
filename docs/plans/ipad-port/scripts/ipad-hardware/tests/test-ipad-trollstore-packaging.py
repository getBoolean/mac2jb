#!/usr/bin/env python3
"""Verify deterministic, entitlement-preserving TrollStore probe packages."""

from __future__ import annotations

import hashlib
import os
import plistlib
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
BUILD = ROOT / "build" / "ipad-hardware"
PACKAGER = ROOT / "scripts" / "ipad-hardware" / "package-trollstore-readonly-probes.sh"
VARIANTS = {
    "baseline": "dev.mac2jb.u1probe.baseline",
    "setdescription": "dev.mac2jb.u1probe.setdescription",
    "controller-client": "dev.mac2jb.u1probe.controller-client",
    "interface-client": "dev.mac2jb.u1probe.interface-client",
}
EXPECTED_ENTITLEMENTS = {
    "baseline": {"get-task-allow": False},
    "setdescription": {"com.apple.private.usbdevice.setdescription": True},
    "controller-client": {
        "com.apple.security.exception.iokit-user-client-class": ["IOUSBDeviceControllerUserClient"],
        "platform-application": True,
    },
    "interface-client": {
        "com.apple.security.exception.iokit-user-client-class": ["IOUSBDeviceInterfaceUserClient"],
        "platform-application": True,
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_packager(*, timezone: str, umask: str) -> None:
    environment = os.environ.copy()
    environment["TZ"] = timezone
    subprocess.run(
        ["/bin/sh", "-c", "umask \"$1\"; exec \"$2\"", "sh", umask, str(PACKAGER)],
        cwd=ROOT,
        env=environment,
        check=True,
    )


def assert_member_metadata(package: zipfile.ZipFile, member: str, mode: int) -> None:
    info = package.getinfo(member)
    archived_mode = info.external_attr >> 16
    assert stat.S_IFMT(archived_mode) == stat.S_IFREG
    assert stat.S_IMODE(archived_mode) == mode
    assert info.date_time == (2026, 1, 1, 0, 0, 0)


def extract_members(package: zipfile.ZipFile, members: list[str], destination: Path) -> None:
    for member in members:
        target = destination / member
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(package.read(member))
        target.chmod(stat.S_IMODE(package.getinfo(member).external_attr >> 16))


def entitlements(path: Path) -> dict[str, object]:
    result = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if not result.stdout:
        return {}
    return plistlib.loads(result.stdout)


def unsigned_bytes(path: Path) -> bytes:
    with tempfile.TemporaryDirectory(prefix="mac2jb-unsigned-test-") as directory:
        copy = Path(directory) / "probe"
        copy.write_bytes(path.read_bytes())
        copy.chmod(0o755)
        subprocess.run(
            ["codesign", "--remove-signature", str(copy)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return copy.read_bytes()


def verify_probe(path: Path, variant: str) -> None:
    subprocess.run(["codesign", "--verify", "--strict", str(path)], check=True)
    assert entitlements(path) == EXPECTED_ENTITLEMENTS[variant]
    source = BUILD / f"mac2jb-ios-probe-stdout-{variant}"
    assert unsigned_bytes(path) == unsigned_bytes(source)


def inspect_package(variant: str, bundle_id: str) -> None:
    archive = BUILD / f"mac2jb-u1-stdout-{variant}.tipa"
    app = f"Mac2JBU1-{variant}.app"
    executable_member = f"Payload/{app}/mac2jb-u1-probe"
    plist_member = f"Payload/{app}/Info.plist"
    resources_member = f"Payload/{app}/_CodeSignature/CodeResources"
    with zipfile.ZipFile(archive) as package:
        assert package.namelist() == [plist_member, executable_member, resources_member]
        plist = plistlib.loads(package.read(plist_member))
        assert plist["CFBundleIdentifier"] == bundle_id
        assert plist["CFBundleExecutable"] == "mac2jb-u1-probe"
        assert plist["CFBundlePackageType"] == "APPL"
        assert plist["CFBundleSupportedPlatforms"] == ["iPhoneOS"]
        assert plist["UIDeviceFamily"] == [2]
        assert plist["MinimumOSVersion"] == "17.0"
        assert_member_metadata(package, plist_member, 0o644)
        assert_member_metadata(package, executable_member, 0o755)
        assert_member_metadata(package, resources_member, 0o644)
        assert all("__MACOSX" not in name and "/._" not in name for name in package.namelist())

        with tempfile.TemporaryDirectory(prefix="mac2jb-package-test-") as directory:
            extraction_root = Path(directory)
            extract_members(package, package.namelist(), extraction_root)
            extracted_app = extraction_root / "Payload" / app
            subprocess.run(
                ["codesign", "--verify", "--deep", "--strict", str(extracted_app)],
                check=True,
            )
            verify_probe(extraction_root / executable_member, variant)


def inspect_toolbox_package() -> None:
    archive = BUILD / "mac2jb-u1-stdout-toolbox.tipa"
    app = "Mac2JBU1-Toolbox.app"
    prefix = f"Payload/{app}"
    expected_members = [
        f"{prefix}/Info.plist",
        f"{prefix}/mac2jb-u1-baseline",
        f"{prefix}/Probes/mac2jb-u1-setdescription",
        f"{prefix}/Probes/mac2jb-u1-controller-client",
        f"{prefix}/Probes/mac2jb-u1-interface-client",
        f"{prefix}/_CodeSignature/CodeResources",
    ]
    member_variants = {
        expected_members[1]: "baseline",
        expected_members[2]: "setdescription",
        expected_members[3]: "controller-client",
        expected_members[4]: "interface-client",
    }

    with zipfile.ZipFile(archive) as package:
        assert package.namelist() == expected_members
        plist = plistlib.loads(package.read(expected_members[0]))
        assert plist["CFBundleIdentifier"] == "dev.mac2jb.u1probe.toolbox"
        assert plist["CFBundleExecutable"] == "mac2jb-u1-baseline"
        assert_member_metadata(package, expected_members[0], 0o644)
        for member, variant in member_variants.items():
            assert_member_metadata(package, member, 0o755)
        assert_member_metadata(package, expected_members[-1], 0o644)
        assert all("__MACOSX" not in name and "/._" not in name for name in package.namelist())

        with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-test-") as directory:
            extraction_root = Path(directory)
            extract_members(package, package.namelist(), extraction_root)
            extracted_app = extraction_root / "Payload" / app
            subprocess.run(
                ["codesign", "--verify", "--deep", "--strict", str(extracted_app)],
                check=True,
            )
            for member, variant in member_variants.items():
                verify_probe(extraction_root / member, variant)


def main() -> None:
    run_packager(timezone="America/Chicago", umask="022")
    first_hashes = {
        variant: sha256(BUILD / f"mac2jb-u1-stdout-{variant}.tipa")
        for variant in VARIANTS
    }
    first_hashes["toolbox"] = sha256(BUILD / "mac2jb-u1-stdout-toolbox.tipa")
    run_packager(timezone="UTC", umask="077")
    second_hashes = {
        variant: sha256(BUILD / f"mac2jb-u1-stdout-{variant}.tipa")
        for variant in VARIANTS
    }
    second_hashes["toolbox"] = sha256(BUILD / "mac2jb-u1-stdout-toolbox.tipa")
    assert first_hashes == second_hashes
    for variant, bundle_id in VARIANTS.items():
        inspect_package(variant, bundle_id)
    inspect_toolbox_package()
    print("PASS deterministic TrollStore packaging tests (4 variants + 1 toolbox)")


if __name__ == "__main__":
    main()
