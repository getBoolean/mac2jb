#!/usr/bin/env python3
"""Host-only hostile-input tests for the U1 stdout report validator.

The harness creates JSON fixtures in temporary Mac-local directories and runs
the validator with isolated Python settings. It does not open a network
connection, invoke SSH, or contact the iPad.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[6]
VALIDATOR = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/validate-probe-stdout.py"
PYTHON = "/usr/bin/python3"
VARIANTS = {"baseline", "setdescription", "controller-client", "interface-client"}
POWERS = {
    "operator-observed-vbus-charging",
    "operator-observed-vbus-not-charging",
    "operator-observed-no-vbus",
    "operator-not-observed",
}
READ_ONLY_SYMBOLS = {
    "IOUSBDeviceControllerCreate",
    "IOUSBDeviceControllerCreateWithService",
    "IOUSBDeviceControllerGetTypeID",
    "IOUSBDeviceDescriptionCopyInterfaces",
    "IOUSBDeviceDescriptionCreateFromController",
    "IOUSBDeviceDescriptionCreateFromDefaultsAndController",
    "IOUSBDeviceDescriptionGetTypeID",
}
INVOKED_READ_ONLY_SYMBOLS = {
    "IOUSBDeviceControllerCreate",
    "IOUSBDeviceControllerGetTypeID",
    "IOUSBDeviceDescriptionCreateFromController",
    "IOUSBDeviceDescriptionGetTypeID",
}
MUTATION_SYMBOLS = {
    "IORegistryEntrySetCFProperties",
    "IORegistryEntrySetCFProperty",
    "IOUSBDeviceControllerForceOffBus",
    "IOUSBDeviceControllerGoOffAndOnBus",
    "IOUSBDeviceControllerSendCommand",
    "IOUSBDeviceControllerSetDescription",
}
ENTITLEMENTS = {
    "com.apple.private.security.no-sandbox",
    "com.apple.private.usbdevice.setdescription",
    "com.apple.security.exception.iokit-user-client-class",
    "com.apple.security.exception.iokit-user-client-class:IOUSBDeviceControllerUserClient",
    "com.apple.security.exception.iokit-user-client-class:IOUSBDeviceInterfaceUserClient",
    "platform-application",
}


def identity(label: str) -> dict[str, str]:
    return {"algorithm": "sha256", "digest": hashlib.sha256(label.encode()).hexdigest()}


def entitlement_profile(variant: str) -> dict[str, bool]:
    profile = {name: False for name in ENTITLEMENTS}
    if variant == "setdescription":
        profile["com.apple.private.usbdevice.setdescription"] = True
    elif variant == "controller-client":
        profile["com.apple.security.exception.iokit-user-client-class"] = True
        profile[
            "com.apple.security.exception.iokit-user-client-class:IOUSBDeviceControllerUserClient"
        ] = True
        profile["platform-application"] = True
    elif variant == "interface-client":
        profile["com.apple.security.exception.iokit-user-client-class"] = True
        profile[
            "com.apple.security.exception.iokit-user-client-class:IOUSBDeviceInterfaceUserClient"
        ] = True
        profile["platform-application"] = True
    return profile


def open_results() -> list[dict[str, object]]:
    return [
        {"clientType": 0, "ioReturn": 0, "outcome": "success"},
        {
            "clientType": 123,
            "ioReturn": -536870201,
            "outcome": "unsupported-operation-or-user-client-type",
        },
    ]


def topology_fingerprint(document: dict[str, object]) -> str:
    snapshot = {
        key: copy.deepcopy(document[key])
        for key in (
            "schemaVersion",
            "target",
            "controllers",
            "functions",
            "configuration",
            "symbols",
            "entitlements",
            "operations",
        )
    }
    for service in snapshot["controllers"]:
        service["openResults"].sort(key=lambda item: (item["clientType"], item["ioReturn"]))
        service["userClientClasses"].sort()
    snapshot["controllers"].sort(key=lambda item: (item["registryID"], item["name"]))
    for service in snapshot["functions"]:
        service["openResults"].sort(key=lambda item: (item["clientType"], item["ioReturn"]))
        service["userClientClasses"].sort()
    snapshot["functions"].sort(key=lambda item: (item["registryID"], item["name"]))
    snapshot["symbols"].sort(key=lambda item: item["name"])
    snapshot["entitlements"].sort(key=lambda item: item["name"])
    snapshot["operations"].sort(key=lambda item: item["name"])
    canonical = json.dumps(
        snapshot,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def reseal(document: dict[str, object]) -> dict[str, object]:
    document["topologyFingerprint"] = topology_fingerprint(document)
    return document


def fixture(
    variant: str = "baseline",
    peer: str = "capture-host",
    orientation: str = "a",
    power: str = "operator-not-observed",
) -> dict[str, object]:
    peer_label = (
        "mac2jb-generic-capture-host-primary"
        if peer == "capture-host"
        else "mac2jb-nintendo-switch-primary"
    )
    profile = entitlement_profile(variant)
    symbols = [
        {
            "available": True,
            "invoked": name in INVOKED_READ_ONLY_SYMBOLS,
            "kind": "readOnly",
            "name": name,
        }
        for name in sorted(READ_ONLY_SYMBOLS)
    ] + [
        {"available": True, "invoked": False, "kind": "mutation", "name": name}
        for name in sorted(MUTATION_SYMBOLS)
    ]
    document = {
        "capturedAt": "2026-10-29T18:30:00Z",
        "configuration": {
            "deviceTreeConfiguration": "standard",
            "path": "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist",
            "sha256": "1" * 64,
        },
        "controllers": [
            {
                "ancestry": ["IOUSBDeviceController", "IOService"],
                "className": "IOUSBDeviceController",
                "name": "controller0",
                "openResults": open_results(),
                "registryID": 100,
                "restoreProperties": {"idProduct": "1234"},
                "userClientClasses": ["IOUSBDeviceControllerUserClient"],
            }
        ],
        "entitlements": [
            {"name": name, "present": present}
            for name, present in sorted(profile.items())
        ],
        "functions": [
            {
                "className": "IOUSBDeviceInterface",
                "controllerRegistryID": 100,
                "functionName": "USBDeviceFunction",
                "name": "function0",
                "openResults": open_results(),
                "registryID": 200,
                "restoreProperties": {"USBConfigurationValue": "1"},
                "userClientClasses": ["IOUSBDeviceInterfaceUserClient"],
            }
        ],
        "operations": [
            {
                "ioReturn": 0,
                "kind": "readOnly",
                "name": "IOServiceGetMatchingServices(IOUSBDeviceController)",
                "outcome": "success",
            },
            {
                "kind": "readOnly",
                "name": "IOServiceMatch(IOUSBDeviceController)",
                "outcome": "service-present",
            },
            {
                "ioReturn": 0,
                "kind": "readOnly",
                "name": "IOServiceGetMatchingServices(IOUSBDeviceInterface)",
                "outcome": "success",
            },
            {
                "kind": "readOnly",
                "name": "IOServiceMatch(IOUSBDeviceInterface)",
                "outcome": "service-present",
            },
            {
                "ioReturn": 0,
                "kind": "readOnly",
                "name": "IOServiceOpen(controller:100,type:0)",
                "outcome": "success",
            },
            {
                "ioReturn": 0,
                "kind": "readOnly",
                "name": "IOServiceClose(controller:100,type:0)",
                "outcome": "success",
            },
            {
                "ioReturn": -536870201,
                "kind": "readOnly",
                "name": "IOServiceOpen(controller:100,type:123)",
                "outcome": "unsupported-operation-or-user-client-type",
            },
            {
                "ioReturn": 0,
                "kind": "readOnly",
                "name": "IOServiceOpen(function:200,type:0)",
                "outcome": "success",
            },
            {
                "ioReturn": 0,
                "kind": "readOnly",
                "name": "IOServiceClose(function:200,type:0)",
                "outcome": "success",
            },
            {
                "ioReturn": -536870201,
                "kind": "readOnly",
                "name": "IOServiceOpen(function:200,type:123)",
                "outcome": "unsupported-operation-or-user-client-type",
            },
            {
                "ioReturn": 0,
                "kind": "readOnly",
                "name": "IOUSBDeviceControllerCreate",
                "outcome": "read-only-description-validated",
            },
            {
                "kind": "readOnly",
                "name": "IOUSBDeviceControllerGetTypeID",
                "outcome": "type-match",
            },
            {
                "kind": "readOnly",
                "name": "IOUSBDeviceDescriptionCreateFromController",
                "outcome": "description-created",
            },
            {
                "kind": "readOnly",
                "name": "IOUSBDeviceDescriptionGetTypeID",
                "outcome": "type-match",
            },
        ],
        "role": {
            "cableIdentity": identity("mac2jb-known-good-usbc-cable-primary"),
            "controllerPresent": True,
            "orientation": orientation,
            "peerIdentity": identity(peer_label),
            "peerKind": peer,
            "powerState": power,
        },
        "schemaVersion": 1,
        "symbols": symbols,
        "target": {
            "boardIdentifier": "J620AP",
            "dopamineBuild": "3.0.12-1",
            "osBuild": "21A329",
            "osVersion": "Version 17.0 (Build 21A329)",
            "portFamily": "thunderbolt-usb4",
            "productType": "iPad14,5",
            "soc": "T8112",
            "trollStoreBuild": "2.1.1",
        },
        "topologyFingerprint": "0" * 64,
    }
    return reseal(document)


def encoded(document: object) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, separators=(",", ": ")) + "\n").encode()


def invoke(
    path: Path,
    *,
    variant: str = "baseline",
    peer: str = "capture-host",
    orientation: str = "a",
    power: str = "operator-not-observed",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            PYTHON,
            "-I",
            "-S",
            str(VALIDATOR),
            str(path),
            variant,
            peer,
            orientation,
            power,
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )


def write(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o400)


def expect_pass(
    root: Path,
    document: dict[str, object],
    *,
    variant: str = "baseline",
    peer: str = "capture-host",
    orientation: str = "a",
    power: str = "operator-not-observed",
    name: str = "report.json",
) -> None:
    path = root / name
    data = encoded(document)
    write(path, data)
    result = invoke(path, variant=variant, peer=peer, orientation=orientation, power=power)
    expected_hash = hashlib.sha256(data[:-1]).hexdigest()
    expected = f"PASS probe report {expected_hash} {document['topologyFingerprint']}\n"
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert result.stdout == expected
    assert result.stderr == ""


def expect_reject(
    root: Path,
    data: bytes,
    *,
    variant: str = "baseline",
    peer: str = "capture-host",
    orientation: str = "a",
    power: str = "operator-not-observed",
    name: str = "rejected.json",
) -> None:
    path = root / name
    write(path, data)
    before = {item.name: item.read_bytes() for item in root.iterdir() if item.is_file()}
    result = invoke(path, variant=variant, peer=peer, orientation=orientation, power=power)
    after = {item.name: item.read_bytes() for item in root.iterdir() if item.is_file()}
    assert result.returncode == 65, (result.returncode, result.stdout, result.stderr)
    assert result.stdout == ""
    assert result.stderr == "Probe stdout rejected; no report was accepted.\n"
    assert after == before


def test_valid_profiles_and_bounds() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for index, variant in enumerate(sorted(VARIANTS)):
            report = fixture(variant=variant)
            if variant == "baseline":
                report["configuration"]["deviceTreeConfiguration"] = "x" * 1500
                reseal(report)
            expect_pass(root, report, variant=variant, name=f"valid-{index}.json")
        missing_create = fixture()
        symbols = {item["name"]: item for item in missing_create["symbols"]}
        symbols["IOUSBDeviceControllerCreate"]["available"] = False
        for name in INVOKED_READ_ONLY_SYMBOLS:
            symbols[name]["invoked"] = False
        operations = {item["name"]: item for item in missing_create["operations"]}
        operations["IOUSBDeviceControllerCreate"].update(
            ioReturn=-536870201,
            outcome="missing-symbol",
        )
        operations["IOUSBDeviceControllerGetTypeID"]["outcome"] = "not-invoked"
        operations["IOUSBDeviceDescriptionCreateFromController"]["outcome"] = "not-invoked"
        operations["IOUSBDeviceDescriptionGetTypeID"]["outcome"] = "not-invoked"
        expect_pass(root, reseal(missing_create), name="valid-missing-create.json")
        omitted_optionals = fixture()
        del omitted_optionals["configuration"]["sha256"]
        del omitted_optionals["configuration"]["deviceTreeConfiguration"]
        del omitted_optionals["functions"][0]["controllerRegistryID"]
        expect_pass(root, reseal(omitted_optionals), name="valid-omitted-optionals.json")


def test_framing_and_duplicate_keys() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        base = encoded(fixture())
        duplicate = base.replace(
            b'  "schemaVersion": 1,',
            b'  "schemaVersion": 1,\n  "schemaVersion": 1,',
            1,
        )
        assert duplicate != base
        expect_reject(root, duplicate, name="duplicate.json")
        expect_reject(root, base[:-1] + b" \n", name="trailing-space.json")
        expect_reject(root, base + b"\n", name="double-newline.json")
        expect_reject(root, base[:-1], name="unterminated.json")
        expect_reject(root, b"[]\n", name="array.json")


def test_identity_and_role_rejections() -> None:
    mutations = []
    wrong_target = fixture()
    wrong_target["target"]["productType"] = "iPad14,6"
    mutations.append(reseal(wrong_target))
    wrong_peer_hash = fixture()
    wrong_peer_hash["role"]["peerIdentity"] = identity("wrong")
    mutations.append(wrong_peer_hash)
    wrong_cable = fixture()
    wrong_cable["role"]["cableIdentity"] = identity("wrong")
    mutations.append(wrong_cable)
    wrong_role = fixture()
    wrong_role["role"]["orientation"] = "b"
    mutations.append(wrong_role)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for index, document in enumerate(mutations):
            expect_reject(root, encoded(document), name=f"identity-{index}.json")


def test_topology_and_schema_rejections() -> None:
    mutations = []
    missing_key = fixture()
    del missing_key["operations"]
    mutations.append(missing_key)
    extra_key = fixture()
    extra_key["unexpected"] = True
    mutations.append(extra_key)
    wrong_clients = fixture()
    wrong_clients["controllers"][0]["openResults"] = [open_results()[0]]
    mutations.append(reseal(wrong_clients))
    duplicate_controller = fixture()
    duplicate_controller["controllers"].append(copy.deepcopy(duplicate_controller["controllers"][0]))
    mutations.append(reseal(duplicate_controller))
    unknown_parent = fixture()
    unknown_parent["functions"][0]["controllerRegistryID"] = 999
    mutations.append(reseal(unknown_parent))
    unsafe_property = fixture()
    unsafe_property["controllers"][0]["restoreProperties"]["unknown"] = "value"
    mutations.append(reseal(unsafe_property))
    long_tree = fixture()
    long_tree["configuration"]["deviceTreeConfiguration"] = "x" * 4097
    mutations.append(reseal(long_tree))
    null_configuration = fixture()
    null_configuration["configuration"]["sha256"] = None
    mutations.append(reseal(null_configuration))
    null_parent = fixture()
    null_parent["functions"][0]["controllerRegistryID"] = None
    mutations.append(reseal(null_parent))
    null_operation = fixture()
    null_operation["operations"][0]["ioReturn"] = None
    mutations.append(reseal(null_operation))
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for index, document in enumerate(mutations):
            expect_reject(root, encoded(document), name=f"topology-{index}.json")


def test_safety_rejections() -> None:
    mutations = []
    invoked_mutation = fixture()
    mutation = next(
        item for item in invoked_mutation["symbols"] if item["kind"] == "mutation"
    )
    mutation["invoked"] = True
    mutations.append(reseal(invoked_mutation))
    mutation_operation = fixture()
    mutation_operation["operations"][0]["kind"] = "mutation"
    mutations.append(reseal(mutation_operation))
    wrong_entitlement = fixture()
    wrong_entitlement["entitlements"][0]["present"] = not wrong_entitlement["entitlements"][0]["present"]
    mutations.append(reseal(wrong_entitlement))
    unknown_symbol = fixture()
    unknown_symbol["symbols"][0]["name"] = "UnknownAPI"
    mutations.append(reseal(unknown_symbol))
    control_text = fixture()
    control_text["controllers"][0]["name"] = "bad\nname"
    mutations.append(reseal(control_text))
    disguised_mutation = fixture()
    disguised_mutation["operations"][0]["name"] = "IOUSBDeviceControllerSetDescription"
    mutations.append(reseal(disguised_mutation))
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for index, document in enumerate(mutations):
            expect_reject(root, encoded(document), name=f"safety-{index}.json")


def test_fingerprint_and_consistency_rejections() -> None:
    mutations = []
    forged_fingerprint = fixture()
    forged_fingerprint["topologyFingerprint"] = "f" * 64
    mutations.append(forged_fingerprint)
    false_controller_presence = fixture()
    false_controller_presence["role"]["controllerPresent"] = False
    mutations.append(false_controller_presence)
    phantom_controller_presence = fixture()
    phantom_controller_presence["controllers"] = []
    phantom_controller_presence["functions"] = []
    phantom_controller_presence["operations"] = [
        item
        for item in phantom_controller_presence["operations"]
        if "IOServiceOpen" not in item["name"] and "IOServiceClose" not in item["name"]
    ]
    phantom_controller_presence["role"]["controllerPresent"] = True
    mutations.append(reseal(phantom_controller_presence))
    mismatched_outcome = fixture()
    mismatched_outcome["controllers"][0]["openResults"][0]["outcome"] = "iokit-error"
    mutations.append(reseal(mismatched_outcome))
    unavailable_invocation = fixture()
    unavailable_invocation["symbols"][0]["available"] = False
    unavailable_invocation["symbols"][0]["invoked"] = True
    mutations.append(reseal(unavailable_invocation))
    missing_open_operation = fixture()
    missing_open_operation["operations"] = [
        item
        for item in missing_open_operation["operations"]
        if item["name"] != "IOServiceOpen(controller:100,type:123)"
    ]
    mutations.append(reseal(missing_open_operation))
    impossible_private_aggregate = fixture()
    aggregate_symbols = {
        item["name"]: item for item in impossible_private_aggregate["symbols"]
    }
    aggregate_operations = {
        item["name"]: item for item in impossible_private_aggregate["operations"]
    }
    for name in (
        "IOUSBDeviceControllerGetTypeID",
        "IOUSBDeviceDescriptionCreateFromController",
        "IOUSBDeviceDescriptionGetTypeID",
    ):
        aggregate_symbols[name]["invoked"] = False
        aggregate_operations[name]["outcome"] = "not-invoked"
    mutations.append(reseal(impossible_private_aggregate))
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for index, document in enumerate(mutations):
            expect_reject(root, encoded(document), name=f"consistency-{index}.json")


def test_file_and_argument_safety() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        original = root / "original.json"
        write(original, encoded(fixture()))
        symlink = root / "symlink.json"
        symlink.symlink_to(original)
        assert invoke(symlink).returncode == 65
        hardlink = root / "hardlink.json"
        os.link(original, hardlink)
        assert invoke(hardlink).returncode == 65
        oversized = root / "oversized.json"
        write(oversized, b"{" + b"x" * (2 * 1024 * 1024) + b"}\n")
        assert invoke(oversized).returncode == 65
        empty = root / "empty.json"
        write(empty, b"")
        assert invoke(empty).returncode == 65
        assert invoke(original, variant="unknown").returncode == 64
        assert invoke(original, peer="unknown").returncode == 64
        assert invoke(original, orientation="c").returncode == 64
        assert invoke(original, power="unknown").returncode == 64


def main() -> None:
    tests = [
        test_valid_profiles_and_bounds,
        test_framing_and_duplicate_keys,
        test_identity_and_role_rejections,
        test_topology_and_schema_rejections,
        test_safety_rejections,
        test_fingerprint_and_consistency_rejections,
        test_file_and_argument_safety,
    ]
    for test in tests:
        test()
    print("PASS probe stdout validator tests (7 groups, 46 scenarios)")


if __name__ == "__main__":
    main()
