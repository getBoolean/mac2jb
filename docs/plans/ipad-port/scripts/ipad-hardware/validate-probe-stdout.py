#!/usr/bin/env python3
"""Validate one U1 stdout-only probe report without writing any file."""

from __future__ import annotations

import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import stat
import sys


MAX_REPORT_SIZE = 2 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}")
CAPTURED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")
TARGET_KEYS = {
    "boardIdentifier",
    "dopamineBuild",
    "osBuild",
    "osVersion",
    "portFamily",
    "productType",
    "soc",
    "trollStoreBuild",
}
ROLE_KEYS = {
    "cableIdentity",
    "controllerPresent",
    "orientation",
    "peerIdentity",
    "peerKind",
    "powerState",
}
REPORT_KEYS = {
    "capturedAt",
    "configuration",
    "controllers",
    "entitlements",
    "functions",
    "operations",
    "role",
    "schemaVersion",
    "symbols",
    "target",
    "topologyFingerprint",
}
CONTROLLER_KEYS = {
    "ancestry",
    "className",
    "name",
    "openResults",
    "registryID",
    "restoreProperties",
    "userClientClasses",
}
FUNCTION_KEYS = {
    "className",
    "controllerRegistryID",
    "functionName",
    "name",
    "openResults",
    "registryID",
    "restoreProperties",
    "userClientClasses",
}
CONTROLLER_PROPERTIES = {
    "USB Product Name",
    "USB Vendor Name",
    "USBDeviceConfiguration",
    "bDeviceClass",
    "bDeviceProtocol",
    "bDeviceSubClass",
    "bcdDevice",
    "current-available",
    "idProduct",
    "idVendor",
    "max-current",
}
FUNCTION_PROPERTIES = {
    "USBConfigurationValue",
    "USBDeviceFunction",
    "bInterfaceClass",
    "bInterfaceProtocol",
    "bInterfaceSubClass",
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
class Rejection(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejection(message)


def exact_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    require(isinstance(value, dict) and set(value) == keys, f"{label} keys")
    return value


def keys_with_optional(
    value: object,
    required: set[str],
    optional: set[str],
    label: str,
) -> dict[str, object]:
    require(
        isinstance(value, dict)
        and required <= set(value)
        and set(value) <= required | optional,
        f"{label} keys",
    )
    return value


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Rejection("duplicate JSON key")
        result[key] = value
    return result


def safe_text(value: object, *, maximum: int = 1024) -> str:
    encoded = value.encode("utf-8") if isinstance(value, str) else b""
    require(
        isinstance(value, str)
        and 1 <= len(encoded) <= maximum
        and all(0x20 <= ord(character) <= 0x7E for character in value),
        "unsafe text",
    )
    return value


def integer(value: object, minimum: int, maximum: int) -> int:
    require(type(value) is int and minimum <= value <= maximum, "integer range")
    return value


def string_list(value: object, maximum_items: int) -> list[str]:
    require(isinstance(value, list) and len(value) <= maximum_items, "string list")
    result = [safe_text(item) for item in value]
    require(len(result) == len(set(result)), "duplicate string list item")
    return result


def read_report(path: Path) -> tuple[bytes, dict[str, object]]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        status = os.fstat(descriptor)
        require(
            stat.S_ISREG(status.st_mode)
            and status.st_nlink == 1
            and 1 < status.st_size <= MAX_REPORT_SIZE,
            "report file metadata",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            require(total <= MAX_REPORT_SIZE, "report exceeded cap")
            chunks.append(chunk)
        data = b"".join(chunks)
        require(len(data) == status.st_size and data.endswith(b"\n"), "report extent")
        payload = data[:-1]
        require(
            payload.startswith(b"{") and payload.endswith(b"}") and b"\0" not in payload,
            "report framing",
        )
        try:
            text = payload.decode("utf-8")
            document = json.loads(text, object_pairs_hook=reject_duplicate_pairs)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise Rejection("report JSON") from error
        require(isinstance(document, dict), "report root")
        return data, document
    finally:
        os.close(descriptor)


def expected_hash(label: str) -> dict[str, str]:
    return {"algorithm": "sha256", "digest": hashlib.sha256(label.encode()).hexdigest()}


def iokit_outcome(value: int) -> str:
    code = value & 0xFFFFFFFF
    if code == 0:
        return "success"
    if code in {0xE00002C1, 0xE00002E2}:
        return "entitlement-or-privilege-denied"
    if code == 0xE00002C7:
        return "unsupported-operation-or-user-client-type"
    if code in {0xE00002C0, 0xE00002D9}:
        return "controller-role-or-service-unavailable"
    if code == 0xE00002CD:
        return "user-client-not-open"
    if code == 0xE00002C5:
        return "user-client-already-open"
    if code == 0xE00002C2:
        return "abi-or-argument-mismatch"
    return "iokit-error"


def validate_open_results(value: object) -> None:
    require(isinstance(value, list) and len(value) == 2, "open result count")
    observed: set[int] = set()
    for item in value:
        result = exact_keys(item, {"clientType", "ioReturn", "outcome"}, "open result")
        client_type = integer(result["clientType"], 0, 0xFFFFFFFF)
        require(client_type not in observed, "duplicate client type")
        observed.add(client_type)
        status = integer(result["ioReturn"], -(2**31), 2**31 - 1)
        require(result["outcome"] == iokit_outcome(status), "open result outcome")
    require(observed == {0, 123}, "client type set")


def validate_properties(value: object, allowed: set[str]) -> None:
    require(isinstance(value, dict) and set(value) <= allowed, "restore properties")
    for key, item in value.items():
        safe_text(key)
        safe_text(item)


def validate_services(document: dict[str, object]) -> None:
    controllers = document["controllers"]
    functions = document["functions"]
    require(isinstance(controllers, list) and len(controllers) <= 128, "controllers")
    require(isinstance(functions, list) and len(functions) <= 256, "functions")
    controller_ids: set[int] = set()
    for item in controllers:
        service = exact_keys(item, CONTROLLER_KEYS, "controller")
        identifier = integer(service["registryID"], 0, 2**64 - 1)
        require(identifier not in controller_ids, "duplicate controller")
        controller_ids.add(identifier)
        safe_text(service["name"])
        safe_text(service["className"])
        string_list(service["ancestry"], 24)
        string_list(service["userClientClasses"], 64)
        validate_open_results(service["openResults"])
        validate_properties(service["restoreProperties"], CONTROLLER_PROPERTIES)
    function_ids: set[int] = set()
    for item in functions:
        service = keys_with_optional(
            item,
            FUNCTION_KEYS - {"controllerRegistryID"},
            {"controllerRegistryID"},
            "function",
        )
        identifier = integer(service["registryID"], 0, 2**64 - 1)
        require(identifier not in function_ids, "duplicate function")
        function_ids.add(identifier)
        safe_text(service["name"])
        safe_text(service["className"])
        safe_text(service["functionName"])
        if "controllerRegistryID" in service:
            parent = service["controllerRegistryID"]
            require(type(parent) is int, "function parent")
            integer(parent, 0, 2**64 - 1)
            require(parent in controller_ids, "unknown function parent")
        string_list(service["userClientClasses"], 64)
        validate_open_results(service["openResults"])
        validate_properties(service["restoreProperties"], FUNCTION_PROPERTIES)


def validate_symbols(document: dict[str, object]) -> None:
    value = document["symbols"]
    require(isinstance(value, list) and len(value) == 13, "symbol count")
    observed: set[str] = set()
    for item in value:
        symbol = exact_keys(item, {"available", "invoked", "kind", "name"}, "symbol")
        name = safe_text(symbol["name"])
        require(name not in observed, "duplicate symbol")
        observed.add(name)
        require(type(symbol["available"]) is bool and type(symbol["invoked"]) is bool, "symbol bool")
        require(not symbol["invoked"] or symbol["available"], "unavailable symbol invocation")
        if name in READ_ONLY_SYMBOLS:
            require(symbol["kind"] == "readOnly", "read-only symbol kind")
        elif name in MUTATION_SYMBOLS:
            require(symbol["kind"] == "mutation" and symbol["invoked"] is False, "mutation symbol")
        else:
            raise Rejection("unknown symbol")
    require(observed == READ_ONLY_SYMBOLS | MUTATION_SYMBOLS, "symbol set")


def entitlement_profile(variant: str) -> dict[str, bool]:
    result = {name: False for name in ENTITLEMENTS}
    if variant == "setdescription":
        result["com.apple.private.usbdevice.setdescription"] = True
    if variant == "controller-client":
        result["com.apple.security.exception.iokit-user-client-class"] = True
        result["com.apple.security.exception.iokit-user-client-class:IOUSBDeviceControllerUserClient"] = True
        result["platform-application"] = True
    if variant == "interface-client":
        result["com.apple.security.exception.iokit-user-client-class"] = True
        result["com.apple.security.exception.iokit-user-client-class:IOUSBDeviceInterfaceUserClient"] = True
        result["platform-application"] = True
    return result


def validate_entitlements(document: dict[str, object], variant: str) -> None:
    value = document["entitlements"]
    require(isinstance(value, list) and len(value) == len(ENTITLEMENTS), "entitlement count")
    observed: dict[str, bool] = {}
    for item in value:
        entitlement = exact_keys(item, {"name", "present"}, "entitlement")
        name = safe_text(entitlement["name"])
        require(name in ENTITLEMENTS and name not in observed, "entitlement name")
        require(type(entitlement["present"]) is bool, "entitlement value")
        observed[name] = entitlement["present"]
    require(observed == entitlement_profile(variant), "entitlement profile")


def validate_operations(document: dict[str, object]) -> None:
    value = document["operations"]
    require(isinstance(value, list) and len(value) <= 2048, "operations")
    observed: dict[str, dict[str, object]] = {}
    for item in value:
        operation = keys_with_optional(
            item,
            {"kind", "name", "outcome"},
            {"ioReturn"},
            "operation",
        )
        require(operation["kind"] == "readOnly", "mutation operation")
        name = safe_text(operation["name"])
        require(name not in observed, "duplicate operation")
        observed[name] = operation
        safe_text(operation["outcome"])
        status = operation.get("ioReturn")
        if "ioReturn" in operation:
            require(type(status) is int, "operation status")
            integer(status, -(2**31), 2**31 - 1)

    expected_names = {
        "IOServiceGetMatchingServices(IOUSBDeviceController)",
        "IOServiceMatch(IOUSBDeviceController)",
        "IOServiceGetMatchingServices(IOUSBDeviceInterface)",
        "IOServiceMatch(IOUSBDeviceInterface)",
        "IOUSBDeviceControllerCreate",
        "IOUSBDeviceControllerGetTypeID",
        "IOUSBDeviceDescriptionCreateFromController",
        "IOUSBDeviceDescriptionGetTypeID",
    }

    def require_iokit(name: str, status: int, outcome: str) -> None:
        operation = observed.get(name)
        require(operation is not None, "missing IOKit operation")
        require(
            operation["ioReturn"] == status and operation["outcome"] == outcome,
            "IOKit operation mismatch",
        )

    for class_name, services, kind in (
        ("IOUSBDeviceController", document["controllers"], "controller"),
        ("IOUSBDeviceInterface", document["functions"], "function"),
    ):
        match_name = f"IOServiceGetMatchingServices({class_name})"
        require_iokit(match_name, 0, "success")
        presence_name = f"IOServiceMatch({class_name})"
        presence = observed.get(presence_name)
        require(presence is not None, "missing service-match operation")
        require(
            "ioReturn" not in presence
            and presence["outcome"] == ("service-present" if services else "missing-service"),
            "service-match mismatch",
        )
        for service in services:
            for result in service["openResults"]:
                client_type = result["clientType"]
                status = result["ioReturn"]
                outcome = result["outcome"]
                open_name = (
                    f"IOServiceOpen({kind}:{service['registryID']},type:{client_type})"
                )
                expected_names.add(open_name)
                require_iokit(open_name, status, outcome)
                close_name = (
                    f"IOServiceClose({kind}:{service['registryID']},type:{client_type})"
                )
                if status == 0:
                    expected_names.add(close_name)
                    close = observed.get(close_name)
                    require(close is not None and type(close["ioReturn"]) is int, "missing close")
                    require(
                        close["outcome"] == iokit_outcome(close["ioReturn"]),
                        "close outcome",
                    )
                else:
                    require(close_name not in observed, "unexpected close")

    private_names = (
        "IOUSBDeviceControllerCreate",
        "IOUSBDeviceControllerGetTypeID",
        "IOUSBDeviceDescriptionCreateFromController",
        "IOUSBDeviceDescriptionGetTypeID",
    )
    create = observed.get(private_names[0])
    require(create is not None and type(create["ioReturn"]) is int, "controller create")
    for name in private_names[1:]:
        require(
            name in observed and "ioReturn" not in observed[name],
            "private operation status",
        )
    symbols = {item["name"]: item for item in document["symbols"]}
    for name in READ_ONLY_SYMBOLS - set(private_names):
        require(symbols[name]["invoked"] is False, "unexpected read-only invocation")

    create_available = symbols[private_names[0]]["available"]
    controller_type_available = symbols[private_names[1]]["available"]
    description_create_available = symbols[private_names[2]]["available"]
    description_type_available = symbols[private_names[3]]["available"]

    def private_state_matches(
        controller_created: bool,
        controller_type_matches: bool,
        description_created: bool,
        description_type_matches: bool,
    ) -> bool:
        if controller_created and (not create_available or create["ioReturn"] != 0):
            return False
        if controller_type_matches and not (controller_created and controller_type_available):
            return False
        if description_created and not (controller_created and description_create_available):
            return False
        if description_type_matches and not (description_created and description_type_available):
            return False

        invoked = {
            private_names[0]: create_available,
            private_names[1]: controller_created and controller_type_available,
            private_names[2]: controller_created and description_create_available,
            private_names[3]: description_created and description_type_available,
        }
        if any(symbols[name]["invoked"] is not invoked[name] for name in private_names):
            return False

        if not create_available:
            if create["ioReturn"] != -536870201:
                return False
            create_outcome = "missing-symbol"
        elif create["ioReturn"] != 0:
            create_outcome = iokit_outcome(create["ioReturn"])
        elif not controller_type_available or not controller_type_matches:
            create_outcome = "controller-abi-mismatch"
        elif not description_create_available or not description_created:
            create_outcome = "description-unavailable"
        elif not description_type_available or not description_type_matches:
            create_outcome = "description-abi-mismatch"
        else:
            create_outcome = "read-only-description-validated"

        controller_type_outcome = (
            "missing-symbol" if not controller_type_available else
            "not-invoked" if not controller_created else
            "type-match" if controller_type_matches else "abi-mismatch"
        )
        description_create_outcome = (
            "missing-symbol" if not description_create_available else
            "not-invoked" if not controller_created else
            "description-created" if description_created else "description-unavailable"
        )
        description_type_outcome = (
            "missing-symbol" if not description_type_available else
            "not-invoked" if not description_created else
            "type-match" if description_type_matches else "abi-mismatch"
        )
        return (
            create["outcome"] == create_outcome
            and observed[private_names[1]]["outcome"] == controller_type_outcome
            and observed[private_names[2]]["outcome"] == description_create_outcome
            and observed[private_names[3]]["outcome"] == description_type_outcome
        )

    require(
        any(private_state_matches(*state) for state in itertools.product((False, True), repeat=4)),
        "unreachable private readback state",
    )
    require(set(observed) == expected_names, "operation set")


def topology_fingerprint(document: dict[str, object]) -> str:
    controllers = []
    for source in document["controllers"]:
        controller = dict(source)
        controller["openResults"] = sorted(
            (dict(item) for item in source["openResults"]),
            key=lambda item: (item["clientType"], item["ioReturn"]),
        )
        controller["userClientClasses"] = sorted(source["userClientClasses"])
        controllers.append(controller)
    controllers.sort(key=lambda item: (item["registryID"], item["name"]))

    functions = []
    for source in document["functions"]:
        function = dict(source)
        function["openResults"] = sorted(
            (dict(item) for item in source["openResults"]),
            key=lambda item: (item["clientType"], item["ioReturn"]),
        )
        function["userClientClasses"] = sorted(source["userClientClasses"])
        functions.append(function)
    functions.sort(key=lambda item: (item["registryID"], item["name"]))

    snapshot = {
        "configuration": document["configuration"],
        "controllers": controllers,
        "entitlements": sorted(document["entitlements"], key=lambda item: item["name"]),
        "functions": functions,
        "operations": sorted(document["operations"], key=lambda item: item["name"]),
        "schemaVersion": document["schemaVersion"],
        "symbols": sorted(document["symbols"], key=lambda item: item["name"]),
        "target": document["target"],
    }
    canonical = json.dumps(
        snapshot,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def validate(
    document: dict[str, object],
    variant: str,
    peer: str,
    orientation: str,
    power: str,
) -> None:
    exact_keys(document, REPORT_KEYS, "report")
    require(document["schemaVersion"] == 1, "schema")
    require(isinstance(document["capturedAt"], str) and CAPTURED_AT.fullmatch(document["capturedAt"]), "capture time")
    require(isinstance(document["topologyFingerprint"], str) and HEX64.fullmatch(document["topologyFingerprint"]), "topology")

    target = exact_keys(document["target"], TARGET_KEYS, "target")
    expected_target = {
        "boardIdentifier": "J620AP",
        "dopamineBuild": "3.0.12-1",
        "portFamily": "thunderbolt-usb4",
        "productType": "iPad14,5",
        "soc": "T8112",
        "trollStoreBuild": "2.1.1",
    }
    for key, expected in expected_target.items():
        require(target[key] == expected, "target identity")
    safe_text(target["osVersion"])
    safe_text(target["osBuild"])

    role = exact_keys(document["role"], ROLE_KEYS, "role")
    peer_label = (
        "mac2jb-generic-capture-host-primary"
        if peer == "capture-host"
        else "mac2jb-nintendo-switch-primary"
    )
    require(role["peerKind"] == peer and role["orientation"] == orientation, "role")
    require(role["powerState"] == power and type(role["controllerPresent"]) is bool, "role state")
    require(role["peerIdentity"] == expected_hash(peer_label), "peer hash")
    require(
        role["cableIdentity"] == expected_hash("mac2jb-known-good-usbc-cable-primary"),
        "cable hash",
    )

    configuration = keys_with_optional(
        document["configuration"],
        {"path"},
        {"deviceTreeConfiguration", "sha256"},
        "configuration",
    )
    require(
        configuration["path"] == "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist",
        "configuration path",
    )
    if "sha256" in configuration:
        digest = configuration["sha256"]
        require(isinstance(digest, str) and HEX64.fullmatch(digest), "configuration digest")
    if "deviceTreeConfiguration" in configuration:
        tree_value = configuration["deviceTreeConfiguration"]
        require(isinstance(tree_value, str), "device-tree configuration")
        safe_text(tree_value, maximum=4096)

    validate_services(document)
    require(
        role["controllerPresent"] is bool(document["controllers"]),
        "controller presence",
    )
    validate_symbols(document)
    validate_entitlements(document, variant)
    validate_operations(document)
    require(
        document["topologyFingerprint"] == topology_fingerprint(document),
        "topology fingerprint",
    )


def run(arguments: list[str]) -> int:
    if len(arguments) != 5:
        print(
            "Usage: validate-probe-stdout.py REPORT VARIANT PEER ORIENTATION POWER_STATE",
            file=sys.stderr,
        )
        return 64
    report, variant, peer, orientation, power = arguments
    if variant not in {"baseline", "setdescription", "controller-client", "interface-client"}:
        return 64
    if peer not in {"capture-host", "switch"} or orientation not in {"a", "b"}:
        return 64
    if power not in {
        "operator-observed-vbus-charging",
        "operator-observed-vbus-not-charging",
        "operator-observed-no-vbus",
        "operator-not-observed",
    }:
        return 64
    try:
        data, document = read_report(Path(report))
        validate(document, variant, peer, orientation, power)
    except (OSError, Rejection, ValueError):
        print("Probe stdout rejected; no report was accepted.", file=sys.stderr)
        return 65
    report_hash = hashlib.sha256(data[:-1]).hexdigest()
    print(f"PASS probe report {report_hash} {document['topologyFingerprint']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
