#!/usr/bin/env python3
"""Check one preserved U1 authorization batch and emit a redacted summary.

What this code does:
1. Opens one local batch directory without following symlinks and requires the
   exact eight report files plus ``batch-manifest.json`` produced by the
   reviewed authorization runner.
2. Pins and executes the already-read bytes of the reviewed stdout validator,
   revalidates every report,
   checks every manifest/report digest, and requires two equal topology
   fingerprints for each of the four entitlement variants.
3. Emits one deterministic JSON document to stdout containing the target and
   role labels, evidence digests, service counts, raw IOReturn classifications,
   private-readback outcomes, and entitlement/symbol availability needed to
   fill the U1 authorization matrix.

This is a Mac-local, read-only evidence summarizer. It opens no network socket,
runs no subprocess, executes no SSH command, writes no file, and cannot contact
or change the iPad. Raw registry reports remain in ignored build storage. The
summary deliberately omits registry IDs, service names, ancestry, restore
properties, and device-tree values; their validated raw evidence stays local.

Important provenance limit: current batch manifests and probe reports are not
cryptographically authenticated. This tool proves only that local bytes are
self-consistent with the reviewed schemas and hashes. Its output is labeled
unauthenticated and cannot, by itself, prove that the reviewed runner executed
twice or satisfy U1. Preserve the private raw capture and corroborating host
evidence until the signed capability-record contract is implemented.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
VALIDATOR_PATH = SCRIPT_DIRECTORY / "validate-probe-stdout.py"
EXPECTED_VALIDATOR_SHA256 = "7afa3421436d1598809f81c06629792cb41830b668e03f913c841adfe75455a9"
EXPECTED_LAUNCHER_SHA256 = "53f86a362b585077d11cbe97417cf12a7fa8f9c9c61d9867cd7836b78c06110c"
MAX_VALIDATOR_SIZE = 2 * 1024 * 1024
MAX_MANIFEST_SIZE = 256 * 1024
MAX_REPORT_SIZE = 2 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}")
VARIANTS = (
    "baseline",
    "setdescription",
    "controller-client",
    "interface-client",
)
PEERS = {"capture-host", "switch"}
ORIENTATIONS = {"a", "b"}
POWERS = {
    "operator-observed-vbus-charging",
    "operator-observed-vbus-not-charging",
    "operator-observed-no-vbus",
    "operator-not-observed",
}
PRIVATE_READBACK = (
    "IOUSBDeviceControllerCreate",
    "IOUSBDeviceControllerGetTypeID",
    "IOUSBDeviceDescriptionCreateFromController",
    "IOUSBDeviceDescriptionGetTypeID",
)


class Rejection(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejection(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Rejection("duplicate JSON key")
        result[key] = value
    return result


def read_fd(descriptor: int, maximum: int) -> bytes:
    status = os.fstat(descriptor)
    require(
        stat.S_ISREG(status.st_mode)
        and status.st_nlink == 1
        and 0 < status.st_size <= maximum,
        "unsafe evidence file",
    )
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        total += len(chunk)
        require(total <= maximum, "evidence file exceeded cap")
        chunks.append(chunk)
    data = b"".join(chunks)
    require(len(data) == status.st_size, "evidence file extent changed")
    return data


def read_regular(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        return read_fd(descriptor, maximum)
    finally:
        os.close(descriptor)


def read_child(directory: int, name: str, maximum: int) -> bytes:
    require("/" not in name and name not in {"", ".", ".."}, "unsafe evidence name")
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=directory,
    )
    try:
        return read_fd(descriptor, maximum)
    finally:
        os.close(descriptor)


def decode_json(data: bytes, *, terminal_newline: bool) -> dict[str, object]:
    payload = data
    if terminal_newline:
        require(data.endswith(b"\n") and not data.endswith(b"\n\n"), "JSON framing")
        payload = data[:-1]
    require(payload.startswith(b"{") and payload.endswith(b"}") and b"\0" not in payload, "JSON object framing")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejection("invalid JSON") from error
    require(isinstance(value, dict), "JSON root")
    return value


def load_validator() -> object:
    data = read_regular(VALIDATOR_PATH, MAX_VALIDATOR_SIZE)
    require(sha256(data) == EXPECTED_VALIDATOR_SHA256, "validator digest drift")
    module = types.ModuleType("mac2jb_u1_stdout_validator")
    module.__file__ = "<pinned mac2jb stdout validator>"
    code = compile(
        data,
        module.__file__,
        "exec",
        dont_inherit=True,
        optimize=0,
    )
    exec(code, module.__dict__)
    return module


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    require(isinstance(value, dict) and set(value) == expected, f"{label} keys")
    return value


def hex_digest(value: object, label: str) -> str:
    require(isinstance(value, str) and HEX64.fullmatch(value) is not None, label)
    return value


def aggregate_opens(services: object) -> list[dict[str, object]]:
    require(isinstance(services, list), "service list")
    counts: dict[tuple[int, int, str], int] = {}
    for service in services:
        require(isinstance(service, dict) and isinstance(service.get("openResults"), list), "service open results")
        for result in service["openResults"]:
            require(isinstance(result, dict), "open result")
            key = (result["clientType"], result["ioReturn"], result["outcome"])
            counts[key] = counts.get(key, 0) + 1
    return [
        {
            "clientType": client_type,
            "count": counts[(client_type, io_return, outcome)],
            "ioReturn": io_return,
            "outcome": outcome,
        }
        for client_type, io_return, outcome in sorted(counts)
    ]


def variant_summary(
    variant: str,
    document: dict[str, object],
    records: list[dict[str, object]],
) -> dict[str, object]:
    operations = {
        item["name"]: item
        for item in document["operations"]
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    readback: dict[str, dict[str, object]] = {}
    for name in PRIVATE_READBACK:
        operation = operations.get(name)
        require(isinstance(operation, dict), "private readback operation")
        result: dict[str, object] = {"outcome": operation["outcome"]}
        if "ioReturn" in operation:
            result["ioReturn"] = operation["ioReturn"]
        readback[name] = result

    configuration = document["configuration"]
    require(isinstance(configuration, dict), "configuration")
    return {
        "availableSymbols": sorted(
            item["name"] for item in document["symbols"] if item["available"]
        ),
        "configuration": {
            "deviceTreeConfigurationObserved": "deviceTreeConfiguration" in configuration,
            "sha256": configuration.get("sha256"),
        },
        "controllerCount": len(document["controllers"]),
        "controllerOpenResults": aggregate_opens(document["controllers"]),
        "entitlementsPresent": sorted(
            item["name"] for item in document["entitlements"] if item["present"]
        ),
        "functionCount": len(document["functions"]),
        "linkedFunctionCount": sum(
            1 for item in document["functions"] if "controllerRegistryID" in item
        ),
        "functionOpenResults": aggregate_opens(document["functions"]),
        "privateReadback": readback,
        "reportSha256": [record["sha256"] for record in records],
        "topologyFingerprint": records[0]["topologyFingerprint"],
        "unresolvedFunctionCount": sum(
            1 for item in document["functions"] if "controllerRegistryID" not in item
        ),
        "variant": variant,
    }


def summarize(directory_path: Path) -> dict[str, object]:
    validator = load_validator()
    directory = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root_status = os.fstat(directory)
        require(stat.S_ISDIR(root_status.st_mode), "batch directory")
        manifest_data = read_child(directory, "batch-manifest.json", MAX_MANIFEST_SIZE)
        manifest = decode_json(manifest_data, terminal_newline=True)
        require(
            manifest_data
            == (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("ascii"),
            "noncanonical batch manifest",
        )
        exact_keys(
            manifest,
            {
                "attestationManifestSha256",
                "launcherSha256",
                "reportValidatorSha256",
                "reports",
                "schemaVersion",
            },
            "batch manifest",
        )
        require(
            manifest["schemaVersion"] == 1
            and manifest["launcherSha256"] == EXPECTED_LAUNCHER_SHA256
            and manifest["reportValidatorSha256"] == EXPECTED_VALIDATOR_SHA256,
            "batch tool identity",
        )
        attestation_sha = hex_digest(
            manifest["attestationManifestSha256"],
            "attestation manifest digest",
        )
        records_value = manifest["reports"]
        require(isinstance(records_value, list) and len(records_value) == 8, "report records")

        records: dict[tuple[str, int], dict[str, object]] = {}
        expected_names = {"batch-manifest.json"}
        for value in records_value:
            record = exact_keys(
                value,
                {"file", "round", "sha256", "topologyFingerprint", "variant"},
                "report record",
            )
            variant = record["variant"]
            round_number = record["round"]
            require(
                variant in VARIANTS
                and type(round_number) is int
                and round_number in {1, 2},
                "report identity",
            )
            expected_name = f"{variant}-round-{round_number}.json"
            require(record["file"] == expected_name, "report filename")
            hex_digest(record["sha256"], "report digest")
            hex_digest(record["topologyFingerprint"], "topology digest")
            key = (variant, round_number)
            require(key not in records, "duplicate report record")
            records[key] = record
            expected_names.add(expected_name)
        require(
            set(records) == {(variant, round_number) for variant in VARIANTS for round_number in (1, 2)},
            "report record set",
        )
        require(set(os.listdir(directory)) == expected_names, "batch directory layout")

        documents: dict[tuple[str, int], dict[str, object]] = {}
        common_role: dict[str, object] | None = None
        common_target: dict[str, object] | None = None
        peer = orientation = power = ""
        for key, record in records.items():
            data = read_child(directory, record["file"], MAX_REPORT_SIZE)
            require(
                data.endswith(b"\n")
                and not data.endswith(b"\n\n")
                and sha256(data[:-1]) == record["sha256"],
                "report bytes",
            )
            document = decode_json(data, terminal_newline=True)
            role = document.get("role")
            target = document.get("target")
            require(isinstance(role, dict) and isinstance(target, dict), "report identity")
            if common_role is None:
                common_role = role
                common_target = target
                peer = role.get("peerKind", "")
                orientation = role.get("orientation", "")
                power = role.get("powerState", "")
                require(
                    peer in PEERS
                    and orientation in ORIENTATIONS
                    and power in POWERS,
                    "unsupported role",
                )
            require(role == common_role and target == common_target, "mixed batch identity")
            try:
                validator.validate(document, key[0], peer, orientation, power)
            except Exception as error:
                raise Rejection("report validation") from error
            require(
                document["topologyFingerprint"] == record["topologyFingerprint"],
                "manifest topology digest",
            )
            documents[key] = document

        require(common_role is not None and common_target is not None, "empty batch")
        variant_rows: list[dict[str, object]] = []
        for variant in VARIANTS:
            first_record = records[(variant, 1)]
            second_record = records[(variant, 2)]
            require(
                first_record["topologyFingerprint"] == second_record["topologyFingerprint"],
                "unstable topology",
            )
            variant_rows.append(
                variant_summary(
                    variant,
                    documents[(variant, 1)],
                    [first_record, second_record],
                )
            )

        require(set(os.listdir(directory)) == expected_names, "batch directory changed")
        role_summary = {
            "cableIdentity": common_role["cableIdentity"],
            "controllerPresent": common_role["controllerPresent"],
            "orientation": common_role["orientation"],
            "peerIdentity": common_role["peerIdentity"],
            "peerKind": common_role["peerKind"],
            "powerState": common_role["powerState"],
        }
        return {
            "evidenceStatus": "unauthenticated-local-self-consistency-check",
            "provenance": {
                "authenticated": False,
                "limitation": (
                    "The batch manifest and reports are not signed; this summary "
                    "does not prove that the reviewed runner produced them."
                ),
            },
            "role": role_summary,
            "schemaVersion": 1,
            "source": {
                "assertedAttestationManifestSha256": attestation_sha,
                "assertedLauncherSha256": EXPECTED_LAUNCHER_SHA256,
                "batchManifestSha256": sha256(manifest_data),
                "localReportValidatorSha256": EXPECTED_VALIDATOR_SHA256,
            },
            "target": common_target,
            "topologyComparison": "equal-within-unauthenticated-capture",
            "variants": variant_rows,
        }
    finally:
        os.close(directory)


def run(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print(
            "Usage: summarize-u1-authorization-batch.py CAPTURE_DIRECTORY",
            file=sys.stderr,
        )
        return 64
    try:
        result = summarize(Path(arguments[0]))
    except (OSError, Rejection, UnicodeError, ValueError):
        print("Authorization evidence rejected; no summary was emitted.", file=sys.stderr)
        return 65
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
