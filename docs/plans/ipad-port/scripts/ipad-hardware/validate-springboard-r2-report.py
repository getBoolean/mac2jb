#!/usr/bin/env python3
"""Validate one private app-container R2 report, excluding physical-role claims.

The collector intentionally labels peer, cable, orientation, and power as
unattributed. This validator reuses the audited stdout report's exact schema,
IOKit status, operation, symbol, entitlement, and topology checks; it accepts
only those fixed unattributed labels and the fixed R2 app build metadata.
It reads ignored mode-0600 local evidence and emits summary categories only.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[5]
BASE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/validate-probe-stdout.py"
BASE_SHA = "7afa3421436d1598809f81c06629792cb41830b668e03f913c841adfe75455a9"


def run(label, round_number):
    if hashlib.sha256(BASE.read_bytes()).hexdigest() != BASE_SHA:
        raise ValueError("base validator changed")
    spec = importlib.util.spec_from_file_location("u1_r2_base", BASE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    path = ROOT / f"build/ipad-hardware/springboard-r2-{label}-round-{round_number}.json"
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or not 1 < info.st_size <= 1_048_576:
        raise ValueError("unsafe private report")
    data = path.read_bytes()
    if not data.startswith(b"{") or not data.endswith(b"}") or b"\0" in data or len(data) != info.st_size:
        raise ValueError("invalid report framing")
    document = json.loads(data.decode("utf-8"), object_pairs_hook=module.reject_duplicate_pairs)
    module.exact_keys(document, module.REPORT_KEYS, "report")
    module.require(document["schemaVersion"] == 1, "schema")
    module.require(isinstance(document["capturedAt"], str) and module.CAPTURED_AT.fullmatch(document["capturedAt"]), "capture time")
    module.require(isinstance(document["topologyFingerprint"], str) and module.HEX64.fullmatch(document["topologyFingerprint"]), "topology")
    target = module.exact_keys(document["target"], module.TARGET_KEYS, "target")
    expected = {"boardIdentifier": "J620AP", "dopamineBuild": "3.0.12", "portFamily": "thunderbolt-usb4", "productType": "iPad14,5", "soc": "T8112", "trollStoreBuild": "2.1.1"}
    module.require(all(target[k] == value for k, value in expected.items()), "target tuple")
    module.safe_text(target["osVersion"])
    module.safe_text(target["osBuild"])
    role = module.exact_keys(document["role"], module.ROLE_KEYS, "role")
    module.require(role["peerKind"] == "unattributed" and role["orientation"] == "unknown" and role["powerState"] == "unobserved", "unattributed role")
    module.require(role["peerIdentity"] == module.expected_hash("springboard-admission-only") and role["cableIdentity"] == module.expected_hash("unattributed"), "unattributed hashes")
    module.require(type(role["controllerPresent"]) is bool and role["controllerPresent"] is bool(document["controllers"]), "controller presence")
    configuration = module.keys_with_optional(document["configuration"], {"path"}, {"deviceTreeConfiguration", "sha256"}, "configuration")
    module.require(configuration["path"] == "/System/Library/AppleUSBDevice/USBDeviceConfiguration.plist", "configuration path")
    if "sha256" in configuration:
        module.require(isinstance(configuration["sha256"], str) and module.HEX64.fullmatch(configuration["sha256"]), "configuration digest")
    if "deviceTreeConfiguration" in configuration:
        module.safe_text(configuration["deviceTreeConfiguration"], maximum=4096)
    module.validate_services(document)
    module.validate_symbols(document)
    module.validate_entitlements(document, label)
    module.validate_operations(document)
    module.require(document["topologyFingerprint"] == module.topology_fingerprint(document), "topology fingerprint")
    counts = (len(document["controllers"]), len(document["functions"]), len(document["operations"]))
    print(f"SPRINGBOARD_R2_REPORT_VALID profile={label} round={round_number} controllers={counts[0]} functions={counts[1]} operations={counts[2]} topology={document['topologyFingerprint']}")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in ("baseline", "setdescription") or not re.fullmatch(r"[1-9][0-9]?", sys.argv[2]):
            raise ValueError("unexpected arguments")
        run(sys.argv[1], sys.argv[2])
    except Exception:
        print("SPRINGBOARD_R2_REPORT_VALID rejected", file=sys.stderr)
        raise SystemExit(1)
