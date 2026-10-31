#!/usr/bin/env python3
"""Validate platform-entitled U1 reports with the pinned strict report model.

What this Mac-local code does: pin the existing full JSON report validator,
reuse its parsing, schema, target, role, symbol, operation, and topology
checks, and supply only the two new exact entitlement profiles. It emits the
same digest/fingerprint receipt after every check passes. It never contacts
the iPad or changes a device file.
"""

import hashlib
import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[5]
BASE_PATH = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/validate-probe-stdout.py"
BASE_SHA = "7afa3421436d1598809f81c06629792cb41830b668e03f913c841adfe75455a9"


def main():
    if len(sys.argv) != 6:
        raise SystemExit(64)
    report, variant, peer, orientation, power = sys.argv[1:]
    if variant not in ("platform-only", "platform-setdescription"):
        raise SystemExit(64)
    if peer not in ("capture-host", "switch") or orientation not in ("a", "b"):
        raise SystemExit(64)
    if power not in (
        "operator-observed-vbus-charging", "operator-observed-vbus-not-charging",
        "operator-observed-no-vbus", "operator-not-observed",
    ):
        raise SystemExit(64)
    if hashlib.sha256(BASE_PATH.read_bytes()).hexdigest() != BASE_SHA:
        raise SystemExit(65)
    spec = importlib.util.spec_from_file_location("u1_platform_report_base", BASE_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(65)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    def entitlement_profile(name):
        profile = {key: False for key in module.ENTITLEMENTS}
        profile["platform-application"] = True
        if name == "platform-setdescription":
            profile["com.apple.private.usbdevice.setdescription"] = True
        return profile

    module.entitlement_profile = entitlement_profile
    try:
        data, document = module.read_report(Path(report))
        module.validate(document, variant, peer, orientation, power)
    except (OSError, module.Rejection, ValueError):
        print("Admission probe stdout rejected.", file=sys.stderr)
        raise SystemExit(65)
    content_sha = hashlib.sha256(data[:-1]).hexdigest()
    print("PASS probe report " + content_sha + " " + document["topologyFingerprint"])


if __name__ == "__main__":
    main()
