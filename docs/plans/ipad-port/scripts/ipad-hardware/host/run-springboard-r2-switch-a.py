#!/usr/bin/env python3
"""Capture the ordinary R2 profile pair on owner-confirmed direct Switch 2 A.

This Mac wrapper verifies pinned Go runner sources and prior private reports,
requires the Mac to have no raw iPad USB node, and reads controller bus/power
categories over pinned Wi-Fi before and after the run. It uses the attested
R2 runner to clear only each app's captured round-6 report by full digest,
run round 7, clear that exact report, and run round 8. Each app performs only
read-only IOKit calls and writes one bounded file in its own app container.
The wrapper verifies all eight retained rounds per app, keeps raw output in
ignored mode-0600 files, and exclusively writes one private binding manifest.
It never changes USB, SSH, trust, or system files. The peer and A orientation
come from the owner's physical observation, not from the app's static labels.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[6]
BUILD = ROOT / "build/ipad-hardware"
RUNNER = ROOT / "scripts/ipad-hardware/host/run-springboard-r2-report-wifi.go"
BUS = ROOT / "scripts/ipad-hardware/host/run-readonly-controller-property-keys-wifi.go"
DIAG = ROOT / "scripts/ipad-hardware/host/diagnose-usb-recognition.py"
VALIDATOR = ROOT / "scripts/ipad-hardware/validate-springboard-r2-report.py"
PINS = {
    RUNNER: "68243722bb93a2762161f3b8e30295e55c3b5479f586b532c9981dd2942475c3",
    BUS: "23edcd4c78c2fb941885baad1fbe3a85566ca4c4466c87cc5f5b771a5451db39",
    DIAG: "98323936396b1e56749e98aba8ec6dfba2d08cbac6d67f0c85de3165c81876ff",
    VALIDATOR: "00a6ca00cde30be22d3a6257fafdeb4e11c9f3e3e8d6a65e17dc51cd3d25cc3d",
}
OUTPUT = BUILD / "springboard-r2-switch2-a-binding.json"
FINGERPRINT = re.compile(rb"^SPRINGBOARD_R2_REPORT_VALID profile=(baseline|setdescription) round=([1-8]) controllers=1 functions=16 operations=42 topology=([0-9a-f]{64})\n$")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(args, timeout, environment=None):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, env=environment)
    require(result.returncode == 0 and len(result.stdout) <= 4096, "bounded command failed")
    return result.stdout


def validate(label, number):
    result = command(["/opt/homebrew/bin/python3", "-I", "-S", "-B", str(VALIDATOR),
                      label, str(number)], 15)
    match = FINGERPRINT.fullmatch(result)
    require(match is not None and match.group(1).decode() == label and
            int(match.group(2)) == number, "R2 report validation failed")
    report = BUILD / f"springboard-r2-{label}-round-{number}.json"
    data = report.read_bytes()
    require(0 < len(data) <= 1_048_576, "private report extent")
    return match.group(3).decode(), hashlib.sha256(data).hexdigest()


def usb_absent():
    result = command(["/opt/homebrew/bin/python3", "-I", "-S", "-B", str(DIAG)], 10)
    require(b"IOREG raw-ipad=no " in result and b"IOREG ios-service=absent\n" in result,
            "Mac still has an iPad USB node")


def state(binary):
    bus = command([str(binary), "--bus"], 20)
    power = command([str(binary), "--power"], 20)
    require(bus == b"CONTROLLER_BUS query=ok state=configured onbus=yes speed=4 config=1\n",
            "Switch-side controller not configured/on-bus")
    require(power == b"POWER_SOURCE query=ok external=yes charging=no full=no\n",
            "Switch-side external-power state changed")
    return {"bus": bus.decode().strip(), "power": power.decode().strip()}


def main():
    require(len(sys.argv) == 1, "no arguments accepted")
    require(not OUTPUT.exists() and not OUTPUT.is_symlink(), "Switch A binding already exists")
    for path, expected in PINS.items():
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, "pinned source changed")
    prior = {label: [validate(label, number) for number in range(1, 7)]
             for label in ("baseline", "setdescription")}
    require(all(len({row[0] for row in rows}) == 1 for rows in prior.values()),
            "prior R2 rounds disagree")
    usb_absent()
    with tempfile.TemporaryDirectory(prefix="mac2jb-r2-switch-a-", dir=BUILD) as folder:
        temp = Path(folder)
        go_env = os.environ.copy()
        go_env["GOCACHE"] = str(BUILD / "go-cache")
        r2_binary = temp / "r2-runner"
        bus_binary = temp / "bus-runner"
        for source, target in ((RUNNER, r2_binary), (BUS, bus_binary)):
            command(["/opt/homebrew/bin/go", "vet", str(source)], 30, go_env)
            command(["/opt/homebrew/bin/go", "build", "-o", str(target), str(source)], 30, go_env)
        before = state(bus_binary)
        for label in ("baseline", "setdescription"):
            for action in ("clear6", "round7", "clear7", "round8"):
                output = command([str(r2_binary), label, action], 20)
                if action.startswith("clear"):
                    require(output == f"SPRINGBOARD_R2_CLEAR profile={label} verified\n".encode(),
                            "R2 clear receipt invalid")
                else:
                    require(output.startswith(f"SPRINGBOARD_R2_LAUNCH profile={label} status=accepted\nSPRINGBOARD_R2_CAPTURE profile={label} bytes=".encode()) and
                            len(output.splitlines()) == 2, "R2 capture receipt invalid")
        after = state(bus_binary)
        usb_absent()
        reports = {}
        for label in ("baseline", "setdescription"):
            rows = [validate(label, number) for number in range(1, 9)]
            require(len({row[0] for row in rows}) == 1, "R2 topology changed")
            reports[label] = {"topologyFingerprint": rows[0][0],
                              "reportSha256ByRound": {str(i): row[1]
                                                      for i, row in enumerate(rows, 1)}}
        for path, expected in PINS.items():
            require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                    "pinned source changed during run")
        manifest = {"schemaVersion": 1, "peer": "switch-2", "orientation": "a",
                    "plugSideAtIPad": "no-logo", "operatorObservedCharging": "not-charging",
                    "operatorConfirmedConnection": True, "controlTransport": "pinned-wifi-ssh",
                    "macUsbIpadNode": "absent-before-and-after", "before": before, "after": after,
                    "runnerSourceSha256": PINS[RUNNER], "busSourceSha256": PINS[BUS],
                    "validatorSourceSha256": PINS[VALIDATOR], "reports": reports}
        data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        fd = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            require(os.write(fd, data) == len(data), "partial private binding")
            os.fsync(fd)
        finally:
            os.close(fd)
        print("SPRINGBOARD_R2_SWITCH_A accepted profiles=two rounds=two-each bus=configured-onbus power=external-not-charging")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("SPRINGBOARD_R2_SWITCH_A rejected; inspect app reports before retry", file=sys.stderr)
        raise SystemExit(1)
