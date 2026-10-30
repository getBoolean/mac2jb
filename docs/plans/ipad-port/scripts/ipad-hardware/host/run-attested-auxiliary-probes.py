#!/usr/bin/env python3
"""Run the two executable-admitted U1 client probes with private host evidence.

What this code does: revalidate the installed toolbox attestation, pin the
durable SSH key and host record, run the existing read-only device launcher
twice for each fixed controller/interface client variant, and validate every
JSON report. It stores raw validated reports only under ignored, mode-0700
Mac build storage. It prints fixed statuses and report fingerprints, never
raw registry data or device identifiers. It creates no iPad file and does
not invoke USB or registry mutation APIs.

The baseline and set-description variants are excluded because their no-arg
startup checks received SIGKILL before main; this runner is partial U1
evidence, not a gate pass or a substitute for the full four-variant batch.
With no arguments it preserves the original A/unobserved capture name and
refuses to overwrite it. Explicit arguments select an observed A or B
orientation, one fixed power label, and an optional short capture label for a
new, separately named capture. The operator must physically confirm the cable
orientation before invocation; a label alone is not physical evidence.
An optional final `--wifi` uses the separately pinned, privately stored iPad
Wi-Fi address to control the probe while its USB cable stays on the Mac host.
An optional `--peer=switch` after `--wifi` selects the Switch keyboard-screen
row; it also refuses to run while the Mac still sees an iPad on USB. The
operator must still verify that the cable is actually on the Switch.
With leading `--admission`, the same bounded runner uses the separately
attested platform-only and platform-plus-setdescription app, retaining the
baseline/setdescription report labels. This mode requires Wi-Fi control and
allows power to remain explicitly unobserved for an admission-only run.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
backup = runpy.run_path(str(HERE / "backup-clienttruth-over-root-ssh.py"))
batch = runpy.run_path(str(ROOT / "scripts/ipad-hardware/run-installed-toolbox-authorization-batch.py"))
LAUNCHER = ROOT / "scripts/ipad-hardware/device/u1-readonly-run-installed-toolbox-probe.sh"
VALIDATOR = ROOT / "scripts/ipad-hardware/validate-probe-stdout.py"
ATTESTATION_VALIDATOR = ROOT / "scripts/ipad-hardware/validate-installed-toolbox-trollstore.py"
ADMISSION_LAUNCHER = ROOT / "scripts/ipad-hardware/device/u1-readonly-run-installed-admission-probe.sh"
ADMISSION_LAUNCHER_SHA = "908fa735b0913a1e2b292f6b4fd954384b789dc0a0f17c1b449d5192e9947788"
ADMISSION_ATTEST = ROOT / "scripts/ipad-hardware/validate-installed-admission.py"
ADMISSION_ATTEST_SHA = "44253da2171adc936aab5b552442862a26289432184904de0b412122b6ed69d1"
ADMISSION_MANIFEST = ROOT / "build/ipad-hardware/installed-admission-attestation.json"
ADMISSION_REPORT_VALIDATOR = ROOT / "scripts/ipad-hardware/validate-admission-probe-stdout.py"
ADMISSION_REPORT_VALIDATOR_SHA = "b5d285c3ccda54873ff7f3373d692bc1ce7bd1b24ae296aba80335c3ad82995c"
BUILD = ROOT / "build/ipad-hardware"
VARIANTS = ("controller-client", "interface-client")
POWERS = ("operator-observed-vbus-charging", "operator-observed-vbus-not-charging",
          "operator-observed-no-vbus", "operator-not-observed")
CAPTURE_LABEL = re.compile(r"[a-z0-9][a-z0-9-]{0,39}\Z")
RECEIPT = re.compile(rb"PASS probe report ([0-9a-f]{64}) ([0-9a-f]{64})\n")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def checked_source(path, digest):
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == digest, "local input digest mismatch")
    return data


def main():
    admission = len(sys.argv) > 1 and sys.argv[1] == "--admission"
    if admission:
        require(len(sys.argv) > 2, "admission mode needs an explicit peer row")
        sys.argv.pop(1)
    if len(sys.argv) == 1:
        orientation, power = "a", "operator-not-observed"
        label = ""
        wireless = False
    elif (len(sys.argv) in (3, 4, 5, 6) and sys.argv[1] in ("a", "b")
          and sys.argv[2] in POWERS and
          (len(sys.argv) == 3 or CAPTURE_LABEL.fullmatch(sys.argv[3]))
          and (len(sys.argv) < 5 or sys.argv[4] == "--wifi")
          and (len(sys.argv) != 6 or sys.argv[5] == "--peer=switch")):
        orientation, power = sys.argv[1:3]
        label = "" if len(sys.argv) == 3 else "-" + sys.argv[3]
        wireless = len(sys.argv) >= 5
        peer = "switch" if len(sys.argv) == 6 else "capture-host"
    else:
        raise SystemExit("Usage: run-attested-auxiliary-probes.py [a|b POWER_STATE [CAPTURE_LABEL [--wifi [--peer=switch]]]]")
    if len(sys.argv) == 1:
        peer = "capture-host"
    if peer == "switch":
        require(label.startswith("-observed-" + orientation + "-") and
                (power != "operator-not-observed" or admission),
                "Switch row requires observed orientation; ordinary mode also requires power")
        usb_diagnostic = runpy.run_path(str(HERE / "diagnose-usb-recognition.py"))
        raw = usb_diagnostic["read"](["/usr/sbin/ioreg", "-p", "IOUSB", "-l", "-w0"])
        require(raw is not None and raw.returncode == 0 and
                not usb_diagnostic["first_ipad_subtree"](
                    raw.stdout.decode("utf-8", "replace").splitlines()),
                "Mac still sees an iPad on USB or cannot classify USB tree")
    if admission:
        require(wireless, "admission mode requires pinned Wi-Fi control")
    output = BUILD / (("admission-probe-" if admission else "auxiliary-probe-") +
                      peer + "-" + orientation + "-" + power +
                      label + ("-wifi-control" if wireless else ""))
    backup["checked_local"](backup["IDENTITY"], backup["IDENTITY_SHA256"], 0o600)
    backup["checked_local"](backup["KNOWN_HOSTS"], backup["KNOWN_HOSTS_SHA256"], 0o600)
    if wireless:
        address = runpy.run_path(str(HERE / "check-pinned-wireless-ssh.py"))["read_address"]()
        require(address is not None, "private pinned Wi-Fi address unavailable")
        ssh_target = "mobile@" + address
        ssh_port = "22"
        extra_ssh_options = ["-o", "HostKeyAlias=[127.0.0.1]:2222",
                             "-o", "AddressFamily=inet"]
    else:
        ssh_target = "mobile@127.0.0.1"
        ssh_port = "2222"
        extra_ssh_options = []
    require(not output.exists() and not output.is_symlink(), "output already exists")
    launcher_path = ADMISSION_LAUNCHER if admission else LAUNCHER
    launcher_sha = ADMISSION_LAUNCHER_SHA if admission else batch["EXPECTED_LAUNCHER_SHA"]
    launcher = checked_source(launcher_path, launcher_sha)
    report_validator = ADMISSION_REPORT_VALIDATOR if admission else VALIDATOR
    checked_source(report_validator, (ADMISSION_REPORT_VALIDATOR_SHA if admission else
                                      batch["EXPECTED_REPORT_VALIDATOR_SHA"]))
    if admission:
        checked_source(ADMISSION_ATTEST, ADMISSION_ATTEST_SHA)
    else:
        checked_source(ATTESTATION_VALIDATOR, batch["EXPECTED_ATTESTATION_VALIDATOR_SHA"])
    scratch = Path(tempfile.mkdtemp(prefix="mac2jb-u1-aux-", dir=BUILD))
    try:
        scratch.chmod(0o700)
        if admission:
            attested = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(ADMISSION_ATTEST), "--check"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=20)
            require(attested.returncode == 0 and attested.stdout ==
                    b"ADMISSION_ATTEST code=matched entitlements=matched layout=exact\n",
                    "admission attestation failed")
            manifest = json.loads(ADMISSION_MANIFEST.read_bytes())
            code = manifest["code"]
            admission_variants = {
                "platform-only": "mac2jb-u1-platform-only",
                "platform-setdescription": "Probes/mac2jb-u1-platform-setdescription",
            }
            require(manifest["status"] == "installed-code-and-entitlements-matched" and
                    set(code) == set(admission_variants.values()),
                    "admission manifest shape changed")
            hashes = {name: code[name]["binarySha256"] for name in code}
            require(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()),
                    "admission binary hashes invalid")
            variants = tuple(admission_variants)
        else:
            _manifest_sha, hashes = batch["validate_attestation"](
                ATTESTATION_VALIDATOR, scratch)
            variants = VARIANTS
            admission_variants = {}
        records = []
        for variant in variants:
            executable = (admission_variants[variant] if admission else
                          batch["VARIANTS"][variant])
            for round_number in (1, 2):
                remote = batch["remote_command"](
                    variant, peer, orientation, power, hashes[executable])
                command = ["/usr/bin/ssh", *backup["ssh_options"](),
                           *extra_ssh_options, "-T", "-p", ssh_port,
                           ssh_target, remote]
                result = subprocess.run(command, input=launcher,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=45)
                require(result.returncode == 0 and 0 < len(result.stdout) <= 2097152,
                        "probe failed: " + variant + " round " + str(round_number) +
                        " status " + str(result.returncode))
                name = variant + "-round-" + str(round_number) + ".json"
                report = scratch / name
                fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW, 0o600)
                try:
                    require(os.write(fd, result.stdout) == len(result.stdout),
                            "short local report write")
                    os.fsync(fd)
                finally:
                    os.close(fd)
                validate = subprocess.run(
                    ["/usr/bin/python3", "-I", "-S", str(report_validator),
                     str(report), variant, peer, orientation, power],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, timeout=10)
                match = RECEIPT.fullmatch(validate.stdout)
                require(validate.returncode == 0 and match is not None,
                        "report validator rejected " + variant)
                content_sha = hashlib.sha256(result.stdout.rstrip(b"\n")).hexdigest()
                require(content_sha == match.group(1).decode("ascii"),
                        "report receipt digest mismatch")
                records.append({"variant": variant, "round": round_number,
                                "file": name, "sha256": content_sha,
                                "topologyFingerprint": match.group(2).decode("ascii")})
                print(("ADMISSION_PROBE " if admission else "AUX_PROBE ") +
                      variant + " round=" + str(round_number) + " valid")
        for variant in variants:
            fingerprints = [r["topologyFingerprint"] for r in records
                            if r["variant"] == variant]
            require(len(fingerprints) == 2 and fingerprints[0] == fingerprints[1],
                    "topology changed between rounds for " + variant)
        manifest = scratch / "partial-manifest.json"
        manifest.write_text(json.dumps(records, sort_keys=True, indent=2) + "\n")
        manifest.chmod(0o600)
        os.rename(scratch, output)
        print(("ADMISSION_PROBE accepted " if admission else "AUX_PROBE accepted ") +
              str(output))
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)


if __name__ == "__main__":
    main()
