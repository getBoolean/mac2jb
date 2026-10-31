#!/usr/bin/env python3
"""One future v4 normal repeat with passive Mac USB observation.

Requires a fresh, externally pinned repeat baseline and already staged exact v4
service. This program makes the one explicitly requested controller call only in
--run-normal mode. It retains private evidence and never confirms or clears the
journal, even if the external check passes. Do not run on the v7 off-bus boot.
"""

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BUILD = ROOT / "build/ipad-hardware"
TRIALS = BUILD / "u2-trials"
BASE = BUILD / "u2-v4-repeat-baseline"
AUDIT = runpy.run_path(str(HOST / "audit-u2-v4-repeat.py"))
LEGACY = runpy.run_path(str(HOST / "run-u2-native-noop-trial-v4-wifi.py"))


def exact_service():
    checked = LEGACY["checked"]
    status_source = checked(LEGACY["STATUS"], LEGACY["STATUS_SHA256"], 16 * 1024)
    client_source = checked(LEGACY["CLIENT"], LEGACY["CLIENT_SHA256"], 16 * 1024)
    checked(LEGACY["MONITOR"], LEGACY["MONITOR_SHA256"], 32 * 1024)
    command = LEGACY["ssh"]()
    status_remote = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(
        status_source.decode("ascii")) + " --status"
    result = subprocess.run([*command, status_remote], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=12)
    if result.returncode or result.stdout != (
            b"U2_TRIAL_V4 job=loaded running=yes binary=exact plist=exact "
            b"socket=responding phase=absent publication=enabled archives=retained\n"):
        raise ValueError("exact v4 service unavailable")
    remote_base = ("/var/jb/usr/bin/python3 -I -S -B -c " +
                   shlex.quote(client_source.decode("ascii")))
    ready = subprocess.run([*command, remote_base + " status"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=12)
    if ready.returncode or ready.stdout != b"U2_NOOP_CLIENT service=ready\n":
        raise ValueError("v4 service not ready")
    return command, remote_base


def check_after(manifest_digest):
    checker = runpy.run_path(str(HOST / "check-u2-v7-current.py"))
    checker["main"].__globals__["BASE"] = BASE
    checker["main"].__globals__["MANIFEST_SHA256"] = manifest_digest
    output = io.StringIO()
    with redirect_stdout(output):
        checker["main"]("awaitingVerification")
    result = output.getvalue().encode("ascii")
    if len(result) > 1024 or b" journal=awaitingVerification\n" not in result:
        raise ValueError("external postcheck malformed")
    return result


def one_trial(manifest_digest):
    _, precheck = AUDIT["preflight"](manifest_digest)
    command, remote_base = exact_service()
    fields = json.loads((BASE / "host-usb-scalars.json").read_bytes())["fields"]
    vendor, product = fields["idVendor"], fields["idProduct"]
    if not (isinstance(vendor, int) and isinstance(product, int) and
            0 < vendor <= 65535 and 0 < product <= 65535):
        raise ValueError("invalid target scalar")
    TRIALS.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(TRIALS.stat().st_mode) != 0o700:
        raise ValueError("unsafe trial directory")
    trial = TRIALS / ("repeat-v4-" + str(time.time_ns()) + "-" + secrets.token_hex(4))
    trial.mkdir(mode=0o700)
    private = LEGACY["private_file"]
    private(trial / "precheck.txt", precheck)
    monitor_result = b""
    monitor_exit = None
    client_result = None
    with tempfile.TemporaryDirectory(prefix="u2-repeat-monitor-", dir=BUILD) as temporary:
        binary = LEGACY["monitor_binary"](temporary)
        process, ready = LEGACY["arm_monitor"](binary, vendor, product)
        try:
            try:
                client_result = subprocess.run(
                    [*command, remote_base + " normal"], stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, timeout=30)
            except subprocess.TimeoutExpired:
                pass
        finally:
            try:
                tail, _ = process.communicate(timeout=LEGACY["WINDOW_SECONDS"] + 5)
                monitor_exit = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                tail, _ = process.communicate(timeout=3)
                monitor_exit = -1
            monitor_result = ready + tail
    private(trial / "lifecycle.ndjson",
            monitor_result if len(monitor_result) <= 8192 else
            b"U2_V4_REPEAT_MONITOR oversized\n")
    client = client_result.stdout if client_result is not None else b""
    private(trial / "client.txt",
            client if len(client) <= 8192 else b"U2_V4_REPEAT_CLIENT oversized\n")
    try:
        postcheck = check_after(manifest_digest)
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        postcheck = b"U2_V4_REPEAT_POSTCHECK unavailable\n"
    private(trial / "postcheck.txt", postcheck)
    names = ("precheck.txt", "client.txt", "lifecycle.ndjson", "postcheck.txt")
    receipt = json.dumps({
        "version": 1, "mode": "normal", "baseline_manifest_sha256": manifest_digest,
        "client_exit": client_result.returncode if client_result is not None else None,
        "monitor_exit": monitor_exit,
        "files": {name: hashlib.sha256((trial / name).read_bytes()).hexdigest()
                  for name in names},
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    private(trial / "receipt.json", receipt)
    digest = hashlib.sha256(receipt).hexdigest()
    print("U2_V4_REPEAT evidence=" + trial.name + " receipt-sha256=" + digest +
          " journal=retained confirmation=never")
    AUDIT["assess"](str(trial), digest)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or not sys.argv[1].startswith("--run-normal="):
            raise ValueError("exact run mode and manifest digest required")
        digest = sys.argv[1].split("=", 1)[1]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid baseline manifest digest")
        one_trial(digest)
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            UnicodeError, subprocess.TimeoutExpired, json.JSONDecodeError):
        print("U2_V4_REPEAT rejected; journal and private evidence retained")
        raise SystemExit(1)
