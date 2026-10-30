#!/usr/bin/env python3
"""Mac-only baseline gate and offline assessment for one future v4 repeat.

`--fixture` classifies retained v4/v7 lifecycle and postcheck evidence. It
requires a first arrival and exact 16-field live shape for strict success.
`--capture` writes an owner-only Mac baseline after a new stock boot; the
target queries are read-only. `--preflight` checks the active journal, boot,
baseline and external USB. No mode publishes, restores, confirms, archives,
loads a service, or writes a device file.
"""

import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import runpy
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
BUILD = ROOT / "build/ipad-hardware"
TRIALS = BUILD / "u2-trials"
V4 = TRIALS / "run-v4-1793374389603740000-0da211de"
V7 = TRIALS / "run-v7-1793393526875167000-b9aa62fa"
V7_BASELINE = BUILD / "u2-v7-baseline/snapshot.json"
REPEAT_BASELINE = BUILD / "u2-v4-repeat-baseline"
V4_BINARY = BUILD / "u2-native-noop-trial-v4-clone"
V4_SHA256 = "cedaa71736aaf0d27f886b5cade552bfd6ee5ff3fde4e9c8eaaac071a8db34c7"
PRIOR_JOURNAL_BACKUP = (BUILD / "u2-v7-journal-backup" /
                        "restore-journal.awaiting-verification-v7.json")
PRIOR_JOURNAL_SHA256 = "0f265fd17847a9db1a1bc6814e39e7da94fd1eaef6e736811e3d618af1bbb02e"
V4_LIFECYCLE_SHA256 = "c4dd0bce00b3dd67599fa5b8ae0a3b01b7ea1fb2fa27cc2679795e7b1433295a"
V7_LIFECYCLE_SHA256 = "26ca031b7556242fb4b752b037277a3d8c55a08b1a202d91109359e44baadf4a"
V4_POSTCHECK_SHA256 = "c07e819c995e9ed8f89864dbb7e63dcc5fc9c2bc1da47682129355390001168e"
V4_CLIENT_SHA256 = "44a240580b2b65ecde77949e64dce95cace8a39f84b162be23f1803f020c906e"
JOURNAL = HOST / "run-u2-readonly-default-description-wifi.py"
REPEAT_NAMES = {"snapshot.json", "raw-configs.bin", "host-interfaces.json",
                "host-usb-scalars.json", "strings.bin", "power.txt",
                "host-network.json"}
PACKET_OK = (b"U2_NCM_PACKET peer=one-linklocal echo=reply "
             b"link=active usbmux=one ssh=healthy\n")
POWER_OK = {
    b"POWER_SOURCE query=ok external=yes charging=yes full=no\n",
    b"POWER_SOURCE query=ok external=yes charging=yes full=yes\n",
    b"POWER_SOURCE query=ok external=yes charging=no full=yes\n",
}


def checked(path, digest, limit):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= limit):
        raise ValueError("unsafe evidence file")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("evidence digest changed")
    return data


def lifecycle(data):
    records = [json.loads(line) for line in data.splitlines()]
    if not records or records[0].get("type") != "ready":
        raise ValueError("monitor was not armed")
    summary = [row for row in records if row.get("type") == "summary"]
    if (len(summary) != 1 or summary[0].get("windowCompleted") is not True or
            summary[0].get("eventsTruncated") is not False):
        raise ValueError("incomplete monitor")
    events = [row for row in records if row.get("type") == "event"]
    if summary[0].get("eventCount") != len(events):
        raise ValueError("event count mismatch")
    arrivals = [row for row in events if row.get("kind") == "arrived"]
    terminations = [row for row in events if row.get("kind") == "terminated"]
    first_arrival = bool(arrivals and terminations and
                         arrivals[0].get("elapsedNanoseconds", -1) >
                         terminations[0].get("elapsedNanoseconds", -1))
    return {"first_arrival": first_arrival, "arrivals": len(arrivals),
            "terminations": len(terminations)}


def strict_postcheck(data):
    lines = data.decode("ascii").splitlines()
    if not lines or not (lines[0].startswith("U2_V4_CURRENT ") or
                         lines[0].startswith("U2_V7_CURRENT ")):
        raise ValueError("invalid postcheck")
    tokens = dict(item.split("=", 1) for item in lines[0].split()[1:]
                  if "=" in item)
    required = {"boot": "same", "live": "original", "configs": "5",
                "resolved-strings": "23", "interfaces": "equal",
                "scalars": "equal", "network-binding": "equal",
                "network-packet": "reply", "usbmux": "one",
                "pairing": "valid", "power": "charging-or-full",
                "journal": "awaitingVerification"}
    semantic = all(tokens.get(key) == value for key, value in required.items()
                   if key != "live")
    return (semantic, semantic and tokens.get("live") == "original" and
            tokens.get("renumbered") == "0")


def classify(monitor_data, client_data, postcheck_data, monitor_exit, client_exit):
    monitor = lifecycle(monitor_data)
    if postcheck_data == b"U2_V4_REPEAT_POSTCHECK unavailable\n":
        semantic, strict = False, False
    else:
        semantic, strict = strict_postcheck(postcheck_data)
    client_ok = (client_exit == 0 and
                 b"U2_NOOP_CLIENT publication=success\n" in client_data and
                 b"U2_NOOP_CLIENT recovery=awaitingVerification\n" in client_data)
    v4_like = (monitor_exit in (0, 65) and monitor["first_arrival"] and
               client_ok and semantic)
    strict_recovery = v4_like and strict
    return {"first_arrival": monitor["first_arrival"], "semantic": semantic,
            "strict": strict, "client_ok": client_ok, "v4_like": v4_like,
            "strict_recovery": strict_recovery}


def fixture():
    v4_monitor = checked(V4 / "lifecycle.ndjson", V4_LIFECYCLE_SHA256, 8192)
    v7_monitor = checked(V7 / "lifecycle.ndjson", V7_LIFECYCLE_SHA256, 8192)
    fake_broker = checked(V4 / "client.txt", V4_CLIENT_SHA256, 1024)
    semantic_post = checked(V4 / "postcheck.txt", V4_POSTCHECK_SHA256, 1024)
    v4 = classify(v4_monitor, fake_broker, semantic_post, 0, 0)
    # Counterfactual: even a successful broker and semantic postcheck cannot
    # make the v7 trace pass when its first arrival never occurred.
    missing_arrival = classify(v7_monitor, fake_broker, semantic_post, 0, 0)
    if not (v4["first_arrival"] and v4["semantic"] and not v4["strict"] and
            v4["v4_like"] and not v4["strict_recovery"] and
            not missing_arrival["first_arrival"] and
            missing_arrival["client_ok"] and missing_arrival["semantic"] and
            not missing_arrival["v4_like"] and
            not missing_arrival["strict_recovery"]):
        raise ValueError("retained fixture behavior changed")
    print("U2_V4_REPEAT_FIXTURE v4-first-arrival=yes v4-semantic=yes "
          "v4-like=yes strict=no fake-broker-v7-first-arrival=no "
          "fake-broker-v7-like=no confirmation=never")


def journal_absent():
    result = subprocess.run(["/usr/bin/python3", str(JOURNAL), "--native-journal"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=20)
    if result.returncode or result.stdout != b"U2_NATIVE_JOURNAL phase=absent sha256=none\n":
        raise ValueError("active journal or journal status unavailable")


def preserved_prior_journal():
    directory = PRIOR_JOURNAL_BACKUP.parent.lstat()
    info = PRIOR_JOURNAL_BACKUP.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or
            stat.S_IMODE(directory.st_mode) != 0o700 or
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("prior failed journal backup unsafe")
    checked(PRIOR_JOURNAL_BACKUP, PRIOR_JOURNAL_SHA256, 2_000_000)


def archived_v7_attested():
    archive = runpy.run_path(str(HOST / "archive-u2-v7-old-boot-journal-wifi.py"))
    output = io.StringIO()
    with redirect_stdout(output):
        archive["main"]("--verify")
    if output.getvalue() != "U2_V7_OLD_JOURNAL verified=exact active=absent external=equal\n":
        raise ValueError("v7 old-boot archive not independently verified")


def new_boot():
    recovery = runpy.run_path(str(HOST / "diagnose-u2-recovery-stage.py"))
    current_boot = recovery["read_boot_token"]()
    prior = runpy.run_path(str(HOST / "check-u2-v7-current.py"))["reference"]()
    v7_boot = json.loads(prior["snapshot.json"])["snapshot"]["identity"]["boot_session"]
    if not re.fullmatch(r"[0-9a-f]{64}", current_boot) or current_boot == v7_boot:
        raise ValueError("new boot not established")
    return current_boot, prior


def capture_one(boot, old, journal_check=journal_absent):
    checker = runpy.run_path(str(HOST / "check-u2-v7-current.py"))
    snapshot = runpy.run_path(str(HOST / "capture-u2-private-baseline.py"))
    current = snapshot["capture"]()
    now = current["snapshot"]
    previous = json.loads(old["snapshot.json"])["snapshot"]
    old_live = base64.b64decode(previous["live_b64"], validate=True)
    live = base64.b64decode(now["live_b64"], validate=True)
    if (now["identity"]["boot_session"] != boot or
            any(now["identity"][key] != previous["identity"][key]
                for key in ("product_type", "os_build", "source_sha256")) or
            checker["live_equals"](old_live, live) != "original"):
        raise ValueError("new boot or stock live description changed")
    raw, strings, interfaces, scalars, drivers = checker["capture_external"]()
    comparison = checker["SEMANTIC"]["compare"](
        old["raw-configs.bin"], old["strings.bin"], raw, strings)
    if comparison["configurations"] != 5:
        raise ValueError("USB configurations changed")
    checker["host_interfaces"](old["host-interfaces.json"], interfaces)
    canonical = checker["CHECK"]["canonical"]
    if canonical(scalars) != old["host-usb-scalars.json"]:
        raise ValueError("USB scalars changed")
    if drivers != (1, 4):
        raise ValueError("NCM driver binding missing")
    packet = subprocess.run(
        ["/usr/bin/python3", str(HOST / "probe-u2-ncm-packet-flow.py")],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if packet.returncode or packet.stdout != PACKET_OK:
        raise ValueError("NCM packet flow missing")
    power = runpy.run_path(str(HOST / "check-u2-power-wifi.py"))["capture"]()
    if power not in POWER_OK:
        raise ValueError("external power missing")
    journal_check()
    if new_boot()[0] != boot:
        raise ValueError("boot changed during capture")
    checker["PROBE"]["host_usb_ready"]()
    return {
        "snapshot.json": canonical(current),
        "raw-configs.bin": raw,
        "host-interfaces.json": canonical(interfaces),
        "host-usb-scalars.json": canonical(scalars),
        "strings.bin": strings,
        "power.txt": power,
        "host-network.json": canonical(
            {"ethernet": drivers[0], "ncm_driver": drivers[1]}),
    }


def exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short private write")
        os.fsync(fd)
    finally:
        os.close(fd)


def capture_baseline():
    if REPEAT_BASELINE.exists() or REPEAT_BASELINE.is_symlink():
        raise ValueError("repeat baseline already exists")
    preserved_prior_journal()
    journal_absent()
    archived_v7_attested()
    boot, old = new_boot()
    first = capture_one(boot, old)
    journal_absent()
    if first != capture_one(boot, old):
        raise ValueError("repeat baseline unstable")
    journal_absent()
    if new_boot()[0] != boot:
        raise ValueError("boot changed before baseline save")
    canonical = runpy.run_path(str(HOST / "check-u2-external-current.py"))["canonical"]
    manifest = canonical({
        "version": 1, "purpose": "u2-v4-repeat",
        "v7_archive_verified": True,
        "prior_v7_manifest_sha256":
            "9757d3853759fc7f5da9260560ae3828a1f369c808ef7dae2d9342bad0295dfb",
        "files": {name: hashlib.sha256(data).hexdigest()
                  for name, data in sorted(first.items())},
    })
    REPEAT_BASELINE.mkdir(mode=0o700)
    for name, data in first.items():
        exclusive(REPEAT_BASELINE / name, data)
    exclusive(REPEAT_BASELINE / "manifest.json", manifest)
    fd = os.open(REPEAT_BASELINE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print("U2_V4_REPEAT_BASELINE captured=stable boot=new stock=16 "
          "journal=absent usb=ready network-packet=reply")
    print("U2_V4_REPEAT_BASELINE manifest-sha256=" +
          hashlib.sha256(manifest).hexdigest())


def preflight(expected_manifest):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_manifest):
        raise ValueError("explicit manifest digest required")
    checked(V4_BINARY, V4_SHA256, 4 * 1024 * 1024)
    preserved_prior_journal()
    journal_absent()  # Stop before any baseline or device state read on current v7 boot.
    current_boot, _ = new_boot()
    info = REPEAT_BASELINE.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("fresh repeat baseline missing")
    manifest_path = REPEAT_BASELINE / "manifest.json"
    manifest_bytes = checked(manifest_path, expected_manifest, 2048)
    manifest = json.loads(manifest_bytes)
    if (manifest.get("version") != 1 or manifest.get("purpose") != "u2-v4-repeat" or
            manifest.get("v7_archive_verified") is not True or
            manifest.get("prior_v7_manifest_sha256") !=
            "9757d3853759fc7f5da9260560ae3828a1f369c808ef7dae2d9342bad0295dfb" or
            set(manifest.get("files", {})) != REPEAT_NAMES):
        raise ValueError("repeat baseline manifest invalid")
    if set(p.name for p in REPEAT_BASELINE.iterdir()) != (
            set(manifest["files"]) | {"manifest.json"}):
        raise ValueError("repeat baseline files changed")
    for name, digest in manifest["files"].items():
        info = (REPEAT_BASELINE / name).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("unsafe repeat baseline file")
        checked(REPEAT_BASELINE / name, digest, 1024 * 1024)
    baseline = json.loads((REPEAT_BASELINE / "snapshot.json").read_bytes())
    saved_boot = baseline["snapshot"]["identity"]["boot_session"]
    live = base64.b64decode(baseline["snapshot"]["live_b64"], validate=True)
    if (saved_boot != current_boot or not isinstance(plistlib.loads(live), dict) or
            len(plistlib.loads(live)) != 16):
        raise ValueError("repeat baseline boot or stock shape changed")
    checker = runpy.run_path(str(HOST / "check-u2-v7-current.py"))
    # Check the current external state against the new private baseline. The
    # established checker is used only for read-only capture/comparison.
    checker["main"].__globals__["BASE"] = REPEAT_BASELINE
    checker["main"].__globals__["MANIFEST_SHA256"] = hashlib.sha256(
        manifest_path.read_bytes()).hexdigest()
    output = io.StringIO()
    with redirect_stdout(output):
        checker["main"]("absent")
    line = output.getvalue()
    if (not line.startswith("U2_V7_CURRENT boot=same live=original ") or
            " renumbered=0 " not in line or
            " network-packet=reply usbmux=one pairing=valid " not in line or
            not line.endswith(" journal=absent\n")):
        raise ValueError("strict external preflight failed")
    return expected_manifest, line.encode("ascii")


def assess(trial_path, receipt_digest):
    if not re.fullmatch(r"[0-9a-f]{64}", receipt_digest):
        raise ValueError("explicit receipt digest required")
    path = Path(trial_path)
    if (path.parent.resolve() != TRIALS.resolve() or
            not re.fullmatch(r"repeat-v4-[0-9]+-[0-9a-f]{8}", path.name)):
        raise ValueError("invalid repeat evidence path")
    details = path.lstat()
    if (not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid() or
            stat.S_IMODE(details.st_mode) != 0o700):
        raise ValueError("unsafe repeat evidence directory")
    receipt = json.loads(checked(path / "receipt.json", receipt_digest, 2048))
    if (receipt.get("version") != 1 or receipt.get("mode") != "normal" or
            set(receipt.get("files", {})) != {
                "precheck.txt", "client.txt", "lifecycle.ndjson", "postcheck.txt"} or
            set(p.name for p in path.iterdir()) != set(receipt["files"]) | {"receipt.json"}):
        raise ValueError("repeat evidence incomplete")
    files = {name: checked(path / name, digest, 8192)
             for name, digest in receipt["files"].items()}
    verdict = classify(files["lifecycle.ndjson"], files["client.txt"],
                       files["postcheck.txt"], receipt.get("monitor_exit"),
                       receipt.get("client_exit"))
    print("U2_V4_REPEAT_ASSESS first-arrival=" +
          ("yes" if verdict["first_arrival"] else "no") +
          " semantic=" + ("yes" if verdict["semantic"] else "no") +
          " v4-like=" + ("yes" if verdict["v4_like"] else "no") +
          " strict-recovery=" +
          ("yes" if verdict["strict_recovery"] else "no") +
          " confirmation=never")
    if not verdict["strict_recovery"]:
        raise ValueError("strict repeat criteria unmet")


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--fixture"]:
            fixture()
        elif sys.argv[1:] == ["--capture"]:
            capture_baseline()
        elif len(sys.argv) == 2 and sys.argv[1].startswith("--preflight="):
            preflight(sys.argv[1].split("=", 1)[1])
            print("U2_V4_REPEAT_PREFLIGHT ready=yes boot=new baseline=pinned "
                  "stock=16 journal=absent external=strict")
        elif (len(sys.argv) == 3 and sys.argv[1].startswith("--assess=") and
              sys.argv[2].startswith("--receipt-sha256=")):
            assess(sys.argv[1].split("=", 1)[1],
                   sys.argv[2].split("=", 1)[1])
        else:
            raise ValueError("invalid mode")
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            UnicodeError, subprocess.TimeoutExpired, json.JSONDecodeError,
            plistlib.InvalidFileException):
        print("U2_V4_REPEAT rejected; no controller command or confirmation issued")
        raise SystemExit(1)
