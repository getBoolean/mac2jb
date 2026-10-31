#!/usr/bin/env python3
"""Run one bounded, externally observed U2 no-op/restore trial.

Requires the separate enabled trial launchd service already staged. The Mac
first verifies the exact private baseline and absent journal, arms the passive
IOUSBHostDevice lifecycle monitor, then sends a pinned socket client over
independent Wi-Fi SSH. The client requests only the journaled original
description; normal, worker-death, and watchdog-restart modes exercise three
recovery paths. After the monitor window, the Mac requires full descriptor,
USBMux/trust, charging, and journal equivalence before the separate confirmer
can remove the journal. Private mode-0600 trial evidence is retained even on
failure. If restoration cannot be verified, it stops with the journal intact.
"""

import hashlib
import json
import os
from pathlib import Path
import plistlib
import secrets
import select
import shlex
import stat
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
BUILD = ROOT / "build/ipad-hardware"
TRIALS = BUILD / "u2-trials"
CHECKER = HOST / "check-u2-external-current.py"
CONFIRM = HOST / "confirm-u2-restoration-wifi.py"
CLIENT = DEVICE / "u2-native-noop-trial-client.py"
CLIENT_SHA256 = "543657394bc548e6a40c35f8de4ba59ddee86edeb94213c6a9973074a8f82902"
MONITOR = HOST / "u1-usb-event-monitor.swift"
MONITOR_SHA256 = "da900b13b41435fc13f7e596f1ed76c88079ad04edd8733440d2a75406079199"
SCALARS = BUILD / "u2-baseline/host-usb-scalars.json"
WIRELESS = HOST / "check-pinned-wireless-ssh.py"
HELPER = HOST / "backup-clienttruth-over-root-ssh.py"
WINDOW_SECONDS = 20


def checked(path, digest, maximum):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= maximum):
        raise ValueError("unsafe trial input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("trial input changed")
    return data


def check_external(phase):
    result = subprocess.run(
        ["/usr/bin/python3", str(CHECKER), "--expect-journal=" + phase],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if (result.returncode != 0 or len(result.stdout) > 512 or
            ("journal=" + phase + "\n").encode("ascii") not in result.stdout):
        raise ValueError("external state or journal did not recover")
    return result.stdout


def ssh():
    import runpy
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe private address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    return ["/usr/bin/ssh", *helper["ssh_options"](),
            "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
            "-o", "AddressFamily=inet", "-T", "-p", "22", "root@" + address]


def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short private evidence write")
        os.fsync(fd)
    finally:
        os.close(fd)


def make_trial_dir():
    TRIALS.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(TRIALS.stat().st_mode) != 0o700:
        raise ValueError("unsafe trial directory")
    trial = TRIALS / ("run-" + str(time.time_ns()) + "-" + secrets.token_hex(4))
    trial.mkdir(mode=0o700)
    return trial


def monitor_binary(temporary):
    binary = Path(temporary) / "u2-usb-observer"
    result = subprocess.run(
        ["/usr/bin/xcrun", "swiftc", str(MONITOR), "-o", str(binary)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30,
        env=dict(os.environ, CLANG_MODULE_CACHE_PATH=str(Path(temporary) / "clang"),
                 SWIFT_MODULE_CACHE_PATH=str(Path(temporary) / "swift")))
    if result.returncode != 0 or not binary.is_file():
        raise ValueError("passive monitor compile failed")
    return binary


def arm_monitor(binary, vendor, product):
    process = subprocess.Popen(
        [str(binary), f"0x{vendor:04x}", f"0x{product:04x}", str(WINDOW_SECONDS)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    ready = b""
    try:
        available, _, _ = select.select([process.stdout], [], [], 8)
        if available:
            ready = process.stdout.readline()
        record = json.loads(ready)
        if (record.get("type") != "ready" or
                record.get("windowSeconds") != WINDOW_SECONDS or
                record.get("target", {}).get("vendorID") != f"0x{vendor:04x}" or
                record.get("target", {}).get("productID") != f"0x{product:04x}"):
            raise ValueError("monitor target not ready")
        return process, ready
    except BaseException:
        process.kill()
        process.communicate(timeout=3)
        raise


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in (
            "normal", "worker-kill", "watchdog-kill"):
        raise ValueError("invalid trial mode")
    mode = sys.argv[1]
    checked(CLIENT, CLIENT_SHA256, 16 * 1024)
    checked(MONITOR, MONITOR_SHA256, 32 * 1024)
    pre = check_external("absent")
    fields = json.loads(SCALARS.read_bytes())["fields"]
    vendor = fields["idVendor"]
    product = fields["idProduct"]
    if not (0 < vendor <= 65535 and 0 < product <= 65535):
        raise ValueError("invalid target scalar")
    command = ssh()
    source = CLIENT.read_bytes().decode("ascii")
    remote_base = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source)
    ready = subprocess.run([*command, remote_base + " status"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=12)
    if ready.returncode != 0 or ready.stdout != b"U2_NOOP_CLIENT service=ready\n":
        raise ValueError("trial service not armed")
    trial = make_trial_dir()
    private_file(trial / "precheck.txt", pre)
    client_result = None
    monitor_result = b""
    monitor_exit = None
    with tempfile.TemporaryDirectory(prefix="u2-monitor-", dir=BUILD) as temporary:
        binary = monitor_binary(temporary)
        process, ready = arm_monitor(binary, vendor, product)
        try:
            remote = remote_base + " " + mode
            try:
                client_result = subprocess.run(
                    [*command, remote], stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, timeout=12)
            except subprocess.TimeoutExpired:
                client_result = None
        finally:
            try:
                tail, _ = process.communicate(timeout=WINDOW_SECONDS + 5)
                monitor_result = ready + tail
                monitor_exit = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                tail, _ = process.communicate(timeout=3)
                monitor_result = ready + tail
                monitor_exit = -1
    private_file(trial / "lifecycle.ndjson", monitor_result)
    client_output = client_result.stdout if client_result is not None else b""
    if len(client_output) > 1024:
        client_output = b"U2_NOOP_CLIENT oversized-output\n"
    private_file(trial / "client.txt", client_output)
    try:
        records = [json.loads(line) for line in monitor_result.splitlines()]
        summaries = [item for item in records if item.get("type") == "summary"]
        summary = summaries[0] if len(summaries) == 1 else {}
    except (ValueError, TypeError):
        summary = {}
    client_ok = (client_result is not None and
                 client_result.returncode == (17 if mode == "worker-kill" else 0) and
                 b"U2_NOOP_CLIENT publication=success\n" in client_output and
                 (mode == "worker-kill" or
                  b"U2_NOOP_CLIENT recovery=awaitingVerification\n" in client_output))
    try:
        post = check_external("awaitingVerification")
    except ValueError:
        print("U2_NOOP_TRIAL recovery-unverified; journal retained; private evidence=" +
              trial.name)
        raise
    private_file(trial / "postcheck.txt", post)
    confirmed = subprocess.run(
        ["/usr/bin/python3", str(CONFIRM)], stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=70)
    if confirmed.returncode != 0 or not confirmed.stdout.startswith(
            b"U2_RESTORE_CONFIRM external=equal broker=verified journal=absent"):
        raise ValueError("external confirmation rejected; preserve journal and evidence")
    private_file(trial / "confirm.txt", confirmed.stdout)
    event_count = summary.get("eventCount")
    complete = summary.get("windowCompleted") is True and monitor_exit in (0, 65)
    print("U2_NOOP_TRIAL mode=" + mode + " publication=" +
          ("success" if client_ok else "unverified") + " recovery=verified " +
          "monitor=" + ("complete" if complete else "partial") +
          " events=" + str(event_count if isinstance(event_count, int) else "unknown") +
          " private-evidence=" + trial.name)
    if not client_ok or not complete:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            json.JSONDecodeError, subprocess.TimeoutExpired):
        print("U2_NOOP_TRIAL rejected; inspect journal and private evidence")
        raise SystemExit(1)
