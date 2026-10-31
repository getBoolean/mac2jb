#!/usr/bin/env python3
"""Try one bounded ForceOffBus(true/false) edge over pinned root Wi-Fi SSH.

Requires the exact post-restore journal and durable Mac backup, same boot,
off-bus controller, absent Mac USB, and a live v4 broker in the awaiting phase.
A private Mac one-shot marker is created before sending the fixed device source.
The Mac passively observes USB return and independently checks full functions.
No retry, journal confirmation, reboot, or iPad file write occurs here.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import select
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
BUILD = ROOT / "build/ipad-hardware"
TRIALS = BUILD / "u2-trials"
SOURCE = DEVICE / "u2-forceoff-edge-once.py"
SOURCE_SHA = "7539203753a3ca098058d324e69b4c9e04242a263954431bdb9235f910b6c5d2"
BACKUP = BUILD / "u2-v7-journal-backup/restore-journal.awaiting-verification-v7.json"
JOURNAL_SHA = "0f265fd17847a9db1a1bc6814e39e7da94fd1eaef6e736811e3d618af1bbb02e"
MONITOR = HOST / "u2-usb-return-observer.py"
MONITOR_SHA = "70d926bed4494205ce3f1731e8977e4ac7e0d1ceb81244d615135e82b16b2660"
STATE = HOST / "read-u2-controller-state-keys-wifi.py"
STATE_SHA = "33f7cc8a2da7a090737a4dfea35b2580ee17ebaab57841e1c961c95713d84e22"
CHECKER = runpy.run_path(str(HOST / "check-u2-v7-current.py"))
RECOVERY = runpy.run_path(str(HOST / "diagnose-u2-recovery-stage.py"))


def checked(path, digest, maximum, private=False):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= maximum or
            (private and (info.st_uid != os.getuid() or
                          stat.S_IMODE(info.st_mode) != 0o600))):
        raise ValueError("unsafe exact input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("exact input changed")
    return data


def ssh():
    wireless = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
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


def preflight(command):
    source = checked(SOURCE, SOURCE_SHA, 16 * 1024)
    checked(BACKUP, JOURNAL_SHA, 2_000_000, private=True)
    checked(MONITOR, MONITOR_SHA, 16 * 1024)
    checked(STATE, STATE_SHA, 16 * 1024)
    reference = CHECKER["reference"]()
    boot = json.loads(reference["snapshot.json"])["snapshot"]["identity"]["boot_session"]
    if (RECOVERY["read_boot_token"]() != boot or
            CHECKER["journal"]("awaitingVerification") != JOURNAL_SHA):
        raise ValueError("same-boot journal changed")
    bus = subprocess.run(["/opt/homebrew/bin/go", "run", str(
        HOST / "run-readonly-controller-property-keys-wifi.go"), "--bus"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if bus.returncode or bus.stdout != (
            b"CONTROLLER_BUS query=ok state=disconnected onbus=no speed=4 config=0\n"):
        raise ValueError("controller state changed")
    state = subprocess.run(["/usr/bin/python3", str(STATE)], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=20)
    if (state.returncode or
            b"CONTROLLER_STATE link=L0 (Normal)\n" not in state.stdout or
            b"CONTROLLER_STATE SelectedConfiguration=0\n" not in state.stdout or
            b"CONTROLLER_STATE force-off-symbol=present\n" not in state.stdout):
        raise ValueError("force-off preflight changed")
    usb = subprocess.run(["/usr/bin/python3", str(HOST / "diagnose-usb-recognition.py")],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
    if usb.returncode or b"USBMUX query=ok count=0\nIOREG raw-ipad=no " not in usb.stdout:
        raise ValueError("Mac USB already returned")
    status_source = b"import socket\ns=socket.socket(socket.AF_UNIX)\ns.settimeout(2)\ns.connect('/var/jb/var/lib/mac2jb-u2-native/broker.sock')\ns.sendall(b'status\\n')\nprint(s.recv(128).decode('ascii'),end='')\n"
    status = subprocess.run([*command, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"],
                            input=status_source, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=12)
    if status.returncode or status.stdout != b"OK phase=awaitingVerification publication=enabled\n":
        raise ValueError("broker phase changed")
    scalars = json.loads((BUILD / "u2-v7-baseline/host-usb-scalars.json").read_bytes())["fields"]
    vendor, product = scalars["idVendor"], scalars["idProduct"]
    if not (0 < vendor <= 65535 and 0 < product <= 65535):
        raise ValueError("target scalar invalid")
    return source, boot, vendor, product


def main():
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--inspect"):
        raise ValueError("fixed one-shot command")
    command = ssh()
    source, boot, vendor, product = preflight(command)
    if not TRIALS.is_dir() or stat.S_IMODE(TRIALS.stat().st_mode) != 0o700:
        raise ValueError("unsafe trial evidence directory")
    if any(path.name.startswith("forceedge-v7-") for path in TRIALS.iterdir()):
        raise ValueError("force-off release already attempted")
    if len(sys.argv) == 2:
        print("U2_FORCEOFF_EDGE inspect=ready journal=backed-up same-boot=yes "
              "controller=offbus mac-usb=absent ipad-write=none")
        return
    trial = TRIALS / ("forceedge-v7-" + str(time.time_ns()))
    trial.mkdir(mode=0o700)
    private_file(trial / "attempt-marker.txt", b"one-shot ForceOffBus(true/false) edge; do not retry\n")
    monitor = subprocess.Popen(["/usr/bin/python3", str(MONITOR),
                                f"0x{vendor:04x}", f"0x{product:04x}", "20"],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        ready, _, _ = select.select([monitor.stdout], [], [], 8)
        first = monitor.stdout.readline() if ready else b""
        record = json.loads(first)
        if (record.get("type") != "ready" or record.get("initial") != "absent" or
                record.get("target") != {"vendorID": f"0x{vendor:04x}",
                                         "productID": f"0x{product:04x}"}):
            raise ValueError("observer not ready")
        result = None
        timed_out = b""
        try:
            try:
                result = subprocess.run([*command, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"],
                                        input=source, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=30)
            except subprocess.TimeoutExpired as error:
                timed_out = error.stdout or b""
        finally:
            try:
                tail, _ = monitor.communicate(timeout=25)
            except subprocess.TimeoutExpired:
                monitor.kill()
                tail, _ = monitor.communicate(timeout=3)
        lifecycle = first + tail
        private_file(trial / "client.txt", (result.stdout if result else timed_out)[:512])
        private_file(trial / "lifecycle.ndjson", lifecycle)
    finally:
        if monitor.poll() is None:
            monitor.kill()
            monitor.communicate(timeout=3)
    if result is None or result.returncode or result.stdout != b"U2_FORCEOFF_EDGE force=success release=success\n":
        print("U2_FORCEOFF_EDGE api=unverified no-retry evidence=" + trial.name)
        return
    records = [json.loads(line) for line in lifecycle.splitlines()]
    summary = [item for item in records if item.get("type") == "summary"]
    if (len(summary) != 1 or summary[0].get("windowCompleted") is not True or
            summary[0].get("targetPresent") is not True or monitor.returncode != 0 or
            not any(item.get("type") == "event" and item.get("kind") == "arrived"
                    for item in records) or RECOVERY["read_boot_token"]() != boot):
        print("U2_FORCEOFF_EDGE external=unverified no-retry evidence=" + trial.name)
        return
    check = subprocess.run(["/usr/bin/python3", str(HOST / "check-u2-v7-current.py"),
                            "--expect-journal=awaitingVerification"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=70)
    if check.returncode or not re.match(
            rb"U2_V7_CURRENT boot=same live=(?:original|original-plus-flag) ", check.stdout):
        print("U2_FORCEOFF_EDGE usb=returned full-check=failed no-retry evidence=" + trial.name)
        return
    private_file(trial / "postcheck.txt", check.stdout)
    print("U2_FORCEOFF_EDGE external=verified journal=awaitingVerification evidence=" + trial.name)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_FORCEOFF_EDGE rejected; no retry")
        raise SystemExit(1)
