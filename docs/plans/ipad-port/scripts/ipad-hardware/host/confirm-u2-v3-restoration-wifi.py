#!/usr/bin/env python3
"""Confirm a future U2 restore only after same-boot semantic external proof.

The current-boot checker verifies original live fields, resolved USB strings,
all non-string descriptor bytes, Mac interfaces/scalars, NCM packet flow,
pairing and charging with an `awaitingVerification` journal. This host then
fsyncs a private receipt bound to that exact journal and sends only its digest
through a pinned root Wi-Fi SSH script. The native watchdog rechecks live
state and removes its journal. A second full external check must pass with no
journal. This script never publishes a USB description or stages iPad files.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import time


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
CHECKER = HOST / "check-u2-v3-current.py"
CHECKER_SHA256 = "c90396d4631cfe28e010f29a2157e0391c36e855cd65db349e4c265c39d0d269"
PACKET = HOST / "probe-u2-ncm-packet-flow.py"
PACKET_SHA256 = "832fb6d2cac032c88a7d31910c7761fcaa132319a209f541a0828af0764a5b21"
CLIENT = ROOT / "scripts/ipad-hardware/device/u2-confirm-native-restoration-v3.py"
CLIENT_SHA256 = "48aae520d71a56d4fa824e7a8d97d13a27bc5a576fc0550973e4f1af3da0c51b"
MANIFEST_SHA256 = "e4da9a2f2679de5d8822c28d19e0fa3b50e99a037b99ad47012c1eb31611c425"
TRIALS = ROOT / "build/ipad-hardware/u2-trials"
WIRELESS = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
HELPER = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
FIRST = re.compile(
    rb"U2_V3_CURRENT boot=same live=(?:original|original-plus-flag) "
    rb"configs=5 resolved-strings=23 renumbered=[0-9]{1,3} "
    rb"interfaces=equal scalars=equal network-binding=equal "
    rb"network-packet=reply usbmux=one pairing=valid "
    rb"power=charging-or-full journal=awaitingVerification\n"
    rb"U2_V3_CURRENT journal-sha256=([0-9a-f]{64})\n\Z"
)


def checked(path, digest, maximum):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not 0 < info.st_size <= maximum):
        raise ValueError("unsafe verifier input")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("verifier input changed")
    return data


def command(args, timeout=60, input=None, maximum=1024):
    result = subprocess.run(args, input=input, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout)
    if result.returncode or len(result.stdout) > maximum:
        raise ValueError("restoration verification failed")
    return result.stdout


def ssh(payload, digest):
    address = WIRELESS["read_address"]()
    if address is None:
        raise ValueError("pinned Wi-Fi address unavailable")
    for path, expected in ((HELPER["IDENTITY"], HELPER["IDENTITY_SHA256"]),
                           (HELPER["KNOWN_HOSTS"], HELPER["KNOWN_HOSTS_SHA256"])):
        HELPER["checked_local"](path, expected, 0o600)
    args = ["/usr/bin/ssh", *HELPER["ssh_options"](),
            "-o", "HostKeyAlias=" + WIRELESS["HOST_KEY_ALIAS"],
            "-o", "AddressFamily=inet", "-T", "-p", "22",
            "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B",
            "-", digest]
    return command(args, timeout=12, input=payload, maximum=256)


def receipt(journal_sha, checked_output):
    TRIALS.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(TRIALS.stat().st_mode) != 0o700:
        raise ValueError("unsafe trial evidence directory")
    directory = TRIALS / ("restore-v3-" + journal_sha[:16])
    directory.mkdir(mode=0o700)
    data = json.dumps({
        "version": 3,
        "journal_sha256": journal_sha,
        "checker_sha256": CHECKER_SHA256,
        "packet_probe_sha256": PACKET_SHA256,
        "client_sha256": CLIENT_SHA256,
        "reference_manifest_sha256": MANIFEST_SHA256,
        "checked_line": checked_output.decode("ascii").splitlines()[0],
        "observed_unix_ns": time.time_ns(),
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    fd = os.open(directory / "external-restore.json",
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short receipt write")
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return hashlib.sha256(data).hexdigest()


def main():
    checked(CHECKER, CHECKER_SHA256, 32 * 1024)
    checked(PACKET, PACKET_SHA256, 16 * 1024)
    payload = checked(CLIENT, CLIENT_SHA256, 16 * 1024)
    output = command(["/usr/bin/python3", str(CHECKER),
                      "--expect-journal=awaitingVerification"])
    match = FIRST.fullmatch(output)
    if not match:
        raise ValueError("same-boot external proof incomplete")
    journal_sha = match.group(1).decode("ascii")
    before = command(["/usr/bin/python3", str(
        HOST / "run-u2-readonly-default-description-wifi.py"), "--native-journal"],
        timeout=20, maximum=128)
    if before != ("U2_NATIVE_JOURNAL phase=awaitingVerification sha256=" +
                  journal_sha + "\n").encode("ascii"):
        raise ValueError("journal changed after external proof")
    proof = receipt(journal_sha, output)
    if ssh(payload, proof) != b"U2_CONFIRM_V3 accepted\n":
        raise ValueError("native watchdog rejected receipt")
    after = command(["/usr/bin/python3", str(CHECKER),
                     "--expect-journal=absent"])
    if (b" journal=absent\n" not in after or
        not after.startswith(b"U2_V3_CURRENT boot=same ")):
        raise ValueError("post-confirm external proof failed")
    print("U2_RESTORE_CONFIRM_V3 external=semantic-equal ncm-packet=reply "
          "broker=verified journal=absent receipt-sha256=" + proof)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_RESTORE_CONFIRM_V3 rejected; preserve journal and private receipt")
        raise SystemExit(1)
