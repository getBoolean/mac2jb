#!/usr/bin/env python3
"""Confirm a restored U2 journal only after exact external Mac verification.

This host orchestrator first runs the digest-pinned read-only current-state
checker against all four private baseline files while requiring an `awaitingVerification`
journal. It binds a private, fsynced Mac receipt to that journal's SHA-256,
then sends only the receipt SHA-256 to the root-only native broker socket via
pinned Wi-Fi SSH. The broker itself rechecks live iPad state before removing
the journal. A final read-only check requires the journal absent. The sole
iPad mutation is the broker's verified journal state/removal. No USB request,
descriptor publication, or iPad staging file is sent by this script.

Run only as the last step of a bounded no-op trial after the watchdog reports
`awaitingVerification`; it refuses absent, published, restoring, or recovery-required journals.
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
CHECKER = HOST / "check-u2-external-current.py"
CHECKER_SHA256 = "67336f70bfd9093a5e3b8466c1ccb27b5a02381b1beb8fd84eb5257a666dbfd3"
JOURNAL = HOST / "run-u2-readonly-default-description-wifi.py"
WIRELESS = HOST / "check-pinned-wireless-ssh.py"
HELPER = HOST / "backup-clienttruth-over-root-ssh.py"
BASE = ROOT / "build/ipad-hardware/u2-baseline"
TRIALS = ROOT / "build/ipad-hardware/u2-trials"
BASELINE_HASHES = {
    "current.json": "39afcfbce83334cec6facc72f2bfadc40c0eae30591acd217fd68ad5422f4883",
    "host-usb-scalars.json": "fa2610eebb7abd7b94848f13524936d7a84c3a3c1bb67d66010c4026a3f76218",
    "host-interfaces.json": "226d9551f3f65a28213b1b0c1888414b9760fea7da9ed6d25942731ff4c0b8c5",
    "raw-configs.bin": "bffeea0b79d6c571b0164b2a2b84f8939148e45b51a63591cb0ad2bec15a599f",
}
CURRENT = (
    b"U2_EXTERNAL_CURRENT identity=match raw-configs=byte-equal "
    b"host-interfaces=equal usb-scalars=equal usbmux=one network=one "
    b"trust=valid power=external charging=or-full "
    b"usb-network-driver=absent journal=awaitingVerification\n"
)
JOURNAL_RESULT = re.compile(rb"U2_NATIVE_JOURNAL phase=awaitingVerification sha256=([0-9a-f]{64})\n\Z")


def read(command, timeout=25, input=None):
    result = subprocess.run(command, input=input, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout)
    if result.returncode != 0 or len(result.stdout) > 512:
        raise ValueError("verification command failed")
    return result.stdout


def check_private():
    info = CHECKER.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 or
            hashlib.sha256(CHECKER.read_bytes()).hexdigest() != CHECKER_SHA256):
        raise ValueError("external checker changed")
    if stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError("unsafe baseline directory")
    for name, digest in BASELINE_HASHES.items():
        path = BASE / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024 * 1024 or
                hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError("baseline changed")


def pinned_ssh():
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
            "-o", "AddressFamily=inet", "-T", "-p", "22",
            "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]


def journal_hash():
    output = read(["/usr/bin/python3", str(JOURNAL), "--native-journal"])
    match = JOURNAL_RESULT.fullmatch(output)
    if not match:
        raise ValueError("journal not awaiting verification")
    return match.group(1).decode("ascii")


def store_receipt(digest, checked_output):
    TRIALS.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(TRIALS.stat().st_mode) != 0o700:
        raise ValueError("unsafe trial directory")
    trial = TRIALS / ("restore-" + digest[:16])
    trial.mkdir(mode=0o700)
    receipt = trial / "external-restore.json"
    data = json.dumps({
        "version": 1, "journal_sha256": digest,
        "checker_sha256": CHECKER_SHA256,
        "baseline_sha256": BASELINE_HASHES,
        "checked_line": checked_output.decode("ascii").splitlines()[0],
        "observed_unix_ns": time.time_ns(),
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short receipt write")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(trial, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return hashlib.sha256(data).hexdigest()


def main():
    check_private()
    output = read(["/usr/bin/python3", str(CHECKER), "--expect-journal=awaitingVerification"],
                  timeout=60)
    if not output.startswith(CURRENT) or len(output.splitlines()) != 2:
        raise ValueError("external comparison failed")
    digest = journal_hash()
    if output != CURRENT + ("U2_EXTERNAL_CURRENT journal-sha256=" + digest + "\n").encode("ascii"):
        raise ValueError("journal changed during comparison")
    ssh = pinned_ssh()
    proof = store_receipt(digest, output)
    payload = (
        "import socket\n"
        "p='/var/jb/var/lib/mac2jb-u2-native/broker.sock'\n"
        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
        "s.settimeout(4)\n"
        "s.connect(p)\n"
        "s.sendall(b'confirm " + proof + "\\n')\n"
        "r=s.recv(128)\n"
        "s.close()\n"
        "assert r==b'OK verified-and-cleared\\n'\n"
        "print('U2_CONFIRM accepted')\n"
    ).encode("ascii")
    response = read(ssh, timeout=12, input=payload)
    if response != b"U2_CONFIRM accepted\n":
        raise ValueError("broker did not confirm restoration")
    after = read(["/usr/bin/python3", str(CHECKER), "--expect-journal=absent"],
                 timeout=60)
    if b" journal=absent\n" not in after:
        raise ValueError("post-confirm external check failed")
    print("U2_RESTORE_CONFIRM external=equal broker=verified "
          "journal=absent receipt-sha256=" + proof)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_RESTORE_CONFIRM rejected; preserve any journal and private receipt")
        raise SystemExit(1)
