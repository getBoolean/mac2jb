#!/usr/bin/env python3
"""Fault-test the native watchdog socket loop with a fake Mac controller.

This compiles a Mac-only Swift fixture that links the real native service,
journal, and coordinator to a file-backed fake controller. It tests publish,
worker death, neutral exit, lease expiry, restart, failed verification, and a
second service contender. No iPad executable is run, no USB API is linked,
and all fixture state stays in a temporary directory removed at exit.
"""

import os
from pathlib import Path
import plistlib
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[6]
SOURCES = [
    "ios/usb/USBRestoreJournal.swift",
    "ios/watchdog/USBRestoreCoordinator.swift",
    "ios/watchdog/USBFunctionRegistrationHealer.swift",
    "ios/watchdog/USBFunctionOwnerRestarter.swift",
    "ios/watchdog/NativeUSBWatchdogService.swift",
    "ios/tests/NativeUSBWatchdogServiceFixture.swift",
]


def fixture_description(label):
    fields = {
        "Attributes": 192, "BcdUSBVersion": 768,
        "ConfigurationDescriptors": [
            {"Description": f"fixture-{label}-{index}", "Interfaces": []}
            for index in range(9)
        ],
        "DefaultBcdUSBVersion": 768, "MPS0": 9, "MaxPower": 112,
        "deviceClass": 0, "deviceID": 1, "deviceProtocol": 0,
        "deviceSubClass": 0, "manufacturerString": "fixture",
        "productID": 1, "productString": "fixture", "serialNumber": "fixture",
        "uniqueDeviceID": "fixture", "vendorID": 1,
    }
    return plistlib.dumps(fields, fmt=plistlib.FMT_BINARY, sort_keys=True)


def build(binary, cache):
    env = dict(os.environ, CLANG_MODULE_CACHE_PATH=str(cache / "clang"),
               SWIFT_MODULE_CACHE_PATH=str(cache / "swift"))
    result = subprocess.run(
        ["/usr/bin/xcrun", "swiftc", *(str(ROOT / p) for p in SOURCES),
         "-o", str(binary)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60, env=env)
    if result.returncode != 0:
        raise AssertionError("native service fixture failed to compile")


class Service:
    def __init__(self, binary, parent, env=None):
        self.state = parent / "state"
        self.state.mkdir(mode=0o700)
        self.live = parent / "live.bplist"
        self.live.write_bytes(fixture_description("original"))
        self.live.chmod(0o600)
        self.original = self.live.read_bytes()
        self.events = parent / "events"
        self.binary = binary
        self.env = env
        self.process = None
        self.start()

    def start(self, timeout=3):
        self.process = subprocess.Popen(
            [str(self.binary), "--fixture-server", str(self.state),
             str(self.live), str(self.events)], stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, env=self.env)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError("fixture service died during startup: " +
                                     self.process.stderr.read(600).decode("utf8", "replace"))
            if (self.state / "broker.sock").exists():
                try:
                    assert self.command("status").startswith("OK phase=")
                    return
                except (OSError, AssertionError):
                    pass
            time.sleep(0.02)
        raise AssertionError("fixture service not ready")

    def connect(self, command):
        peer = socket.socket(socket.AF_UNIX)
        peer.settimeout(2)
        peer.connect(str(self.state / "broker.sock"))
        peer.sendall(command.encode("ascii") + b"\n")
        return peer

    def command(self, command):
        with self.connect(command) as peer:
            return peer.recv(256).decode("ascii").strip()

    def count(self):
        return len(self.events.read_bytes()) if self.events.exists() else 0

    def phase(self, expected):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.command("status") == f"OK phase={expected} publication=enabled":
                return
            time.sleep(0.02)
        raise AssertionError("expected journal phase " + expected)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=3)


def require(value):
    if not value:
        raise AssertionError("native service fixture mismatch")


def normal(binary, parent):
    service = Service(binary, parent)
    try:
        require(service.command("prepare") == "OK prepared")
        require(service.command("prepare") == "ERR rejected")
        worker = service.connect("watch")
        require(worker.recv(256) == b"OK watching\n")
        require(service.command("publish-noop") == "OK published")
        require(service.count() == 1)
        worker.close()
        service.phase("awaitingVerification")
        require(service.count() == 2)
        require(service.command("restore") == "OK awaiting-verification")
        require(service.count() == 2)
        with_flag = plistlib.loads(service.original)
        with_flag["AllowMultipleCreates"] = True
        service.live.write_bytes(plistlib.dumps(with_flag, fmt=plistlib.FMT_BINARY))
        require(service.command("confirm " + "c" * 64) == "OK verified-and-cleared")
        service.phase("absent")
        require(not (service.state / "restore-journal.json").exists())
        require(service.command("restore") == "OK already-clear")
    finally:
        service.stop()


def restart_and_contender(binary, parent):
    service = Service(binary, parent)
    try:
        require(service.command("prepare") == "OK prepared")
        worker = service.connect("watch")
        require(worker.recv(256) == b"OK watching\n")
        require(service.command("publish-noop") == "OK published")
        require(service.count() == 1)
        contender = subprocess.run(
            [str(binary), "--fixture-server", str(service.state),
             str(service.live), str(service.events)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        require(contender.returncode != 0 and service.count() == 1)
        service.stop()
        worker.close()
        service.start()
        service.phase("awaitingVerification")
        require(service.count() == 2)
        require(service.command("confirm " + "d" * 64) == "OK verified-and-cleared")
        service.phase("absent")
    finally:
        service.stop()


def restart_after_restore(binary, parent):
    service = Service(binary, parent)
    try:
        require(service.command("prepare") == "OK prepared")
        worker = service.connect("watch")
        require(worker.recv(256) == b"OK watching\n")
        require(service.command("publish-noop") == "OK published")
        worker.close()
        service.phase("awaitingVerification")
        require(service.count() == 2)
        service.stop()
        service.start()
        service.phase("awaitingVerification")
        require(service.count() == 2)
        require(service.command("confirm " + "b" * 64) == "OK verified-and-cleared")
    finally:
        service.stop()


def reject_unexpected_live_field(binary, parent):
    service = Service(binary, parent)
    try:
        require(service.command("prepare") == "OK prepared")
        worker = service.connect("watch")
        require(worker.recv(256) == b"OK watching\n")
        require(service.command("publish-noop") == "OK published")
        worker.close()
        service.phase("awaitingVerification")
        wrong = plistlib.loads(service.original)
        wrong["UnexpectedField"] = True
        service.live.write_bytes(plistlib.dumps(wrong, fmt=plistlib.FMT_BINARY))
        require(service.command("confirm " + "8" * 64) == "ERR rejected")
        service.phase("recoveryRequired")
        require(service.count() == 2)
    finally:
        service.stop()


def lease_and_failed_verification(binary, parent):
    service = Service(binary, parent)
    try:
        require(service.command("prepare") == "OK prepared")
        worker = service.connect("watch")
        require(worker.recv(256) == b"OK watching\n")
        require(service.command("publish-noop") == "OK published")
        service.phase("awaitingVerification")  # The lease expires while worker stays open.
        require(service.count() == 2)
        service.live.write_bytes(fixture_description("changed"))
        require(service.command("confirm " + "e" * 64) == "ERR rejected")
        service.phase("recoveryRequired")
        require((service.state / "restore-journal.json").is_file())
        service.stop()
        service.start()
        service.phase("recoveryRequired")
        require(service.count() == 2)  # Failed verification cannot auto-republish.
        service.live.write_bytes(service.original)
        require(service.command("restore") == "OK restore-issued")
        service.phase("awaitingVerification")
        require(service.count() == 3)
        require(service.command("confirm " + "f" * 64) == "OK verified-and-cleared")
        worker.close()
    finally:
        service.stop()


def neutral(binary, parent):
    service = Service(binary, parent)
    try:
        require(service.command("prepare") == "OK prepared")
        worker = service.connect("watch")
        require(worker.recv(256) == b"OK watching\n")
        require(service.command("publish-noop") == "OK published")
        worker.sendall(b"neutral\n")
        worker.close()
        service.phase("awaitingVerification")
        require(service.count() == 2)
        require(service.command("confirm " + "a" * 64) == "OK verified-and-cleared")
    finally:
        service.stop()


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u2-native-fixture-",
                                     dir="/tmp") as temp:
        root = Path(temp)
        binary = root / "service-fixture"
        build(binary, root / "cache")
        for name, test in (("normal", normal), ("restart", restart_and_contender),
                           ("restart-after-restore", restart_after_restore),
                           ("unexpected-live-field", reject_unexpected_live_field),
                           ("lease", lease_and_failed_verification),
                           ("neutral", neutral)):
            directory = root / name
            directory.mkdir(mode=0o700)
            test(binary, directory)
    print("PASS native U2 service fixture: normal, worker death, restart, "
          "restart after restore, replacement flag whitelist, "
          "contender, lease, failed verification, neutral")


if __name__ == "__main__":
    main()
