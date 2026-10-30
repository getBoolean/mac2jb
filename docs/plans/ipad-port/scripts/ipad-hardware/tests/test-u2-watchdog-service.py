#!/usr/bin/env python3
"""Mac fixture checks for the rootless U2 broker command boundary."""

import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest


DEVICE = Path(__file__).resolve().parents[1] / "device"
sys.path.insert(0, str(DEVICE))
from u2_restore_journal import RestoreJournal  # noqa: E402
from u2_watchdog_service import Broker  # noqa: E402


DESCRIPTION = plistlib.dumps({"DeviceDescription": "fixture"}, fmt=plistlib.FMT_BINARY)
IDENTITY = {
    "product_type": "iPad14,5", "os_build": "21A329",
    "controller_id": "42", "boot_session": "boot-a", "source_sha256": "a" * 64,
}


class Clock:
    now = 1_000_000_000

    def __call__(self):
        return self.now


class Controller:
    def __init__(self):
        self.calls = []

    def __call__(self, description, registry_id, publish=False):
        self.calls.append((description, registry_id, publish))
        return "published"


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mac2jb-u2-broker-")
        self.addCleanup(self.temporary.cleanup)
        os.chmod(self.temporary.name, 0o700)
        self.journal = RestoreJournal(self.temporary.name, expected_uid=os.getuid())
        self.clock = Clock()
        self.controller = Controller()
        self.snapshot = lambda: (dict(IDENTITY), DESCRIPTION)

    def broker(self, enabled=False):
        return Broker(self.journal, self.snapshot, self.controller,
                      self.clock, enable_publication=enabled)

    def test_default_denies_publication_and_writes_nothing(self):
        broker = self.broker()
        self.assertEqual(broker.handle("status"), "phase=absent publication=disabled")
        for command in ("prepare", "publish-noop"):
            with self.assertRaises(RuntimeError):
                broker.handle(command)
        self.assertEqual(self.controller.calls, [])
        with self.assertRaises(FileNotFoundError):
            self.journal.read()

    def test_noop_round_trip_retains_journal_until_host_proof(self):
        broker = self.broker(enabled=True)
        self.assertEqual(broker.handle("prepare"), "prepared")
        self.assertEqual(self.journal.read()["phase"], "prepared")
        broker.worker_attached = True
        self.assertEqual(broker.handle("publish-noop"), "published")
        self.assertEqual(self.controller.calls, [(DESCRIPTION, 42, True)])
        self.assertEqual(broker.handle("restore"), "restore-issued")
        self.assertEqual(self.journal.read()["phase"], "restoring")
        self.assertEqual(len(self.controller.calls), 2)
        self.assertEqual(broker.handle("confirm " + "c" * 64), "verified-and-cleared")
        self.assertEqual(broker.handle("restore"), "already-clear")

    def test_expired_lease_and_restart_recover_without_client(self):
        first = self.broker(enabled=True)
        first.handle("prepare")
        first.worker_attached = True
        first.handle("publish-noop")
        restarted = self.broker(enabled=False)
        self.assertEqual(restarted.on_start(), "restore-issued")
        self.assertEqual(len(self.controller.calls), 2)
        self.assertEqual(self.journal.read()["phase"], "restoring")

    def test_invalid_external_proof_preserves_journal(self):
        broker = self.broker(enabled=True)
        broker.handle("prepare")
        broker.worker_attached = True
        broker.handle("publish-noop")
        broker.handle("restore")
        with self.assertRaises(RuntimeError):
            broker.handle("confirm invalid")
        self.assertEqual(self.journal.read()["phase"], "restoring")

    def test_repeated_prepare_refuses_second_writer(self):
        broker = self.broker(enabled=True)
        broker.handle("prepare")
        with self.assertRaises(FileExistsError):
            broker.handle("prepare")
        self.assertEqual(self.controller.calls, [])

    def test_worker_watch_required_and_crash_restores(self):
        broker = self.broker(enabled=True)
        broker.handle("prepare")
        with self.assertRaises(RuntimeError):
            broker.handle("publish-noop")
        self.assertEqual(self.controller.calls, [])
        broker.worker_attached = True
        broker.handle("publish-noop")
        self.assertEqual(broker.worker_closed(), "crash-restore-issued")
        self.assertEqual(self.journal.read()["phase"], "restoring")

    def test_controlled_neutral_exit_restores_without_wait(self):
        broker = self.broker(enabled=True)
        broker.handle("prepare")
        broker.worker_attached = True
        broker.handle("publish-noop")
        self.assertEqual(broker.worker_closed(neutral_report_ack=True),
                         "neutral-restore-issued")
        self.assertEqual(len(self.controller.calls), 2)

    def test_worker_dies_before_publication_and_cannot_publish(self):
        broker = self.broker(enabled=True)
        broker.handle("prepare")
        broker.worker_attached = True
        self.assertEqual(broker.worker_closed(), "crash-no-publication")
        with self.assertRaises(RuntimeError):
            broker.handle("publish-noop")
        self.assertEqual(self.controller.calls, [])


if __name__ == "__main__":
    unittest.main()
