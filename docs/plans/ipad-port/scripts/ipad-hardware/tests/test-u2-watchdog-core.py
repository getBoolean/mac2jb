#!/usr/bin/env python3
"""Fault-path tests for the iPad USB restore watchdog state machine."""

import base64
import hashlib
import os
import plistlib
from pathlib import Path
import sys
import tempfile
import unittest


DEVICE = Path(__file__).resolve().parents[1] / "device"
sys.path.insert(0, str(DEVICE))
from u2_restore_journal import RestoreJournal  # noqa: E402
from u2_watchdog_core import WatchdogCore, WatchdogError  # noqa: E402


DESCRIPTION = plistlib.dumps({"DeviceDescription": "fixture"}, fmt=plistlib.FMT_BINARY)


def recipe():
    return {
        "version": 1, "product_type": "iPad14,5", "os_build": "21A329",
        "controller_id": "42", "boot_session": "boot-a", "source_sha256": "a" * 64,
        "original_description_b64": base64.b64encode(DESCRIPTION).decode(),
        "planned_sha256": hashlib.sha256(DESCRIPTION).hexdigest(),
        "lease_deadline_ns": 100, "phase": "prepared", "external_proof_sha256": None,
    }


class FakeClock:
    now = 10

    def __call__(self):
        return self.now


class FakeController:
    def __init__(self):
        self.calls = []
        self.fail = False

    def __call__(self, description, registry_id, publish=False):
        self.calls.append((description, registry_id, publish))
        if self.fail:
            raise RuntimeError("injected controller failure")


class FakeVerifier:
    fail = False

    def __call__(self, record):
        if self.fail:
            raise RuntimeError("injected external failure")
        return "c" * 64


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mac2jb-u2-watchdog-")
        self.addCleanup(self.temporary.cleanup)
        os.chmod(self.temporary.name, 0o700)
        self.journal = RestoreJournal(self.temporary.name, expected_uid=os.getuid())
        self.clock = FakeClock()
        self.controller = FakeController()
        self.verifier = FakeVerifier()
        self.identity = {key: recipe()[key] for key in (
            "product_type", "os_build", "controller_id", "boot_session", "source_sha256")}
        self.live = DESCRIPTION
        self.watchdog = WatchdogCore(self.journal, lambda: self.identity,
                                    lambda: self.live,
                                    self.controller, self.verifier, self.clock)

    def test_prepared_restart_does_not_write_controller(self):
        self.watchdog.prepare(recipe())
        self.assertEqual(self.watchdog.recover(), "no-publication")
        self.assertEqual(self.controller.calls, [])
        self.watchdog.confirm_external_restore()
        with self.assertRaises(FileNotFoundError):
            self.journal.read()

    def test_lease_expiry_restores_and_keeps_record_until_verified(self):
        self.watchdog.prepare(recipe())
        self.watchdog.publish_noop()
        self.assertEqual(len(self.controller.calls), 1)
        self.assertEqual(self.watchdog.tick(), "waiting")
        self.clock.now = 100
        self.assertEqual(self.watchdog.tick(), "restore-issued")
        self.assertEqual(self.journal.read()["phase"], "restoring")
        self.assertEqual(self.controller.calls[1], (DESCRIPTION, 42, True))
        self.assertEqual(self.watchdog.tick(), "waiting")
        self.assertEqual(len(self.controller.calls), 2)
        self.watchdog.confirm_external_restore()
        with self.assertRaises(FileNotFoundError):
            self.journal.read()

    def test_failed_restore_keeps_recovery_required(self):
        self.watchdog.prepare(recipe())
        self.watchdog.publish_noop()
        self.controller.fail = True
        with self.assertRaises(RuntimeError):
            self.watchdog.recover()
        self.assertEqual(self.journal.read()["phase"], "recovery-required")
        self.controller.fail = False
        self.assertEqual(self.watchdog.recover(), "restore-issued")
        self.verifier.fail = True
        with self.assertRaises(RuntimeError):
            self.watchdog.confirm_external_restore()
        self.assertEqual(self.journal.read()["phase"], "recovery-required")

    def test_wrong_boot_and_lease_refuse_publication(self):
        self.identity["boot_session"] = "boot-b"
        with self.assertRaises(WatchdogError):
            self.watchdog.prepare(recipe())
        self.assertEqual(self.controller.calls, [])
        self.identity["boot_session"] = "boot-a"
        self.watchdog.prepare(recipe())
        self.clock.now = 100
        with self.assertRaises(WatchdogError):
            self.watchdog.publish_noop()
        self.assertEqual(self.controller.calls, [])

    def test_changed_live_description_refuses_publication(self):
        self.watchdog.prepare(recipe())
        self.live = plistlib.dumps({"DeviceDescription": "changed"}, fmt=plistlib.FMT_BINARY)
        with self.assertRaises(WatchdogError):
            self.watchdog.publish_noop()
        self.assertEqual(self.controller.calls, [])
        self.assertEqual(self.journal.read()["phase"], "prepared")

    def test_restarted_watchdog_restores_published_journal(self):
        self.watchdog.prepare(recipe())
        self.watchdog.publish_noop()
        restarted = WatchdogCore(self.journal, lambda: self.identity,
                                 lambda: self.live, self.controller,
                                 self.verifier, self.clock)
        self.assertEqual(restarted.recover(), "restore-issued")
        self.assertEqual(self.journal.read()["phase"], "restoring")
        self.assertEqual(len(self.controller.calls), 2)
        self.assertEqual(restarted.recover(), "restore-issued")
        self.assertEqual(len(self.controller.calls), 3)
        restarted.confirm_external_restore()
        with self.assertRaises(FileNotFoundError):
            self.journal.read()

    def test_second_prepare_refuses_existing_journal_without_write(self):
        self.watchdog.prepare(recipe())
        with self.assertRaises(FileExistsError):
            self.watchdog.prepare(recipe())
        self.assertEqual(self.controller.calls, [])

    def test_live_restore_mismatch_preserves_journal(self):
        self.watchdog.prepare(recipe())
        self.watchdog.publish_noop()
        self.watchdog.recover()
        self.live = plistlib.dumps({"DeviceDescription": "not-restored"},
                                   fmt=plistlib.FMT_BINARY)
        with self.assertRaises(WatchdogError):
            self.watchdog.confirm_external_restore()
        self.assertEqual(self.journal.read()["phase"], "recovery-required")


if __name__ == "__main__":
    unittest.main()
