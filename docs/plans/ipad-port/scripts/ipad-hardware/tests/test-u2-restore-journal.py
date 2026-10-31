#!/usr/bin/env python3
"""Mac-only fault cases for the iPad watchdog's private restore journal."""

import base64
import os
import plistlib
from pathlib import Path
import runpy
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[6]
MODULE = runpy.run_path(str(ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2_restore_journal.py"))
RestoreJournal = MODULE["RestoreJournal"]
JournalError = MODULE["JournalError"]


def record(phase="prepared", proof=None):
    return {
        "version": 1,
        "product_type": "iPad14,5",
        "os_build": "21A329",
        "controller_id": "42",
        "boot_session": "boot-a",
        "source_sha256": "a" * 64,
        "original_description_b64": base64.b64encode(
            plistlib.dumps({"DeviceDescription": "fixture"}, fmt=plistlib.FMT_BINARY)).decode(),
        "planned_sha256": "b" * 64,
        "lease_deadline_ns": 100,
        "phase": phase,
        "external_proof_sha256": proof,
    }


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mac2jb-u2-journal-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        os.chmod(self.path, 0o700)
        self.journal = RestoreJournal(str(self.path), expected_uid=os.getuid())

    def test_create_read_refuses_overwrite(self):
        original = record()
        self.journal.create(original)
        self.assertEqual(self.journal.read(), original)
        info = (self.path / "restore-journal.json").stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            self.journal.create(record("published"))
        self.assertEqual(self.journal.read(), original)

    def test_transition_and_verified_removal(self):
        prepared = record()
        published = record("published")
        restoring = record("restoring")
        verified = record("restored", "c" * 64)
        self.journal.create(prepared)
        with self.assertRaises(JournalError):
            self.journal.transition(prepared, verified)
        self.journal.transition(prepared, published)
        with self.assertRaises(JournalError):
            self.journal.transition(prepared, restoring)
        self.journal.transition(published, restoring)
        with self.assertRaises(JournalError):
            self.journal.remove_verified(restoring)
        self.journal.transition(restoring, verified)
        self.journal.remove_verified(verified)
        with self.assertRaises(FileNotFoundError):
            self.journal.read()

    def test_corruption_and_wrong_metadata(self):
        self.journal.create(record())
        target = self.path / "restore-journal.json"
        target.write_bytes(target.read_bytes()[:-1])
        with self.assertRaises(JournalError):
            self.journal.read()
        target.chmod(0o644)
        with self.assertRaises(JournalError):
            self.journal.read()

    def test_wrong_owner_expectation_rejects_directory(self):
        foreign = RestoreJournal(str(self.path), expected_uid=os.getuid() + 1)
        with self.assertRaises(JournalError):
            foreign.create(record())
        self.assertFalse((self.path / "restore-journal.json").exists())

    def test_interrupted_link_preserves_no_final_journal(self):
        with mock.patch("os.link", side_effect=OSError("injected link failure")):
            with self.assertRaises(OSError):
                self.journal.create(record())
        self.assertEqual(list(self.path.iterdir()), [])

    def test_second_writer_cannot_replace_first_record(self):
        original = record()
        self.journal.create(original)
        other = RestoreJournal(str(self.path), expected_uid=os.getuid())
        with self.assertRaises(FileExistsError):
            other.create(record("published"))
        self.assertEqual(self.journal.read(), original)

    def test_invalid_binary_plist_rejected_before_create(self):
        damaged = record()
        damaged["original_description_b64"] = base64.b64encode(b"bplist00fixture").decode()
        with self.assertRaises(JournalError):
            self.journal.create(damaged)
        self.assertFalse((self.path / "restore-journal.json").exists())

    def test_identity_and_lease_cannot_change_in_transition(self):
        prepared = record()
        self.journal.create(prepared)
        for field, value in (("controller_id", "43"), ("boot_session", "boot-b"),
                             ("source_sha256", "d" * 64), ("lease_deadline_ns", 200)):
            changed = record("published")
            changed[field] = value
            with self.assertRaises(JournalError):
                self.journal.transition(prepared, changed)
        self.assertEqual(self.journal.read(), prepared)

    def test_symlink_and_directory_mode(self):
        with tempfile.TemporaryDirectory(prefix="mac2jb-u2-outside-") as outside:
            target = Path(outside) / "outside"
            target.write_bytes(b"private")
            (self.path / "restore-journal.json").symlink_to(target)
            with self.assertRaises(OSError):
                self.journal.read()
            with self.assertRaises(FileExistsError):
                self.journal.create(record())
            self.assertEqual(target.read_bytes(), b"private")
        (self.path / "restore-journal.json").unlink()
        self.path.chmod(0o755)
        with self.assertRaises(JournalError):
            self.journal.create(record())


if __name__ == "__main__":
    unittest.main()
