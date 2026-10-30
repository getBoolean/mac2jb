#!/var/jb/usr/bin/python3
"""Single-writer restore state machine used by the supervised iPad process.

The watchdog alone calls this module. It journals the original description
before publication, bounds each lease, restores independently of a canary,
and keeps failed or externally unverified journal records. Controller and
external verifier callables are injected for fault tests. This module itself
does not open USB or touch a system configuration file.
"""

import base64
import hashlib
import time

from u2_restore_journal import JournalError, RestoreJournal, validate


MAX_LEASE_NS = 30_000_000_000


class WatchdogError(Exception):
    pass


def _next(record, phase, proof=None):
    value = dict(record)
    value["phase"] = phase
    value["external_proof_sha256"] = proof
    return value


class WatchdogCore:
    def __init__(self, journal, identity, current_description, controller, external_verifier,
                 clock=time.monotonic_ns):
        self.journal = journal
        self.identity = identity
        self.current_description = current_description
        self.controller = controller
        self.external_verifier = external_verifier
        self.clock = clock

    def _bound(self, record):
        validate(record)
        current = self.identity()
        for key in ("product_type", "os_build", "controller_id", "boot_session",
                    "source_sha256"):
            if record[key] != current[key]:
                raise WatchdogError("target identity changed")

    def prepare(self, record):
        self._bound(record)
        now = self.clock()
        if (record["phase"] != "prepared" or not now < record["lease_deadline_ns"] or
                record["lease_deadline_ns"] - now > MAX_LEASE_NS):
            raise WatchdogError("invalid lease")
        if record["planned_sha256"] != hashlib.sha256(
                base64.b64decode(record["original_description_b64"])).hexdigest():
            raise WatchdogError("no-op description mismatch")
        if base64.b64decode(record["original_description_b64"]) != self.current_description():
            raise WatchdogError("live description changed")
        self.journal.create(record)

    def publish_noop(self):
        prepared = self.journal.read()
        self._bound(prepared)
        if prepared["phase"] != "prepared" or self.clock() >= prepared["lease_deadline_ns"]:
            raise WatchdogError("lease expired")
        description = base64.b64decode(prepared["original_description_b64"])
        if description != self.current_description():
            raise WatchdogError("live description changed")
        self.journal.transition(prepared, _next(prepared, "published"))
        try:
            self.controller(description, int(prepared["controller_id"]), publish=True)
        except Exception:
            try:
                self.recover()
            except Exception:
                pass
            raise

    def recover(self):
        current = self.journal.read()
        self._bound(current)
        if current["phase"] == "restored":
            return "already-restored"
        if current["phase"] in ("prepared", "published", "recovery-required"):
            self.journal.transition(current, _next(current, "restoring"))
        if current["phase"] == "prepared":
            return "no-publication"
        try:
            description = base64.b64decode(current["original_description_b64"])
            self.controller(description, int(current["controller_id"]), publish=True)
            return "restore-issued"
        except Exception:
            latest = self.journal.read()
            if latest["phase"] == "restoring":
                self.journal.transition(latest, _next(latest, "recovery-required"))
            raise

    def tick(self):
        current = self.journal.read()
        self._bound(current)
        if (current["phase"] in ("prepared", "published") and
                self.clock() >= current["lease_deadline_ns"]):
            return self.recover()
        return "waiting"

    def confirm_external_restore(self):
        current = self.journal.read()
        self._bound(current)
        if current["phase"] != "restoring":
            raise WatchdogError("restore not pending verification")
        try:
            if self.current_description() != base64.b64decode(
                    current["original_description_b64"]):
                raise WatchdogError("live description not restored")
            proof = self.external_verifier(current)
            if (not isinstance(proof, str) or len(proof) != 64 or
                    any(char not in "0123456789abcdef" for char in proof)):
                raise WatchdogError("invalid external proof")
            restored = _next(current, "restored", proof)
            self.journal.transition(current, restored)
            self.journal.remove_verified(restored)
        except Exception:
            latest = self.journal.read()
            if latest["phase"] == "restoring":
                self.journal.transition(latest, _next(latest, "recovery-required"))
            raise
