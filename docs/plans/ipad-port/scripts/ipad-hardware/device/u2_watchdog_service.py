#!/var/jb/usr/bin/python3
"""Separately supervised, root-only U2 restore broker for the exact iPad.

Launchd should run this from a root-owned rootless package. The private state
directory and Unix socket admit only root. The service is the sole writer of
the journal and controller: it captures the current live description itself,
issues a 15-second no-op lease, and restores on timeout or restart. The
default invocation rejects prepare/publish; a later guarded trial must
explicitly add --enable-noop-publication after an independent host baseline.
Even then, it only republishes the captured live description. A host-provided
external proof may clear a journal only after live readback equals original.
This file never edits the stock configuration plist or SSH configuration.
"""

import base64
import hashlib
import fcntl
import os
import select
import socket
import stat
import sys
import time


MODULE_DIR = "/var/jb/usr/libexec/mac2jb-u2"
STATE_DIR = "/var/jb/var/lib/mac2jb-u2"
SOCKET_PATH = STATE_DIR + "/broker.sock"
LEASE_NS = 15_000_000_000
MAX_REQUEST = 256
MAX_RESPONSE = 256

def _private_directory(path):
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError("unsafe private state directory")


def _trusted_module_directory(path):
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) not in (0o700, 0o755)):
        raise RuntimeError("unsafe module directory")
    for name in ("u2_restore_journal.py", "u2_target_snapshot.py",
                 "u2_usb_controller.py", "u2_watchdog_core.py",
                 "u2_watchdog_service.py"):
        item = os.lstat(os.path.join(path, name))
        if (not stat.S_ISREG(item.st_mode) or item.st_uid != 0 or
                item.st_nlink != 1 or stat.S_IMODE(item.st_mode) not in (0o600, 0o644) or
                item.st_size > 64 * 1024):
            raise RuntimeError("unsafe module file")


# Python -I removes the script directory from import search. Validate the
# fixed root-owned package before adding it to the module path or importing.
if __name__ == "__main__":
    _trusted_module_directory(MODULE_DIR)
    sys.path.insert(0, MODULE_DIR)

from u2_restore_journal import RestoreJournal
from u2_target_snapshot import capture
from u2_usb_controller import reconstruct_or_publish
from u2_watchdog_core import WatchdogCore


class Broker:
    def __init__(self, journal, snapshot, controller, clock=time.monotonic_ns,
                 enable_publication=False):
        self.journal = journal
        self.snapshot = snapshot
        self.controller = controller
        self.clock = clock
        self.enable_publication = enable_publication
        self.worker_attached = False
        self.pending_proof = None
        self.core = WatchdogCore(
            journal, self._identity, self._description, controller,
            self._verify_external, clock)

    def _identity(self):
        return self.snapshot()[0]

    def _description(self):
        return self.snapshot()[1]

    def _verify_external(self, record):
        proof = self.pending_proof
        if proof is None:
            raise RuntimeError("external proof absent")
        return proof

    def _current_phase(self):
        try:
            return self.journal.read()["phase"]
        except FileNotFoundError:
            return "absent"

    def on_start(self):
        phase = self._current_phase()
        if phase in ("prepared", "published", "restoring", "recovery-required"):
            return self.core.recover()
        return phase

    def tick(self):
        if self._current_phase() in ("prepared", "published"):
            return self.core.tick()
        return "waiting"

    def handle(self, request):
        if request == "status":
            return "phase=" + self._current_phase() + " publication=" + (
                "enabled" if self.enable_publication else "disabled")
        if request == "prepare":
            if not self.enable_publication:
                raise RuntimeError("publication disabled")
            identity, live = self.snapshot()
            record = {
                "version": 1, **identity,
                "original_description_b64": base64.b64encode(live).decode("ascii"),
                "planned_sha256": hashlib.sha256(live).hexdigest(),
                "lease_deadline_ns": self.clock() + LEASE_NS,
                "phase": "prepared", "external_proof_sha256": None,
            }
            self.core.prepare(record)
            return "prepared"
        if request == "publish-noop":
            if not self.enable_publication:
                raise RuntimeError("publication disabled")
            if not self.worker_attached:
                raise RuntimeError("worker supervision absent")
            self.core.publish_noop()
            return "published"
        if request == "restore":
            if self._current_phase() == "absent":
                return "already-clear"
            return self.core.recover()
        if request.startswith("confirm "):
            proof = request.removeprefix("confirm ")
            if len(proof) != 64 or any(char not in "0123456789abcdef" for char in proof):
                raise RuntimeError("invalid external proof")
            self.pending_proof = proof
            try:
                self.core.confirm_external_restore()
            finally:
                self.pending_proof = None
            return "verified-and-cleared"
        raise RuntimeError("unknown command")

    def worker_closed(self, neutral_report_ack=False):
        """Restore after worker EOF or an acknowledged controlled neutral exit."""
        self.worker_attached = False
        if self._current_phase() in ("prepared", "published"):
            result = self.core.recover()
            return ("neutral-" if neutral_report_ack else "crash-") + result
        return "no-active-lease"


def _socket():
    if os.path.lexists(SOCKET_PATH):
        info = os.lstat(SOCKET_PATH)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise RuntimeError("unsafe stale socket")
        os.unlink(SOCKET_PATH)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o177)
    try:
        listener.bind(SOCKET_PATH)
    finally:
        os.umask(old_umask)
    os.chmod(SOCKET_PATH, 0o600)
    listener.listen(4)
    listener.settimeout(0.25)
    return listener


def _singleton():
    path = STATE_DIR + "/broker.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(fd)
        raise RuntimeError("unsafe broker lock")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def serve(enable_publication=False):
    if os.geteuid() != 0:
        raise RuntimeError("root required")
    _trusted_module_directory(MODULE_DIR)
    _private_directory(STATE_DIR)
    singleton_fd = _singleton()
    journal = RestoreJournal(STATE_DIR)
    broker = Broker(journal, capture, reconstruct_or_publish,
                    enable_publication=enable_publication)
    broker.on_start()
    listener = _socket()
    worker = None
    try:
        while True:
            if worker is not None and select.select([worker], [], [], 0)[0]:
                try:
                    message = worker.recv(MAX_REQUEST + 1)
                    broker.worker_closed(neutral_report_ack=(message == b"neutral\n"))
                except Exception:
                    # The journal remains for retry; an invalid worker message
                    # is treated like a crash, never as neutral confirmation.
                    pass
                finally:
                    worker.close()
                    worker = None
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                try:
                    broker.tick()
                except Exception:
                    # The journal retains recovery-required evidence.
                    pass
                continue
            connection.settimeout(1)
            try:
                raw = connection.recv(MAX_REQUEST + 1)
                if len(raw) > MAX_REQUEST or not raw.endswith(b"\n"):
                    raise RuntimeError("invalid request")
                command = raw[:-1].decode("ascii")
                if command == "watch":
                    if (worker is not None or broker._current_phase() != "prepared" or
                            not broker.enable_publication):
                        raise RuntimeError("watch unavailable")
                    broker.worker_attached = True
                    worker = connection
                    encoded = b"OK watching\n"
                else:
                    response = broker.handle(command)
                    encoded = ("OK " + response + "\n").encode("ascii")
            except Exception:
                encoded = b"ERR rejected\n"
            try:
                connection.sendall(encoded[:MAX_RESPONSE])
            finally:
                if connection is not worker:
                    connection.close()
    finally:
        if worker is not None:
            worker.close()
        listener.close()
        info = os.lstat(SOCKET_PATH)
        if stat.S_ISSOCK(info.st_mode) and info.st_uid == 0:
            os.unlink(SOCKET_PATH)
        os.close(singleton_fd)


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--enable-noop-publication"]):
        raise SystemExit(2)
    serve(enable_publication=(sys.argv[1:] == ["--enable-noop-publication"]))
