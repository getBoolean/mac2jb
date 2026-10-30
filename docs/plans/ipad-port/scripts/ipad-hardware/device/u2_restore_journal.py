#!/var/jb/usr/bin/python3
"""Durable, root-owned USB restore journal for the supervised iPad watchdog.

The watchdog creates a checksummed record before any USB publication, changes
its phase with atomic replacement and file/directory fsync, and keeps a failed
record for recovery. This module only writes inside its caller-supplied private
state directory. It does not open a USB controller or invoke an iPad setting.
The journal format is versioned and intentionally rejects unknown fields.
"""

import base64
import binascii
import hashlib
import json
import os
import plistlib
import stat
import uuid
import fcntl


FILENAME = "restore-journal.json"
LOCKNAME = ".restore-journal.lock"
MAX_BYTES = 2_000_000
PHASES = {"prepared", "published", "restoring", "recovery-required", "restored"}
TRANSITIONS = {
    ("prepared", "published"), ("prepared", "restoring"),
    ("published", "restoring"), ("restoring", "restored"),
    ("restoring", "recovery-required"),
    ("recovery-required", "restoring"),
}
FIELDS = {
    "version", "product_type", "os_build", "controller_id", "boot_session",
    "source_sha256", "original_description_b64", "planned_sha256",
    "lease_deadline_ns", "phase", "external_proof_sha256",
}


class JournalError(Exception):
    pass


def _digest(value):
    return (isinstance(value, str) and len(value) == 64 and
            all(character in "0123456789abcdef" for character in value))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise JournalError("duplicate key")
        result[key] = value
    return result


def validate(record):
    if not isinstance(record, dict) or set(record) != FIELDS:
        raise JournalError("record fields")
    if record["version"] != 1 or record["phase"] not in PHASES:
        raise JournalError("record version or phase")
    for key in ("product_type", "os_build", "controller_id", "boot_session"):
        if not isinstance(record[key], str) or not 1 <= len(record[key]) <= 128:
            raise JournalError("record identity")
    if not _digest(record["source_sha256"]) or not _digest(record["planned_sha256"]):
        raise JournalError("record digest")
    if (not isinstance(record["original_description_b64"], str) or
            not 8 <= len(record["original_description_b64"]) <= 1_400_000):
        raise JournalError("record description")
    try:
        description = base64.b64decode(record["original_description_b64"], validate=True)
    except (binascii.Error, ValueError) as error:
        raise JournalError("record description") from error
    if not 8 <= len(description) <= 1_048_576 or not description.startswith(b"bplist00"):
        raise JournalError("record description")
    try:
        decoded = plistlib.loads(description)
    except (ValueError, TypeError, plistlib.InvalidFileException) as error:
        raise JournalError("record description plist") from error
    if not isinstance(decoded, dict) or not 1 <= len(decoded) <= 64:
        raise JournalError("record description shape")
    if (type(record["lease_deadline_ns"]) is not int or
            record["lease_deadline_ns"] <= 0):
        raise JournalError("record lease")
    proof = record["external_proof_sha256"]
    if (record["phase"] == "restored") != _digest(proof):
        raise JournalError("record proof")
    if record["phase"] != "restored" and proof is not None:
        raise JournalError("unexpected proof")
    return record


def _seal(record):
    validate(record)
    payload = _canonical(record)
    envelope = {"record": record, "sha256": hashlib.sha256(payload).hexdigest()}
    data = _canonical(envelope)
    if len(data) > MAX_BYTES:
        raise JournalError("journal too large")
    return data


def _unseal(data):
    try:
        envelope = json.loads(data, object_pairs_hook=_pairs_unique)
        if (not isinstance(envelope, dict) or set(envelope) != {"record", "sha256"} or
                _canonical(envelope) != data or
                not _digest(envelope["sha256"]) or
                hashlib.sha256(_canonical(envelope["record"])).hexdigest() != envelope["sha256"]):
            raise JournalError("corrupt envelope")
        return validate(envelope["record"])
    except (UnicodeError, ValueError, TypeError) as error:
        raise JournalError("corrupt journal") from error


def _write_all(fd, data):
    offset = 0
    while offset < len(data):
        count = os.write(fd, data[offset:])
        if count <= 0:
            raise JournalError("short write")
        offset += count


class RestoreJournal:
    def __init__(self, directory, expected_uid=0):
        self.directory = directory
        self.expected_uid = expected_uid

    def _dir(self):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.expected_uid or
                stat.S_IMODE(info.st_mode) != 0o700):
            os.close(fd)
            raise JournalError("unsafe directory")
        return fd

    def _temp(self, directory_fd, data):
        name = ".restore-journal-" + uuid.uuid4().hex
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        try:
            _write_all(fd, data)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            os.unlink(name, dir_fd=directory_fd)
            raise
        os.close(fd)
        return name

    def read(self):
        directory_fd = self._dir()
        try:
            fd = os.open(FILENAME, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid or
                        info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                        not 1 <= info.st_size <= MAX_BYTES):
                    raise JournalError("unsafe journal")
                chunks = bytearray()
                while len(chunks) < info.st_size:
                    block = os.read(fd, info.st_size - len(chunks))
                    if not block:
                        raise JournalError("short journal")
                    chunks.extend(block)
                if os.read(fd, 1):
                    raise JournalError("growing journal")
                return _unseal(bytes(chunks))
            finally:
                os.close(fd)
        finally:
            os.close(directory_fd)

    def create(self, record):
        data = _seal(record)
        directory_fd = self._dir()
        try:
            name = self._temp(directory_fd, data)
            try:
                os.link(name, FILENAME, src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd, follow_symlinks=False)
                os.fsync(directory_fd)
            finally:
                os.unlink(name, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)

    def _locked(self, operation):
        directory_fd = self._dir()
        try:
            fd = os.open(LOCKNAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid or
                        info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                    raise JournalError("unsafe lock")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return operation(directory_fd)
            finally:
                os.close(fd)
        finally:
            os.close(directory_fd)

    def transition(self, expected, next_record):
        validate(expected)
        data = _seal(next_record)
        if ((expected["phase"], next_record["phase"]) not in TRANSITIONS or
                any(expected[key] != next_record[key] for key in FIELDS -
                    {"phase", "external_proof_sha256"})):
            raise JournalError("invalid transition")

        def operation(directory_fd):
            if self.read() != expected:
                raise JournalError("journal changed")
            name = self._temp(directory_fd, data)
            try:
                os.replace(name, FILENAME, src_dir_fd=directory_fd,
                           dst_dir_fd=directory_fd)
                os.fsync(directory_fd)
            finally:
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
        self._locked(operation)

    def remove_verified(self, expected):
        validate(expected)
        if expected["phase"] != "restored":
            raise JournalError("unverified restore")

        def operation(directory_fd):
            if self.read() != expected:
                raise JournalError("journal changed")
            os.unlink(FILENAME, dir_fd=directory_fd)
            os.fsync(directory_fd)
        self._locked(operation)
