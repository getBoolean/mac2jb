#!/usr/bin/python3
"""Reconstruct an earlier known-hosts file from the same current public keys.

`ssh-keyscan` can emit supported key families in a different order, while an
earlier capture may contain only a selected subset. This helper accepts only a
small strict set of localhost known-host records, enumerates permutations of all
nonempty subsets, and writes exactly one private candidate only when its full
SHA-256 equals the caller-supplied prior digest. It cannot approve a changed key,
hostname, algorithm, comment, or byte representation.

No captured key, path, or diagnostic is emitted. The output uses exclusive
creation and is removed on any write or sync failure.
"""

from __future__ import annotations

import hashlib
import itertools
import os
import re
import stat
import sys


MAX_CAPTURE = 16 * 1024
MAX_RECORDS = 5
EXPECTED_HOST = b"[127.0.0.1]:2222"
ALGORITHMS = {
    b"ecdsa-sha2-nistp256",
    b"ssh-ed25519",
    b"sk-ecdsa-sha2-nistp256@openssh.com",
    b"sk-ssh-ed25519@openssh.com",
    b"ssh-rsa",
}
KEY_DATA = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
DIGEST = re.compile(r"[0-9a-f]{64}")


def read_private_regular(path: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError
        if metadata.st_nlink != 1 or metadata.st_size < 1 or metadata.st_size > MAX_CAPTURE:
            raise ValueError
        content = bytearray()
        while len(content) <= MAX_CAPTURE:
            chunk = os.read(descriptor, min(4096, MAX_CAPTURE + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != metadata.st_size or len(content) > MAX_CAPTURE:
            raise ValueError
        return bytes(content)
    finally:
        os.close(descriptor)


def parse_records(capture: bytes) -> list[bytes]:
    if not capture.endswith(b"\n") or b"\r" in capture or b"\x00" in capture:
        raise ValueError
    records = capture.splitlines(keepends=True)
    if not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError
    algorithms: set[bytes] = set()
    for record in records:
        if len(record) > 4096 or not record.endswith(b"\n"):
            raise ValueError
        fields = record[:-1].split(b" ")
        if len(fields) != 3 or fields[0] != EXPECTED_HOST:
            raise ValueError
        algorithm, key_data = fields[1], fields[2]
        if algorithm not in ALGORITHMS or algorithm in algorithms:
            raise ValueError
        if KEY_DATA.fullmatch(key_data) is None:
            raise ValueError
        algorithms.add(algorithm)
    return records


def find_prior_bytes(records: list[bytes], expected_digest: str) -> bytes:
    matches: set[bytes] = set()
    for length in range(1, len(records) + 1):
        for ordering in itertools.permutations(records, length):
            candidate = b"".join(ordering)
            if hashlib.sha256(candidate).hexdigest() == expected_digest:
                matches.add(candidate)
    if len(matches) != 1:
        raise ValueError
    return matches.pop()


def write_exclusive(path: str, content: bytes) -> None:
    parent = os.path.dirname(path) or "."
    parent_metadata = os.lstat(parent)
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise ValueError
    if parent_metadata.st_uid != os.getuid() or stat.S_IMODE(parent_metadata.st_mode) != 0o700:
        raise ValueError
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)


def main() -> int:
    if len(sys.argv) != 4 or DIGEST.fullmatch(sys.argv[3]) is None:
        return 1
    capture_path, output_path, expected_digest = sys.argv[1:]
    try:
        capture = read_private_regular(capture_path)
        records = parse_records(capture)
        prior_bytes = find_prior_bytes(records, expected_digest)
        write_exclusive(output_path, prior_bytes)
    except (OSError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
