#!/usr/bin/python3
"""Canonicalize SSH host keys observed through the pinned physical USB tunnel.

The input must contain only a small strict set of public host-key records for
the fixed localhost tunnel endpoint and must include Ed25519. Records are sorted
by a fixed algorithm order and written once to a private exclusive output. This
does not authenticate to SSH, trust a network-discovered host, or modify the
iPad. The physical-device binding belongs to the separately reviewed iproxy
launcher and is an explicit prerequisite of the caller.

No key, path, or diagnostic is emitted. The output is removed on write/fsync
failure and is independently hashed before publication by the caller.
"""

from __future__ import annotations

import os
import re
import stat
import sys


MAX_CAPTURE = 16 * 1024
MAX_RECORDS = 5
EXPECTED_HOST = b"[127.0.0.1]:2222"
ALGORITHM_ORDER = (
    b"ssh-ed25519",
    b"ecdsa-sha2-nistp256",
    b"ssh-rsa",
    b"sk-ssh-ed25519@openssh.com",
    b"sk-ecdsa-sha2-nistp256@openssh.com",
)
ALGORITHMS = frozenset(ALGORITHM_ORDER)
KEY_DATA = re.compile(rb"[A-Za-z0-9+/]+={0,2}")


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


def canonicalize(capture: bytes) -> bytes:
    if not capture.endswith(b"\n") or b"\r" in capture or b"\x00" in capture:
        raise ValueError
    scanned_records = capture.splitlines(keepends=True)
    if not 1 <= len(scanned_records) <= MAX_RECORDS:
        raise ValueError
    records = [record for record in scanned_records if not record.startswith(b"# ")]
    if not records:
        raise ValueError
    by_algorithm: dict[bytes, bytes] = {}
    for record in records:
        if len(record) > 4096 or not record.endswith(b"\n"):
            raise ValueError
        fields = record[:-1].split(b" ")
        if len(fields) != 3 or fields[0] != EXPECTED_HOST:
            raise ValueError
        algorithm, key_data = fields[1], fields[2]
        if algorithm not in ALGORITHMS or algorithm in by_algorithm:
            raise ValueError
        if KEY_DATA.fullmatch(key_data) is None:
            raise ValueError
        by_algorithm[algorithm] = record
    if b"ssh-ed25519" not in by_algorithm:
        raise ValueError
    return b"".join(by_algorithm[algorithm] for algorithm in ALGORITHM_ORDER if algorithm in by_algorithm)


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
    if len(sys.argv) != 3:
        return 1
    try:
        capture = read_private_regular(sys.argv[1])
        canonical = canonicalize(capture)
        write_exclusive(sys.argv[2], canonical)
    except (OSError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
