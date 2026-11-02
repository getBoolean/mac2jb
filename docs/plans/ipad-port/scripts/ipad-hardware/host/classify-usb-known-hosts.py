#!/usr/bin/python3
"""Classify a private ssh-keyscan capture without emitting key material."""

from __future__ import annotations

import os
import re
import stat
import sys


MAX_CAPTURE = 16 * 1024
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


def aggregate(values: list[str]) -> str:
    unique = set(values)
    if len(unique) == 1:
        return unique.pop()
    return "mixed"


def classify(capture: bytes) -> list[str]:
    records = capture.splitlines(keepends=True)
    if len(records) == 1:
        count = "one"
    elif 2 <= len(records) <= 5:
        count = "two-to-five"
    else:
        count = "over-five"

    field_shapes: list[str] = []
    host_forms: list[str] = []
    algorithm_forms: list[str] = []
    key_forms: list[str] = []
    for record in records:
        body = record[:-1] if record.endswith(b"\n") else record
        fields = body.split(b" ")
        field_shapes.append("three" if len(fields) == 3 else "other")
        host = fields[0] if fields else b""
        if host == b"[127.0.0.1]:2222":
            host_forms.append("bracketed-loopback-port")
        elif host == b"127.0.0.1":
            host_forms.append("plain-loopback")
        else:
            host_forms.append("other")
        algorithm = fields[1] if len(fields) > 1 else b""
        algorithm_forms.append("ed25519" if algorithm == b"ssh-ed25519" else "other")
        key_data = fields[2] if len(fields) == 3 else b""
        key_forms.append("base64" if KEY_DATA.fullmatch(key_data) else "other")

    trailing_newline = "yes" if capture.endswith(b"\n") else "no"
    carriage_return = "present" if b"\r" in capture else "absent"
    nul_byte = "present" if b"\x00" in capture else "absent"
    return [
        "capture-status: classified",
        f"record-count: {count}",
        f"trailing-newline: {trailing_newline}",
        f"carriage-return: {carriage_return}",
        f"nul-byte: {nul_byte}",
        f"field-shape: {aggregate(field_shapes)}",
        f"host-form: {aggregate(host_forms)}",
        f"algorithm-form: {aggregate(algorithm_forms)}",
        f"key-data-form: {aggregate(key_forms)}",
    ]


def main() -> int:
    if len(sys.argv) != 2:
        return 1
    try:
        capture = read_private_regular(sys.argv[1])
        lines = classify(capture)
    except (OSError, ValueError):
        return 1
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
