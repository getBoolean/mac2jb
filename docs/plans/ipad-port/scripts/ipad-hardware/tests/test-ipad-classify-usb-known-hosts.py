#!/usr/bin/env python3
"""Hermetic checks for redacted USB host-key classification."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[6]
HELPER = ROOT / "scripts/ipad-hardware/host/classify-usb-known-hosts.py"
STANDARD = b"[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaFixtureEd25519\n"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def invoke(capture: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin",
            "LC_ALL=C",
            "TMPDIR=/tmp",
            "/usr/bin/python3",
            "-I",
            "-S",
            "-B",
            str(HELPER),
            str(capture),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=False,
    )


def expected(*, count: str, newline: str, carriage: str, nul: str, fields: str, host: str, algorithm: str, key: str) -> bytes:
    return (
        "capture-status: classified\n"
        f"record-count: {count}\n"
        f"trailing-newline: {newline}\n"
        f"carriage-return: {carriage}\n"
        f"nul-byte: {nul}\n"
        f"field-shape: {fields}\n"
        f"host-form: {host}\n"
        f"algorithm-form: {algorithm}\n"
        f"key-data-form: {key}\n"
    ).encode("ascii")


def classify(content: bytes, mode: int = 0o600) -> subprocess.CompletedProcess[bytes]:
    temporary = tempfile.TemporaryDirectory(prefix="mac2jb-key-classifier-test.")
    capture = Path(temporary.name) / "capture"
    capture.write_bytes(content)
    capture.chmod(mode)
    result = invoke(capture)
    result._temporary_directory = temporary  # type: ignore[attr-defined]
    return result


def test_standard_record() -> None:
    result = classify(STANDARD)
    expect(result.returncode == 0, result.stderr.decode(errors="replace"))
    expect(result.stderr == b"", "classifier emitted stderr")
    expect(
        result.stdout
        == expected(
            count="one",
            newline="yes",
            carriage="absent",
            nul="absent",
            fields="three",
            host="bracketed-loopback-port",
            algorithm="ed25519",
            key="base64",
        ),
        result.stdout.decode(errors="replace"),
    )


def test_alternate_shapes_are_redacted() -> None:
    scenarios = [
        (
            b"127.0.0.1 ssh-ed25519 AAAA\n",
            expected(count="one", newline="yes", carriage="absent", nul="absent", fields="three", host="plain-loopback", algorithm="ed25519", key="base64"),
        ),
        (
            STANDARD + b"# banner\n",
            expected(count="two-to-five", newline="yes", carriage="absent", nul="absent", fields="mixed", host="mixed", algorithm="mixed", key="mixed"),
        ),
        (
            STANDARD.rstrip(b"\n") + b"\r\x00",
            expected(count="two-to-five", newline="no", carriage="present", nul="present", fields="mixed", host="mixed", algorithm="mixed", key="other"),
        ),
    ]
    for content, wanted in scenarios:
        result = classify(content)
        expect(result.returncode == 0, "alternate capture was not classified")
        expect(result.stdout == wanted, result.stdout.decode(errors="replace"))
        expect(b"AAA" not in result.stdout, "key material leaked")


def test_file_guards() -> None:
    result = classify(STANDARD, mode=0o644)
    expect(result.returncode != 0, "wrong-mode capture passed")
    expect(result.stdout == b"" and result.stderr == b"", "guard failure emitted data")

    with tempfile.TemporaryDirectory(prefix="mac2jb-key-classifier-test.") as temporary:
        root = Path(temporary)
        real_capture = root / "real"
        real_capture.write_bytes(STANDARD)
        real_capture.chmod(0o600)
        capture = root / "capture"
        capture.symlink_to(real_capture)
        result = invoke(capture)
        expect(result.returncode != 0, "symlink capture passed")
        expect(result.stdout == b"" and result.stderr == b"", "symlink failure emitted data")


def main() -> None:
    tests = [test_standard_record, test_alternate_shapes_are_redacted, test_file_guards]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print("PASS USB known-hosts classifier (3 groups / 6 scenarios)")


if __name__ == "__main__":
    main()
