#!/usr/bin/env python3
"""Hermetic checks for USB-bound SSH host-key canonicalization."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[6]
HELPER = ROOT / "scripts/ipad-hardware/host/canonicalize-usb-known-hosts.py"
ED25519 = b"[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaFixtureEd25519\n"
ECDSA = b"[127.0.0.1]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNhFixtureEcdsa==\n"
RSA = b"[127.0.0.1]:2222 ssh-rsa AAAAB3NzaFixtureRsa\n"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def invoke(
    capture: Path,
    output: Path,
    *,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    child_environment = os.environ.copy()
    if environment:
        child_environment.update(environment)
    result = subprocess.run(
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
            str(output),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_environment,
        timeout=3,
        check=False,
    )
    expect(result.stdout == b"", "helper emitted stdout")
    expect(result.stderr == b"", "helper emitted stderr")
    return result


def write_capture(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.write_bytes(content)
    path.chmod(mode)


def test_canonical_order() -> None:
    for capture_bytes in (
        ED25519,
        RSA + ED25519 + ECDSA,
        ECDSA + ED25519,
        b"# 127.0.0.1:2222 SSH-2.0-OpenSSH_fixture\n" + ED25519,
    ):
        with tempfile.TemporaryDirectory(prefix="mac2jb-usb-pin-test.") as temporary:
            root = Path(temporary)
            capture = root / "capture"
            output = root / "output"
            write_capture(capture, capture_bytes)
            result = invoke(capture, output)
            expect(result.returncode == 0, "valid key set failed")
            expected = b"".join(record for record in (ED25519, ECDSA, RSA) if record in capture_bytes)
            expect(output.read_bytes() == expected, "canonical order changed")
            expect(output.stat().st_mode & 0o777 == 0o600, "wrong output mode")


def test_malformed_or_weak_sets_rejected() -> None:
    malformed = [
        ECDSA + RSA,
        ED25519.replace(b"127.0.0.1", b"127.0.0.2"),
        ED25519.replace(b"ssh-ed25519", b"ssh-dss"),
        ED25519 + ED25519,
        ED25519.rstrip(b"\n"),
        ED25519.replace(b"\n", b" comment\n"),
        ED25519.replace(b"\n", b"\r\n"),
    ]
    for content in malformed:
        with tempfile.TemporaryDirectory(prefix="mac2jb-usb-pin-test.") as temporary:
            root = Path(temporary)
            capture = root / "capture"
            output = root / "output"
            write_capture(capture, content)
            result = invoke(capture, output)
            expect(result.returncode != 0, f"malformed capture passed: {content!r}")
            expect(not output.exists(), "malformed capture produced output")


def test_input_and_destination_guards() -> None:
    for kind in ("wrong-mode", "source-symlink", "source-hardlink", "output-exists"):
        with tempfile.TemporaryDirectory(prefix="mac2jb-usb-pin-test.") as temporary:
            root = Path(temporary)
            capture = root / "capture"
            output = root / "output"
            write_capture(capture, ED25519)
            if kind == "wrong-mode":
                capture.chmod(0o644)
            elif kind == "source-symlink":
                real_capture = root / "real-capture"
                capture.rename(real_capture)
                capture.symlink_to(real_capture)
            elif kind == "source-hardlink":
                os.link(capture, root / "prior-link")
            else:
                output.write_bytes(b"keep\n")
            result = invoke(capture, output)
            expect(result.returncode != 0, f"{kind} falsely passed")
            if kind == "output-exists":
                expect(output.read_bytes() == b"keep\n", "existing output changed")
            else:
                expect(not output.exists(), f"{kind} created output")


def test_python_environment_isolation() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-usb-pin-test.") as temporary:
        root = Path(temporary)
        capture = root / "capture"
        output = root / "output"
        write_capture(capture, ED25519)
        poison = root / "poison"
        poison.mkdir()
        marker = root / "sitecustomize-ran"
        (poison / "sitecustomize.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        result = invoke(
            capture,
            output,
            environment={"PYTHONPATH": str(poison), "PYTHONUSERBASE": str(poison)},
        )
        expect(result.returncode == 0, "isolated canonicalization failed")
        expect(not marker.exists(), "Python startup customization executed")


def main() -> None:
    tests = [
        test_canonical_order,
        test_malformed_or_weak_sets_rejected,
        test_input_and_destination_guards,
        test_python_environment_isolation,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print("PASS USB known-hosts canonicalizer (4 groups / 16 scenarios)")


if __name__ == "__main__":
    main()
