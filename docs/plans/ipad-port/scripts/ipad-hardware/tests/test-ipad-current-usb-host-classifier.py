#!/usr/bin/env python3
"""Hermetic checks for the USB host-key classification wrapper."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[6]
RUNNER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/classify-current-usb-ssh-host.sh"
CLASSIFIER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/classify-usb-known-hosts.py"
STANDARD = b"[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaFixtureEd25519\n"
STANDARD_OUTPUT = (
    b"capture-status: classified\n"
    b"record-count: one\n"
    b"trailing-newline: yes\n"
    b"carriage-return: absent\n"
    b"nul-byte: absent\n"
    b"field-shape: three\n"
    b"host-form: bracketed-loopback-port\n"
    b"algorithm-form: ed25519\n"
    b"key-data-form: base64\n"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def replace_once(source: str, old: str, new: str) -> str:
    expect(source.count(old) == 1, f"replacement count for {old!r}")
    return source.replace(old, new)


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o555)


def prepare(root: Path, mode: str) -> Path:
    runner = root / RUNNER.name
    classifier = root / CLASSIFIER.name
    shutil.copyfile(CLASSIFIER, classifier)
    if mode == "staging-failure":
        classifier.chmod(0o000)
    scanner = root / "ssh-keyscan"
    scanner_prefix = (
        "#!/bin/sh\n"
        "set +euxv\n"
        "[ \"$*\" = '-T 5 -p 2222 -t ed25519 127.0.0.1' ] || exit 64\n"
    )
    if mode == "scanner-failure":
        scanner_body = scanner_prefix + "exit 1\n"
    elif mode == "plain-host":
        scanner_body = scanner_prefix + "/usr/bin/printf '%s\\n' '127.0.0.1 ssh-ed25519 AAAA'\n"
    else:
        scanner_body = scanner_prefix + f"/usr/bin/printf '%s\\n' {STANDARD.decode().rstrip()!r}\n"
    write_executable(scanner, scanner_body)

    source = RUNNER.read_text(encoding="utf-8")
    replacements = {
        "readonly ssh_keyscan='/usr/bin/ssh-keyscan'": f"readonly ssh_keyscan='{scanner}'",
        "readonly expected_ssh_keyscan_sha='05aa5eeca64dd2e610932b08accd02f905417972b583e0b5af2e46cd574eb093'": (
            f"readonly expected_ssh_keyscan_sha='{digest(scanner)}'"
        ),
        "/tmp/mac2jb-usb-host-classify.XXXXXX": f"{root}/classify.XXXXXX",
        "/tmp/mac2jb-usb-host-classify.*": f"{root}/classify.*",
    }
    for old, new in replacements.items():
        source = replace_once(source, old, new)
    runner.write_text(source, encoding="utf-8")
    return runner


def execute(mode: str) -> tuple[subprocess.CompletedProcess[bytes], list[Path], Path]:
    temporary = tempfile.TemporaryDirectory(prefix="mac2jb-usb-classifier-test.")
    root = Path(temporary.name)
    runner = prepare(root, mode)
    environment = os.environ.copy()
    marker = root / "perl-startup-ran"
    if mode == "hostile-perl":
        poison = root / "perl-poison"
        poison.mkdir()
        (poison / "Mac2JBPoison.pm").write_text(
            "package Mac2JBPoison; BEGIN { open(my $fh, '>', "
            f"{str(marker)!r}) or die; print $fh 'ran'; close($fh); }} 1;\n",
            encoding="utf-8",
        )
        environment["PERL5LIB"] = str(poison)
        environment["PERL5OPT"] = "-MMac2JBPoison"
    result = subprocess.run(
        [
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "LC_ALL=C",
            "TMPDIR=/tmp",
            "/bin/sh",
            str(runner),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=5,
        check=False,
    )
    leftovers = list(root.glob("classify.*"))
    result._temporary_directory = temporary  # type: ignore[attr-defined]
    return result, leftovers, marker


def test_standard_classification() -> None:
    result, leftovers, _ = execute("normal")
    expect(result.returncode == 0, result.stderr.decode(errors="replace"))
    expect(result.stdout == STANDARD_OUTPUT, result.stdout.decode(errors="replace"))
    expect(b"AAA" not in result.stdout, "key material leaked")
    expect(not leftovers, f"left temporaries: {leftovers}")


def test_shape_and_failure_classification() -> None:
    result, leftovers, _ = execute("plain-host")
    expect(result.returncode == 0, "plain host classification failed")
    expect(b"host-form: plain-loopback\n" in result.stdout, "plain host was not classified")
    expect(b"AAA" not in result.stdout, "plain host leaked key material")
    expect(not leftovers, f"plain host left temporaries: {leftovers}")

    result, leftovers, _ = execute("scanner-failure")
    expect(result.returncode != 0, "scanner failure falsely passed")
    expect(result.stdout == b"", "scanner failure emitted capture")
    expect(not leftovers, f"scanner failure left temporaries: {leftovers}")

    result, leftovers, _ = execute("staging-failure")
    expect(result.returncode != 0, "staging failure falsely passed")
    expect(result.stdout == b"" and result.stderr == b"", "staging failure leaked diagnostics")
    expect(not leftovers, f"staging failure left temporaries: {leftovers}")


def test_hostile_perl_startup_is_ignored() -> None:
    result, leftovers, marker = execute("hostile-perl")
    expect(result.returncode == 0, result.stderr.decode(errors="replace"))
    expect(result.stdout == STANDARD_OUTPUT, "hostile environment changed output")
    expect(not marker.exists(), "inherited Perl startup code executed")
    expect(not leftovers, f"hostile environment left temporaries: {leftovers}")


def test_shell_diagnostic_suppression_order() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    expect(
        '127.0.0.1 2>/dev/null >"$capture"' in source,
        "capture path is opened before stderr suppression",
    )
    expect(
        '} 2>/dev/null\n) || exit 65' in source,
        "directory-resolution compound command is not fully suppressed",
    )


def main() -> None:
    tests = [
        test_standard_classification,
        test_shape_and_failure_classification,
        test_hostile_perl_startup_is_ignored,
        test_shell_diagnostic_suppression_order,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print("PASS current USB host classifier (4 groups / 7 scenarios)")


if __name__ == "__main__":
    main()
