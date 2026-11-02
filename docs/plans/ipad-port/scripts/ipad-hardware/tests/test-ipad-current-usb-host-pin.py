#!/usr/bin/env python3
"""Hermetic checks for USB-bound current host-pin publication."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[6]
RUNNER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/pin-current-usb-ssh-host.sh"
LINK_HELPER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/exact-link-no-replace.py"
CANONICAL_HELPER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/canonicalize-usb-known-hosts.py"
ED25519 = b"[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaFixtureEd25519\n"
ECDSA = b"[127.0.0.1]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNhFixtureEcdsa==\n"
PIN = ED25519
CAPTURE = b"# 127.0.0.1:2222 SSH-2.0-OpenSSH_fixture\n" + ED25519


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


def prepare(root: Path, mode: str) -> tuple[Path, Path]:
    runner = root / RUNNER.name
    link_helper = root / LINK_HELPER.name
    canonical_helper = root / CANONICAL_HELPER.name
    shutil.copyfile(LINK_HELPER, link_helper)
    shutil.copyfile(CANONICAL_HELPER, canonical_helper)
    if mode == "staging-failure":
        canonical_helper.chmod(0o000)
    scanner = root / "ssh-keyscan"
    destination = root / "known-hosts"

    scanner_prefix = (
        "#!/bin/sh\n"
        "set +euxv\n"
        "[ \"$*\" = '-T 5 -p 2222 -t ed25519 127.0.0.1' ] || exit 64\n"
    )
    if mode == "directory-race":
        scanner_prefix += f"/bin/mkdir {str(destination)!r} || exit 1\n"
    if mode == "scanner-failure":
        scanner_body = scanner_prefix + "exit 1\n"
    elif mode == "missing-ed25519":
        scanner_body = scanner_prefix + f"/usr/bin/printf '%s\\n' {ECDSA.decode().rstrip()!r}\n"
    else:
        scanner_body = scanner_prefix + f"/usr/bin/printf '%b' {CAPTURE.decode()!r}\n"
    write_executable(scanner, scanner_body)

    python = Path("/usr/bin/python3")
    if mode == "linked-then-killed":
        python = root / "python-after-link-failure"
        write_executable(
            python,
            "#!/bin/sh\n"
            "set +euxv\n"
            "case \"$4\" in\n"
            "  */canonicalize-usb-known-hosts.py) "
            "exec /usr/bin/python3 -I -S -B \"$4\" \"$5\" \"$6\" ;;\n"
            "esac\n"
            "exec /usr/bin/python3 -I -S -c "
            "'import os,signal,sys; os.link(sys.argv[1],sys.argv[2]); "
            "os.kill(os.getpid(),signal.SIGKILL)' \"$5\" \"$6\"\n",
        )

    source = RUNNER.read_text(encoding="utf-8")
    replacements = {
        "readonly ssh_keyscan='/usr/bin/ssh-keyscan'": f"readonly ssh_keyscan='{scanner}'",
        "readonly python='/usr/bin/python3'": f"readonly python='{python}'",
        "readonly expected_ssh_keyscan_sha='05aa5eeca64dd2e610932b08accd02f905417972b583e0b5af2e46cd574eb093'": (
            f"readonly expected_ssh_keyscan_sha='{digest(scanner)}'"
        ),
        "readonly expected_python_sha='34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2'": (
            f"readonly expected_python_sha='{digest(python)}'"
        ),
        "readonly destination='/tmp/mac2jb-ipad-known-hosts'": f"readonly destination='{destination}'",
        "/tmp/mac2jb-current-usb-host-pin.XXXXXX": f"{root}/pin.XXXXXX",
        "/tmp/mac2jb-current-usb-host-pin.*": f"{root}/pin.*",
    }
    for old, new in replacements.items():
        source = replace_once(source, old, new)
    runner.write_text(source, encoding="utf-8")
    return runner, destination


def execute(
    mode: str,
) -> tuple[subprocess.CompletedProcess[bytes], Path, list[Path], Path]:
    temporary = tempfile.TemporaryDirectory(prefix="mac2jb-current-usb-pin-test.")
    root = Path(temporary.name)
    runner, destination = prepare(root, mode)
    environment = os.environ.copy()
    poison_marker = root / "perl-startup-ran"
    if mode == "hostile-perl":
        poison = root / "perl-poison"
        poison.mkdir()
        (poison / "Mac2JBPoison.pm").write_text(
            "package Mac2JBPoison; BEGIN { open(my $fh, '>', "
            f"{str(poison_marker)!r}) or die; print $fh 'ran'; close($fh); }} 1;\n",
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
    leftovers = list(root.glob("pin.*"))
    result._temporary_directory = temporary  # type: ignore[attr-defined]
    return result, destination, leftovers, poison_marker


def test_normal_publication() -> None:
    result, destination, leftovers, _ = execute("normal")
    expect(result.returncode == 0, f"normal exit {result.returncode}: {result.stderr!r}")
    expect(result.stdout == b"", "normal run emitted stdout")
    expect(destination.read_bytes() == PIN, "published pin was not canonical")
    expect(destination.lstat().st_uid == os.getuid(), "published owner changed")
    expect(destination.stat().st_mode & 0o777 == 0o600, "published mode changed")
    expect(not leftovers, f"normal run left temporaries: {leftovers}")


def test_linked_child_failure_is_reconciled() -> None:
    result, destination, leftovers, _ = execute("linked-then-killed")
    expect(result.returncode == 0, f"post-link failure was not reconciled: {result.stderr!r}")
    expect(destination.read_bytes() == PIN, "reconciled pin changed")
    expect(not leftovers, f"reconciled run left temporaries: {leftovers}")


def test_failure_paths_publish_nothing() -> None:
    for mode in ("scanner-failure", "missing-ed25519", "directory-race", "staging-failure"):
        result, destination, leftovers, _ = execute(mode)
        expect(result.returncode != 0, f"{mode} falsely passed")
        if mode == "directory-race":
            expect(destination.is_dir(), "directory race target changed")
            expect(not (destination / "known-hosts").exists(), "directory semantics created child")
        else:
            expect(not destination.exists(), f"{mode} published a pin")
        if mode == "staging-failure":
            expect(result.stdout == b"" and result.stderr == b"", "staging failure leaked diagnostics")
        expect(not leftovers, f"{mode} left temporaries: {leftovers}")


def test_hostile_perl_startup_is_ignored() -> None:
    result, destination, leftovers, poison_marker = execute("hostile-perl")
    expect(result.returncode == 0, f"hostile environment affected run: {result.stderr!r}")
    expect(destination.read_bytes() == PIN, "hostile environment changed pin")
    expect(not poison_marker.exists(), "inherited Perl startup code executed")
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
    expect(
        'current_uid=$(/usr/bin/id -u 2>/dev/null) || exit 65' in source,
        "current-UID diagnostic suppression is missing",
    )


def main() -> None:
    tests = [
        test_normal_publication,
        test_linked_child_failure_is_reconciled,
        test_failure_paths_publish_nothing,
        test_hostile_perl_startup_is_ignored,
        test_shell_diagnostic_suppression_order,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print("PASS current USB host-pin publisher (5 groups / 10 scenarios)")


if __name__ == "__main__":
    main()
