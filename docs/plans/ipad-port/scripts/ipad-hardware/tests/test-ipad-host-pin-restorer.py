#!/usr/bin/env python3
"""Hermetic checks for the host-pin restoration wrapper."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[6]
RESTORER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/restore-pinned-known-hosts.sh"
HELPER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/exact-link-no-replace.py"
RECONSTRUCT_HELPER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/reconstruct-pinned-known-hosts.py"
PIN = b"[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaFixtureHostKey\n"


def digest(path_or_bytes: Path | bytes) -> str:
    value = path_or_bytes.read_bytes() if isinstance(path_or_bytes, Path) else path_or_bytes
    return hashlib.sha256(value).hexdigest()


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
    runner = root / "restore-pinned-known-hosts.sh"
    helper = root / HELPER.name
    reconstruct_helper = root / RECONSTRUCT_HELPER.name
    shutil.copyfile(HELPER, helper)
    shutil.copyfile(RECONSTRUCT_HELPER, reconstruct_helper)
    scanner = root / "ssh-keyscan"
    destination = root / "known-hosts"

    scanner_prefix = "#!/bin/sh\nset +euxv\n"
    if mode == "directory-race":
        scanner_prefix += f"/bin/mkdir {str(destination)!r} || exit 1\n"
    if mode == "scanner-failure":
        scanner_body = scanner_prefix + "exit 1\n"
    elif mode == "pin-mismatch":
        scanner_body = scanner_prefix + "/usr/bin/printf '%s\\n' 'different'\n"
    else:
        scanner_body = (
            scanner_prefix
            + f"/usr/bin/printf '%s\\n' {PIN.decode('ascii').rstrip()!r}\n"
        )
    write_executable(scanner, scanner_body)

    python = Path("/usr/bin/python3")
    if mode == "linked-then-killed":
        python = root / "python-after-link-failure"
        write_executable(
            python,
            "#!/bin/sh\n"
            "set +euxv\n"
            "case \"$4\" in\n"
            "  */reconstruct-pinned-known-hosts.py) "
            "exec /usr/bin/python3 -I -S -B \"$4\" \"$5\" \"$6\" \"$7\" ;;\n"
            "esac\n"
            "exec /usr/bin/python3 -I -S -c "
            "'import os,signal,sys; os.link(sys.argv[1],sys.argv[2]); "
            "os.kill(os.getpid(),signal.SIGKILL)' \"$5\" \"$6\"\n",
        )

    source = RESTORER.read_text(encoding="utf-8")
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
        "readonly expected_pin_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'": (
            f"readonly expected_pin_sha='{digest(PIN)}'"
        ),
        "/tmp/mac2jb-ipad-host-pin.XXXXXX": f"{root}/pin.XXXXXX",
        "/tmp/mac2jb-ipad-host-pin.*": f"{root}/pin.*",
    }
    for old, new in replacements.items():
        source = replace_once(source, old, new)
    runner.write_text(source, encoding="utf-8")
    return runner, destination


def execute(
    mode: str,
) -> tuple[subprocess.CompletedProcess[bytes], Path, list[Path], Path]:
    temporary = tempfile.TemporaryDirectory(prefix="mac2jb-host-pin-test.")
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
    expect(destination.read_bytes() == PIN, "published pin changed")
    expect(destination.lstat().st_uid == os.getuid(), "published pin owner changed")
    expect(destination.stat().st_mode & 0o777 == 0o600, "published pin mode changed")
    expect(not leftovers, f"normal run left temporaries: {leftovers}")


def test_linked_child_failure_is_reconciled() -> None:
    result, destination, leftovers, _ = execute("linked-then-killed")
    expect(result.returncode == 0, f"post-link child failure was not reconciled: {result.stderr!r}")
    expect(destination.read_bytes() == PIN, "reconciled pin changed")
    expect(not leftovers, f"reconciled run left temporaries: {leftovers}")


def test_failure_paths_publish_nothing() -> None:
    for mode in ("scanner-failure", "pin-mismatch", "directory-race"):
        result, destination, leftovers, _ = execute(mode)
        expect(result.returncode != 0, f"{mode} falsely passed")
        if mode == "directory-race":
            expect(destination.is_dir(), "directory race target changed")
            expect(not (destination / "known-hosts").exists(), "directory semantics created child")
        else:
            expect(not destination.exists(), f"{mode} published a pin")
        expect(not leftovers, f"{mode} left temporaries: {leftovers}")


def test_hostile_perl_startup_is_ignored() -> None:
    result, destination, leftovers, poison_marker = execute("hostile-perl")
    expect(result.returncode == 0, f"hostile Perl environment affected run: {result.stderr!r}")
    expect(destination.read_bytes() == PIN, "hostile environment changed pin")
    expect(not poison_marker.exists(), "inherited Perl startup code executed")
    expect(not leftovers, f"hostile environment left temporaries: {leftovers}")


def main() -> None:
    tests = [
        test_normal_publication,
        test_linked_child_failure_is_reconciled,
        test_failure_paths_publish_nothing,
        test_hostile_perl_startup_is_ignored,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print("PASS host-pin restorer (4 groups / 6 scenarios)")


if __name__ == "__main__":
    main()
