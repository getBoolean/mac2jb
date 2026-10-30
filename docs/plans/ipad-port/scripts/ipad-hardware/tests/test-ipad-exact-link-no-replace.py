#!/usr/bin/env python3
"""Hermetic checks for exact-path, no-replace host-pin publication."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[6]
HELPER = ROOT / "scripts/ipad-hardware/host/exact-link-no-replace.py"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run(
    *arguments: Path,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    if extra_environment:
        environment.update(extra_environment)
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
            *(str(argument) for argument in arguments),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=3,
        check=False,
    )
    expect(result.stdout == b"", "helper emitted stdout")
    expect(result.stderr == b"", "helper emitted stderr")
    return result


def make_source(root: Path, name: str = "source") -> Path:
    source = root / name
    source.write_bytes(b"reviewed public host-key fixture\n")
    source.chmod(0o600)
    return source


def test_success() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-exact-link-test.") as temporary:
        root = Path(temporary)
        source = make_source(root)
        destination = root / "destination"
        result = run(source, destination)
        expect(result.returncode == 0, "valid exact link failed")
        source_stat = source.lstat()
        destination_stat = destination.lstat()
        expect(source_stat.st_ino == destination_stat.st_ino, "published a different inode")
        expect(source_stat.st_nlink == 2, "link count was not two")
        expect(destination.read_bytes() == source.read_bytes(), "published bytes changed")


def test_existing_targets_rejected() -> None:
    for kind in ("file", "directory", "directory-symlink", "dangling-symlink"):
        with tempfile.TemporaryDirectory(prefix="mac2jb-exact-link-test.") as temporary:
            root = Path(temporary)
            source = make_source(root)
            destination = root / "destination"
            nested = destination / source.name
            if kind == "file":
                destination.write_bytes(b"keep\n")
            elif kind == "directory":
                destination.mkdir()
            elif kind == "directory-symlink":
                target = root / "target-directory"
                target.mkdir()
                destination.symlink_to(target, target_is_directory=True)
                nested = target / source.name
            else:
                destination.symlink_to(root / "missing")
            result = run(source, destination)
            expect(result.returncode != 0, f"{kind} target was replaced")
            expect(source.lstat().st_nlink == 1, f"{kind} created a hard link")
            expect(not nested.exists(), f"{kind} triggered target-directory semantics")
            if kind == "file":
                expect(destination.read_bytes() == b"keep\n", "existing file changed")


def test_invalid_sources_rejected() -> None:
    for kind in ("symlink", "wrong-mode", "already-linked"):
        with tempfile.TemporaryDirectory(prefix="mac2jb-exact-link-test.") as temporary:
            root = Path(temporary)
            real_source = make_source(root, "real-source")
            source = real_source
            if kind == "symlink":
                source = root / "source"
                source.symlink_to(real_source)
            elif kind == "wrong-mode":
                source.chmod(0o644)
            else:
                os.link(source, root / "prior-link")
            destination = root / "destination"
            result = run(source, destination)
            expect(result.returncode != 0, f"{kind} source was accepted")
            expect(not destination.exists(), f"{kind} source created destination")


def test_argument_rejection() -> None:
    result = run()
    expect(result.returncode != 0, "missing arguments were accepted")


def test_python_environment_isolation() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-exact-link-test.") as temporary:
        root = Path(temporary)
        source = make_source(root)
        destination = root / "destination"
        poison = root / "poison"
        poison.mkdir()
        marker = root / "sitecustomize-ran"
        (poison / "sitecustomize.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        result = run(
            source,
            destination,
            extra_environment={"PYTHONPATH": str(poison), "PYTHONUSERBASE": str(poison)},
        )
        expect(result.returncode == 0, "isolated helper invocation failed")
        expect(not marker.exists(), "inherited Python customization executed")


def main() -> None:
    tests = [
        test_success,
        test_existing_targets_rejected,
        test_invalid_sources_rejected,
        test_argument_rejection,
        test_python_environment_isolation,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print("PASS exact-link helper (5 groups / 10 scenarios)")


if __name__ == "__main__":
    main()
