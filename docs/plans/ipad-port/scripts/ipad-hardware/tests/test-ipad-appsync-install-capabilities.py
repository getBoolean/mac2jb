#!/usr/bin/env python3
"""Hermetic tests for the read-only AppSync/appinst capability payload."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time


ROOT = Path(__file__).resolve().parents[6]
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-appsync-install-capabilities.sh"
PACKAGES = {
    "ai.akemi.appsyncunified": ("116.0", "iphoneos-arm64"),
    "ai.akemi.appinst": ("2.1.1", "iphoneos-arm64"),
    "ellekit": ("1.1.2", "iphoneos-arm64"),
}
PATH_LABELS = (
    "appinst-binary",
    "appsync-installd-dylib",
    "appsync-installd-filter",
    "appsync-frontboard-dylib",
    "appsync-frontboard-filter",
)


def write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o555)


def fake_timeout_source() -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import os
        import signal
        import subprocess
        import sys

        if len(sys.argv) < 5 or sys.argv[1] != "-k":
            raise SystemExit(125)
        grace = float(sys.argv[2])
        duration = float(sys.argv[3])
        process = subprocess.Popen(sys.argv[4:], start_new_session=True)
        try:
            status = process.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            raise SystemExit(124)
        if status < 0:
            raise SystemExit(128 - status)
        raise SystemExit(status)
        """
    )


def fake_query_source(
    records: dict[str, tuple[str, str]],
    malformed: bool,
    failure_status: int | None,
    partial_failure: bool,
    newline_only_failure: bool,
    hang_with_descendant: bool,
    descendant_pid_file: Path,
) -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import pathlib
        import subprocess
        import sys
        import time

        records = {records!r}
        failure_status = {failure_status!r}
        package = sys.argv[-1]
        if package == "ai.akemi.appsyncunified" and {hang_with_descendant!r}:
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            pathlib.Path({str(descendant_pid_file)!r}).write_text(str(child.pid), encoding="ascii")
            time.sleep(30)
        if package == "ai.akemi.appsyncunified" and failure_status is not None:
            if {newline_only_failure!r}:
                sys.stdout.write("\\n")
                sys.stdout.flush()
            elif {partial_failure!r}:
                sys.stdout.write("install ok installed|partial|iphoneos-arm64")
                sys.stdout.flush()
            raise SystemExit(failure_status)
        if package not in records:
            raise SystemExit(1)
        version, architecture = records[package]
        if {malformed!r} and package == "ai.akemi.appsyncunified":
            version = "116.0\\nforged"
        sys.stdout.write(f"install ok installed|{{version}}|{{architecture}}")
        """
    )


def prepare(
    root: Path,
    records: dict[str, tuple[str, str]],
    path_modes: dict[str, str],
    *,
    malformed: bool = False,
    query_writable: bool = False,
    failure_status: int | None = None,
    partial_failure: bool = False,
    newline_only_failure: bool = False,
    hang_with_descendant: bool = False,
    parent_observable: bool = True,
) -> tuple[Path, Path, Path]:
    fixtures = root / "fixtures"
    fixtures.mkdir()
    descendant_pid_file = root / "descendant.pid"
    fake_query = root / "dpkg-query"
    write_executable(
        fake_query,
        fake_query_source(
            records,
            malformed,
            failure_status,
            partial_failure,
            newline_only_failure,
            hang_with_descendant,
            descendant_pid_file,
        ),
    )
    if query_writable:
        fake_query.chmod(0o755)
    fake_timeout = root / "timeout"
    write_executable(fake_timeout, fake_timeout_source())

    replacements: dict[str, Path] = {}
    for label in PATH_LABELS:
        path = fixtures / label
        mode = path_modes.get(label, "absent")
        if mode == "readonly-executable":
            write_executable(path, "#!/bin/sh\nexit 0\n")
        elif mode == "readonly-data":
            path.write_bytes(b"fixture")
            path.chmod(0o444)
        elif mode == "writable":
            path.write_bytes(b"fixture")
            path.chmod(0o644)
        elif mode == "symlink":
            target = root / f"{label}-target"
            target.write_bytes(b"fixture")
            path.symlink_to(target)
        elif mode != "absent":
            raise AssertionError(mode)
        replacements[label] = path

    source = PAYLOAD.read_text(encoding="utf-8")
    start = source.index("dpkg_query=\n")
    end = source.index("if [ -z \"$dpkg_query\" ]; then", start)
    selection = (
        "dpkg_query=\n"
        f"for candidate in '{fake_query}'\n"
        "do\n"
        "  if [ -f \"$candidate\" ] && [ ! -L \"$candidate\" ] &&\n"
        "    [ -r \"$candidate\" ] && [ -x \"$candidate\" ] && [ ! -w \"$candidate\" ]; then\n"
        "    dpkg_query=$candidate\n"
        "    break\n"
        "  fi\n"
        "done\n"
    )
    source = source[:start] + selection + source[end:]
    timeout_selection_start = source.index(
        "select_readonly_tool \\\n  /var/jb/usr/bin/timeout"
    )
    timeout_selection_end = source.index(
        "timeout_path=$selected_tool", timeout_selection_start
    )
    source = (
        source[:timeout_selection_start]
        + f"select_readonly_tool '{fake_timeout}'\n"
        + source[timeout_selection_end:]
    )
    for label, path in replacements.items():
        variable = label.replace("-", "_") + "_path"
        original_prefix = f"{variable}='"
        line_start = source.index(original_prefix)
        line_end = source.index("\n", line_start)
        source = source[:line_start] + f"{variable}='{path}'" + source[line_end:]
    for variable in ("appinst_binary_parent", "appsync_library_parent"):
        original_prefix = f"{variable}='"
        line_start = source.index(original_prefix)
        line_end = source.index("\n", line_start)
        source = source[:line_start] + f"{variable}='{fixtures}'" + source[line_end:]
    staged = root / "payload.sh"
    write_executable(staged, source)
    fixtures.chmod(0o555 if parent_observable else 0o000)
    return staged, fixtures, descendant_pid_file


def run_payload(
    records: dict[str, tuple[str, str]],
    path_modes: dict[str, str],
    *,
    malformed: bool = False,
    query_writable: bool = False,
    failure_status: int | None = None,
    partial_failure: bool = False,
    newline_only_failure: bool = False,
    hang_with_descendant: bool = False,
    parent_observable: bool = True,
    argument: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], int | None]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-appsync-capability-test-") as directory:
        root = Path(directory)
        payload, fixtures, descendant_pid_file = prepare(
            root,
            records,
            path_modes,
            malformed=malformed,
            query_writable=query_writable,
            failure_status=failure_status,
            partial_failure=partial_failure,
            newline_only_failure=newline_only_failure,
            hang_with_descendant=hang_with_descendant,
            parent_observable=parent_observable,
        )
        command = ["/bin/sh", str(payload)]
        if argument is not None:
            command.append(argument)
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=4,
            check=False,
        )
        descendant_pid = None
        if descendant_pid_file.exists():
            descendant_pid = int(descendant_pid_file.read_text(encoding="ascii"))
        fixtures.chmod(0o755)
        return result, descendant_pid


def expected_path(label: str, kind: str, readable: str, writable: str, executable: str) -> str:
    return (
        f"{label}-type: {kind}\n"
        f"{label}-readable: {readable}\n"
        f"{label}-writable: {writable}\n"
        f"{label}-executable: {executable}\n"
    )


def test_installed_readonly_shape() -> None:
    modes = {
        "appinst-binary": "readonly-executable",
        "appsync-installd-dylib": "readonly-data",
        "appsync-installd-filter": "readonly-data",
        "appsync-frontboard-dylib": "readonly-data",
        "appsync-frontboard-filter": "readonly-data",
    }
    result, _ = run_payload(PACKAGES, modes)
    assert result.returncode == 0, result.stderr
    expected = (
        "dpkg-query: present\n"
        "appsync-package: installed version=116.0 architecture=iphoneos-arm64\n"
        "appinst-package: installed version=2.1.1 architecture=iphoneos-arm64\n"
        "ellekit-package: installed version=1.1.2 architecture=iphoneos-arm64\n"
        + expected_path("appinst-binary", "regular-file", "yes", "no", "yes")
        + expected_path("appsync-installd-dylib", "regular-file", "yes", "no", "no")
        + expected_path("appsync-installd-filter", "regular-file", "yes", "no", "no")
        + expected_path("appsync-frontboard-dylib", "regular-file", "yes", "no", "no")
        + expected_path("appsync-frontboard-filter", "regular-file", "yes", "no", "no")
    )
    assert result.stdout == expected


def test_absent_packages_and_paths() -> None:
    result, _ = run_payload({}, {})
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(
        "dpkg-query: present\n"
        "appsync-package: not-installed\n"
        "appinst-package: not-installed\n"
        "ellekit-package: not-installed\n"
    )
    for label in PATH_LABELS:
        assert expected_path(label, "absent", "no", "no", "no") in result.stdout


def test_symlink_and_writable_paths_are_visible_without_dereference() -> None:
    result, _ = run_payload(
        {},
        {
            "appinst-binary": "symlink",
            "appsync-installd-dylib": "writable",
        },
    )
    assert result.returncode == 0, result.stderr
    assert expected_path("appinst-binary", "symbolic-link", "no", "no", "no") in result.stdout
    assert expected_path(
        "appsync-installd-dylib", "regular-file", "yes", "yes", "no"
    ) in result.stdout


def test_malformed_package_record_rejects_without_partial_output() -> None:
    result, _ = run_payload(PACKAGES, {}, malformed=True)
    assert result.returncode == 65
    assert result.stdout == ""
    result, _ = run_payload(
        PACKAGES,
        {},
        failure_status=1,
        newline_only_failure=True,
    )
    assert result.returncode == 65
    assert result.stdout == ""


def test_untrusted_query_and_arguments_reject() -> None:
    result, _ = run_payload(PACKAGES, {}, query_writable=True)
    assert result.returncode == 66
    assert result.stdout.startswith("dpkg-query: not-observed\n")
    result, _ = run_payload(PACKAGES, {}, argument="unexpected")
    assert result.returncode == 64
    assert result.stdout == ""


def test_query_failures_and_partial_missing_records_reject() -> None:
    for status in (2, 126, 127, 137):
        result, _ = run_payload(PACKAGES, {}, failure_status=status)
        assert result.returncode == 68, (status, result.returncode, result.stdout)
        assert result.stdout == ""
    result, _ = run_payload(
        PACKAGES,
        {},
        failure_status=1,
        partial_failure=True,
    )
    assert result.returncode == 65
    assert result.stdout == ""


def test_timeout_kills_query_descendant_before_rejecting() -> None:
    started = time.monotonic()
    result, descendant_pid = run_payload(PACKAGES, {}, hang_with_descendant=True)
    elapsed = time.monotonic() - started
    assert result.returncode == 68, (result.returncode, result.stdout)
    assert result.stdout == ""
    assert elapsed < 8, elapsed
    assert descendant_pid is not None
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(descendant_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        os.kill(descendant_pid, signal.SIGKILL)
        raise AssertionError(f"query descendant {descendant_pid} survived timeout")


def test_inaccessible_parent_is_not_reported_absent() -> None:
    result, _ = run_payload(PACKAGES, {}, parent_observable=False)
    assert result.returncode == 0, result.stderr
    for label in PATH_LABELS:
        assert expected_path(label, "not-observed", "no", "no", "no") in result.stdout
        assert expected_path(label, "absent", "no", "no", "no") not in result.stdout


def main() -> None:
    tests = (
        test_installed_readonly_shape,
        test_absent_packages_and_paths,
        test_symlink_and_writable_paths_are_visible_without_dereference,
        test_malformed_package_record_rejects_without_partial_output,
        test_untrusted_query_and_arguments_reject,
        test_query_failures_and_partial_missing_records_reject,
        test_timeout_kills_query_descendant_before_rejecting,
        test_inaccessible_parent_is_not_reported_absent,
    )
    for test in tests:
        test()
    print("PASS AppSync/appinst capability payload tests (8 groups / 15 scenarios)")


if __name__ == "__main__":
    main()
