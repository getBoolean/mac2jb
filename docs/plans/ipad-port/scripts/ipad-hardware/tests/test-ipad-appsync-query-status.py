#!/usr/bin/env python3
"""Hermetic tests for the read-only AppSync query-status classifier."""

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
PAYLOAD = ROOT / "scripts/ipad-hardware/device/u1-readonly-appsync-query-status.sh"
PACKAGE_ORDER = (
    "ai.akemi.appsyncunified",
    "ai.akemi.appinst",
    "ellekit",
)


def write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o555)


def fake_timeout_source(sets_group: bool) -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import os
        import signal
        import subprocess
        import sys

        if len(sys.argv) < 5 or sys.argv[1] != "-k":
            raise SystemExit(125)
        sets_group = {sets_group!r}
        if sets_group:
            os.setpgid(0, 0)
        signal.signal(signal.SIGTERM, lambda _signum, _frame: None)
        grace = float(sys.argv[2])
        duration = float(sys.argv[3])
        process = subprocess.Popen(sys.argv[4:], start_new_session=not sets_group)
        target_group = os.getpgrp() if sets_group else process.pid
        try:
            status = process.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(target_group, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                os.killpg(target_group, signal.SIGKILL)
            raise SystemExit(124)
        if status < 0:
            raise SystemExit(128 - status)
        raise SystemExit(status)
        """
    )


def fake_query_source(
    outcomes: dict[str, tuple[int, str]],
    hang_package: str | None,
    kill_timeout_package: str | None,
    descendant_pid_file: Path,
) -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import os
        import pathlib
        import signal
        import subprocess
        import sys
        import time

        outcomes = {outcomes!r}
        hang_package = {hang_package!r}
        kill_timeout_package = {kill_timeout_package!r}
        package = sys.argv[-1]
        if package == kill_timeout_package:
            pathlib.Path({str(descendant_pid_file)!r}).write_text(str(os.getpid()), encoding="ascii")
            os.kill(os.getppid(), signal.SIGKILL)
            time.sleep(30)
        if package == hang_package:
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            pathlib.Path({str(descendant_pid_file)!r}).write_text(str(child.pid), encoding="ascii")
            time.sleep(30)
        status, output = outcomes[package]
        if output == "__MAC2JB_HIGH_RATE_OUTPUT__":
            chunk = "x" * 4096
            for _ in range(2048):
                sys.stdout.write(chunk)
        else:
            sys.stdout.write(output)
        sys.stdout.flush()
        raise SystemExit(status)
        """
    )


def fake_kill_source() -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import os
        import sys

        arguments = sys.argv[1:]
        if "--" in arguments:
            separator = arguments.index("--")
            if any(item.startswith("-") and item[1:].isdigit() for item in arguments[separator + 1:]):
                raise SystemExit(1)
        os.execv("/bin/kill", ["/bin/kill", *arguments])
        """
    )


def replace_selection(source: str, start: str, assignment: str, replacement: str) -> str:
    begin = source.index(start)
    end = source.index(assignment, begin) + len(assignment)
    return source[:begin] + replacement + source[end:]


def prepare(
    root: Path,
    outcomes: dict[str, tuple[int, str]],
    *,
    query_writable: bool = False,
    hang_package: str | None = None,
    kill_timeout_package: str | None = None,
    timeout_sets_group: bool = True,
    kill_rejects_group: bool = False,
) -> tuple[Path, Path]:
    descendant_pid_file = root / "descendant.pid"
    fake_query = root / "dpkg-query"
    fake_timeout = root / "timeout"
    fake_kill = root / "kill"
    write_executable(
        fake_query,
        fake_query_source(
            outcomes,
            hang_package,
            kill_timeout_package,
            descendant_pid_file,
        ),
    )
    write_executable(fake_timeout, fake_timeout_source(timeout_sets_group))
    if kill_rejects_group:
        write_executable(fake_kill, fake_kill_source())
    if query_writable:
        fake_query.chmod(0o755)

    source = PAYLOAD.read_text(encoding="utf-8")
    source = replace_selection(
        source,
        "select_readonly_tool \\\n  /var/jb/usr/bin/dpkg-query",
        "dpkg_query=$selected_tool",
        f"select_readonly_tool '{fake_query}'\ndpkg_query=$selected_tool",
    )
    source = replace_selection(
        source,
        "select_readonly_tool \\\n  /var/jb/usr/bin/timeout",
        "timeout_path=$selected_tool",
        f"select_readonly_tool '{fake_timeout}'\ntimeout_path=$selected_tool",
    )
    if kill_rejects_group:
        source = replace_selection(
            source,
            "select_readonly_tool \\\n  /var/jb/usr/bin/kill",
            "kill_path=$selected_tool",
            f"select_readonly_tool '{fake_kill}'\nkill_path=$selected_tool",
        )
    staged = root / "payload.sh"
    write_executable(staged, source)
    return staged, descendant_pid_file


def run_payload(
    outcomes: dict[str, tuple[int, str]],
    *,
    query_writable: bool = False,
    hang_package: str | None = None,
    kill_timeout_package: str | None = None,
    timeout_sets_group: bool = True,
    kill_rejects_group: bool = False,
    argument: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], int | None]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-appsync-status-test-") as directory:
        root = Path(directory)
        payload, descendant_pid_file = prepare(
            root,
            outcomes,
            query_writable=query_writable,
            hang_package=hang_package,
            kill_timeout_package=kill_timeout_package,
            timeout_sets_group=timeout_sets_group,
            kill_rejects_group=kill_rejects_group,
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
            timeout=8,
            check=False,
        )
        descendant_pid = None
        if descendant_pid_file.exists():
            descendant_pid = int(descendant_pid_file.read_text(encoding="ascii"))
        return result, descendant_pid


def expected(*statuses: int) -> str:
    labels = ("appsync-query", "appinst-query", "ellekit-query")
    return "\n".join(
        f"{label}-status: {status}"
        for label, status in zip(labels, statuses, strict=True)
    ) + "\n"


def test_numeric_statuses() -> None:
    result, _ = run_payload(
        {
            PACKAGE_ORDER[0]: (2, ""),
            PACKAGE_ORDER[1]: (1, ""),
            PACKAGE_ORDER[2]: (0, "install ok installed|1.1.2|iphoneos-arm64"),
        }
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected(2, 1, 0)


def test_query_stdout_is_never_released() -> None:
    result, _ = run_payload(
        {
            PACKAGE_ORDER[0]: (1, "\n"),
            PACKAGE_ORDER[1]: (2, "__MAC2JB_QUERY_STATUS_0__"),
            PACKAGE_ORDER[2]: (137, "partial\n"),
        }
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected(1, 2, 137)
    assert "MAC2JB_QUERY_STATUS" not in result.stdout
    assert "partial" not in result.stdout


def test_high_rate_output_is_discarded_without_blocking_later_queries() -> None:
    result, _ = run_payload(
        {
            PACKAGE_ORDER[0]: (2, "__MAC2JB_HIGH_RATE_OUTPUT__"),
            PACKAGE_ORDER[1]: (1, ""),
            PACKAGE_ORDER[2]: (0, "record"),
        }
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected(2, 1, 0)
    assert len(result.stdout) < 100


def test_arguments_and_writable_query_reject_without_output() -> None:
    outcomes = {package: (0, "record") for package in PACKAGE_ORDER}
    result, _ = run_payload(outcomes, argument="unexpected")
    assert result.returncode == 64
    assert result.stdout == ""
    result, _ = run_payload(outcomes, query_writable=True)
    assert result.returncode == 66
    assert result.stdout == ""


def test_timeout_classifies_and_kills_query_descendant() -> None:
    outcomes = {package: (0, "record") for package in PACKAGE_ORDER}
    started = time.monotonic()
    result, descendant_pid = run_payload(
        outcomes,
        hang_package=PACKAGE_ORDER[0],
    )
    elapsed = time.monotonic() - started
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected(124, 0, 0)
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


def test_timeout_self_kill_group_is_removed_before_later_queries() -> None:
    outcomes = {package: (0, "record") for package in PACKAGE_ORDER}
    result, residual_pid = run_payload(
        outcomes,
        kill_timeout_package=PACKAGE_ORDER[0],
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected(137, 0, 0)
    assert residual_pid is not None
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(residual_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        os.kill(residual_pid, signal.SIGKILL)
        raise AssertionError(f"query {residual_pid} survived timeout-supervisor death")


def test_group_semantics_and_kill_probe_fail_closed_before_queries() -> None:
    outcomes = {package: (0, "record") for package in PACKAGE_ORDER}
    result, query_pid = run_payload(
        outcomes,
        hang_package=PACKAGE_ORDER[0],
        timeout_sets_group=False,
    )
    assert result.returncode == 67, result.returncode
    assert result.stdout == ""
    assert query_pid is None
    time.sleep(2.2)

    result, query_pid = run_payload(
        outcomes,
        hang_package=PACKAGE_ORDER[0],
        kill_rejects_group=True,
    )
    assert result.returncode == 67, result.returncode
    assert result.stdout == ""
    assert query_pid is None
    time.sleep(2.2)


def main() -> None:
    tests = (
        test_numeric_statuses,
        test_query_stdout_is_never_released,
        test_high_rate_output_is_discarded_without_blocking_later_queries,
        test_arguments_and_writable_query_reject_without_output,
        test_timeout_classifies_and_kills_query_descendant,
        test_timeout_self_kill_group_is_removed_before_later_queries,
        test_group_semantics_and_kill_probe_fail_closed_before_queries,
    )
    for test in tests:
        test()
    print("PASS AppSync query-status payload tests (7 groups / 9 scenarios)")


if __name__ == "__main__":
    main()
