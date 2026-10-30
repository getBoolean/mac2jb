#!/usr/bin/env python3
"""Hermetic tests for the read-only AppSync package-membership scan."""

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
PAYLOAD = ROOT / "scripts/ipad-hardware/device/u1-readonly-appsync-package-membership.sh"


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


def fake_query_source(
    records: list[str],
    status: int,
    high_volume: bool,
    hang: bool,
    residual_pid_file: Path,
) -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import pathlib
        import subprocess
        import sys
        import time

        if {hang!r}:
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            pathlib.Path({str(residual_pid_file)!r}).write_text(str(child.pid), encoding="ascii")
            time.sleep(30)
        if {high_volume!r}:
            for index in range(20000):
                sys.stdout.write(f"unrelated-package-{{index}}|install ok installed\\n")
        for record in {records!r}:
            sys.stdout.write(record + "\\n")
        sys.stdout.flush()
        raise SystemExit({status})
        """
    )


def replace_selection(source: str, start: str, assignment: str, replacement: str) -> str:
    begin = source.index(start)
    end = source.index(assignment, begin) + len(assignment)
    return source[:begin] + replacement + source[end:]


def prepare(
    root: Path,
    records: list[str],
    *,
    status: int = 0,
    high_volume: bool = False,
    hang: bool = False,
    timeout_sets_group: bool = True,
    kill_rejects_group: bool = False,
) -> tuple[Path, Path]:
    residual_pid_file = root / "residual.pid"
    fake_query = root / "dpkg-query"
    fake_timeout = root / "timeout"
    fake_kill = root / "kill"
    write_executable(
        fake_query,
        fake_query_source(records, status, high_volume, hang, residual_pid_file),
    )
    write_executable(fake_timeout, fake_timeout_source(timeout_sets_group))
    if kill_rejects_group:
        write_executable(fake_kill, fake_kill_source())

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
    return staged, residual_pid_file


def run_payload(
    records: list[str],
    *,
    status: int = 0,
    high_volume: bool = False,
    hang: bool = False,
    timeout_sets_group: bool = True,
    kill_rejects_group: bool = False,
    argument: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], int | None]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-membership-test-") as directory:
        root = Path(directory)
        payload, residual_pid_file = prepare(
            root,
            records,
            status=status,
            high_volume=high_volume,
            hang=hang,
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
            timeout=10,
            check=False,
        )
        residual_pid = None
        if residual_pid_file.exists():
            residual_pid = int(residual_pid_file.read_text(encoding="ascii"))
        return result, residual_pid


def expected(appsync: str, appinst: str, ellekit: str) -> str:
    return (
        "dpkg-list-status: 0\n"
        f"appsync-membership: {appsync}\n"
        f"appinst-membership: {appinst}\n"
        f"ellekit-membership: {ellekit}\n"
    )


def test_installed_absent_and_noninstalled_states() -> None:
    result, _ = run_payload(
        [
            "ai.akemi.appsyncunified|install ok installed",
            "ellekit|hold ok installed",
            "unrelated|install ok installed",
        ]
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected("installed", "not-observed", "installed")

    result, _ = run_payload(
        [
            "ai.akemi.appsyncunified|deinstall ok config-files",
            "ai.akemi.appinst|install ok half-installed",
            "ellekit|install ok installed",
        ]
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected(
        "record-not-installed",
        "record-not-installed",
        "installed",
    )

    result, _ = run_payload(
        [
            "ai.akemi.appsyncunified|deinstall ok installed",
            "ai.akemi.appinst|purge ok installed",
            "ellekit|install reinstreq installed",
        ]
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected("installed", "installed", "installed-error")


def test_producer_failure_and_duplicates_reject_without_output() -> None:
    result, _ = run_payload([], status=2)
    assert result.returncode == 68
    assert result.stdout == ""
    result, _ = run_payload(["ai.akemi.appsyncunified|invalid ok installed"])
    assert result.returncode == 68
    assert result.stdout == ""
    result, _ = run_payload(
        [
            "ai.akemi.appsyncunified|install ok installed",
            "ai.akemi.appsyncunified|install ok installed",
        ]
    )
    assert result.returncode == 68
    assert result.stdout == ""


def test_high_volume_unrelated_records_are_filtered() -> None:
    result, _ = run_payload(
        ["ellekit|install ok installed"],
        high_volume=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected("not-observed", "not-observed", "installed")
    assert len(result.stdout) < 160


def test_timeout_kills_producer_descendant_and_rejects() -> None:
    result, residual_pid = run_payload([], hang=True)
    assert result.returncode == 68
    assert result.stdout == ""
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
        raise AssertionError(f"producer descendant {residual_pid} survived timeout")


def test_tool_semantic_failures_stop_before_query() -> None:
    result, query_pid = run_payload([], hang=True, timeout_sets_group=False)
    assert result.returncode == 67
    assert result.stdout == ""
    assert query_pid is None
    time.sleep(2.2)

    result, query_pid = run_payload([], hang=True, kill_rejects_group=True)
    assert result.returncode == 67
    assert result.stdout == ""
    assert query_pid is None
    time.sleep(2.2)


def test_arguments_reject_before_query() -> None:
    result, query_pid = run_payload([], hang=True, argument="unexpected")
    assert result.returncode == 64
    assert result.stdout == ""
    assert query_pid is None


def main() -> None:
    tests = (
        test_installed_absent_and_noninstalled_states,
        test_producer_failure_and_duplicates_reject_without_output,
        test_high_volume_unrelated_records_are_filtered,
        test_timeout_kills_producer_descendant_and_rejects,
        test_tool_semantic_failures_stop_before_query,
        test_arguments_reject_before_query,
    )
    for test in tests:
        test()
    print("PASS AppSync package-membership payload tests (6 groups / 11 scenarios)")


if __name__ == "__main__":
    main()
