#!/usr/bin/env python3
"""Hermetic tests for the read-only diagnostic launch-isolation runner.

The production runner pins its paths and SSH policy. Each test rewrites a
temporary copy to use local fake SSH/SCP programs; no network or iPad access is
possible. The scenarios prove that a failed boundary stops every later device
access and that only exact marker prefixes are accepted.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time


REPO_ROOT = Path(__file__).resolve().parents[6]
RUNNER = REPO_ROOT / "scripts/ipad-hardware/run-diagnostic-launch-isolation.sh"
STAGES = [
    "shell",
    "env-select",
    "tools-select",
    "env-canary",
    "timeout-canary",
    "trustcache-membership",
    "diagnostic-direct",
    "diagnostic-timeout",
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o700)


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise AssertionError(f"expected one occurrence of {old!r}, observed {count}")
    return source.replace(old, new)


def replace_exact_count(source: str, old: str, new: str, expected: int) -> str:
    count = source.count(old)
    if count != expected:
        raise AssertionError(
            f"expected {expected} occurrences of {old!r}, observed {count}"
        )
    return source.replace(old, new)


def prepare_scenario(root: Path, scenario: str) -> tuple[Path, Path, Path]:
    identity = root / "identity"
    known_hosts = root / "known-hosts"
    probe = root / "diagnostic"
    identity.write_bytes(b"test-identity\n")
    known_hosts.write_bytes(b"test-known-host\n")
    identity.chmod(0o600)
    known_hosts.chmod(0o600)
    write_executable(
        probe,
        "#!/bin/sh\nprintf '%s\\n' 'MAC2JB_DIAG_PROCESS v1' "
        "'MAC2JB_DIAG_BEGIN v1 launch' 'MAC2JB_DIAG_END v1 launch ok'\n",
    )
    probe.chmod(0o500)

    ssh_log = root / "ssh-stages"
    scp_log = root / "scp-calls"
    fake_ssh = root / "ssh"
    fake_scp = root / "scp"
    fake_timeout = root / "timeout"
    fake_jbctl = root / "jbctl"
    fake_sudo = root / "sudo"
    fake_grep = root / "grep"
    fake_stat = root / "stat"
    transport_child_pid = root / "transport-child-pid"

    write_executable(
        fake_timeout,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import os
            import signal
            import subprocess
            import sys

            if sys.argv[1:3] != ["-k", "1"] or sys.argv[3] not in ("0.1", "3", "5", "12"):
                raise SystemExit(125)
            if sys.argv[3] in ("3", "5") and os.environ.get("MAC2JB_FAKE_ROOT") != "1":
                raise SystemExit(126)
            process = subprocess.Popen(sys.argv[4:], start_new_session=True)
            deadline = 0.05 if sys.argv[3] == "0.1" else (1.0 if sys.argv[3] in ("3", "5") else 5)
            try:
                return_code = process.wait(timeout=deadline)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait()
                raise SystemExit(124)
            raise SystemExit(return_code)
            """
        ),
    )
    fake_timeout.chmod(0o500)

    write_executable(
        fake_jbctl,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import sys
            import time

            if sys.argv[1:] != ["trustcache", "info"]:
                raise SystemExit(64)
            scenario = {scenario!r}
            target = "d4afc7698e19545e4714f1c8cc6cd74976276738"
            if scenario == "execute-hanging-query":
                time.sleep(30)
            elif scenario == "execute-oversized-output":
                for index in range(3000):
                    print(f"| {{index + 1}}:\\t1111111111111111111111111111111111111111")
            elif scenario in ("execute-exact-member", "root-member"):
                print(f"| 1:\\t{{target}}")
            elif scenario == "execute-near-match":
                print(f"| 1:\\t0{{target}}0")
            elif scenario in ("execute-query-status-3", "root-query-status-3"):
                raise SystemExit(3)
            else:
                print("| 1:\\t1111111111111111111111111111111111111111")
            """
        ),
    )
    fake_jbctl.chmod(0o500)

    write_executable(
        fake_sudo,
        "#!/bin/sh\n"
        "[ \"$#\" -ge 3 ] && [ \"$1\" = -n ] && [ \"$2\" = -- ] || exit 64\n"
        f"if [ {scenario!r} = execute-sudo-failure ]; then exit 1; fi\n"
        "shift 2\n"
        "export MAC2JB_FAKE_ROOT=1\n"
        "exec \"$@\"\n",
    )
    fake_sudo.chmod(0o500)

    write_executable(
        fake_grep,
        "#!/bin/sh\n"
        f"if [ {scenario!r} = execute-grep-failure ]; then exit 2; fi\n"
        "exec /usr/bin/grep \"$@\"\n",
    )
    fake_grep.chmod(0o500)

    write_executable(
        fake_stat,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import sys

            if len(sys.argv) != 4 or sys.argv[1:3] != ["-f", "%u:%Lp"]:
                raise SystemExit(64)
            if {scenario!r} == "root-invalid-tool-metadata":
                print("501:777")
            else:
                print("0:555")
            """
        ),
    )
    fake_stat.chmod(0o500)

    write_executable(
        fake_scp,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import pathlib
            import shutil
            import time

            log = pathlib.Path({str(scp_log)!r})
            count = int(log.read_text() or "0") if log.exists() else 0
            log.write_text(str(count + 1))
            if {scenario!r} == "interrupt-scp" and count == 0:
                pathlib.Path({str(transport_child_pid)!r}).write_text(str(__import__("os").getpid()))
                time.sleep(30)
            if {scenario!r} == "stalled-scp" and count == 0:
                time.sleep(3)
            shutil.copyfile({str(probe)!r}, __import__("sys").argv[-1])
            """
        ),
    )

    write_executable(
        fake_ssh,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import os
            import pathlib
            import re
            import subprocess
            import sys
            import time

            if {scenario!r} == "root-auth-denied":
                raise SystemExit(255)
            command = sys.argv[-1]
            syntax = subprocess.run(
                ["/bin/sh", "-n", "-c", command],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if syntax.returncode != 0:
                print(syntax.stderr, file=sys.stderr)
                raise SystemExit(65)
            match = re.search(r"stage_tag='([^']+)'", command)
            if match is None:
                raise SystemExit(64)
            stage = match.group(1)
            if stage == "trustcache-membership":
                if {scenario!r}.startswith("root-"):
                    root_query = '\"$timeout_path\" -k 1 5 \"$jbctl_path\" trustcache info'
                    if command.count(root_query) != 1 or 'sudo_path' in command:
                        raise SystemExit(79)
                else:
                    sudo_canary = '\"$sudo_path\" -n -- \"$timeout_path\" -k 1 3 \"$true_path\"'
                    trust_query = '\"$sudo_path\" -n -- \"$timeout_path\" -k 1 5 \"$jbctl_path\" trustcache info'
                    if command.count(sudo_canary) != 1 or command.count(trust_query) != 1:
                        raise SystemExit(79)
            with pathlib.Path({str(ssh_log)!r}).open("a", encoding="utf-8") as handle:
                handle.write(stage + "\\n")

            scenario = {scenario!r}
            expected = [f"MAC2JB_ISO v1 {{stage}} begin"]
            if stage == "trustcache-membership":
                membership = "member" if scenario == "trustcache-member" else "not-member"
                expected.append(f"MAC2JB_ISO v1 trustcache-membership {{membership}}")
            elif stage in ("diagnostic-direct", "diagnostic-timeout"):
                expected.extend([
                    "MAC2JB_DIAG_PROCESS v1",
                    "MAC2JB_DIAG_BEGIN v1 launch",
                    "MAC2JB_DIAG_END v1 launch ok",
                ])
            else:
                expected.append(f"MAC2JB_ISO v1 {{stage}} ok")

            if scenario == "interrupt" and stage == "shell":
                pathlib.Path({str(transport_child_pid)!r}).write_text(str(os.getpid()))
                time.sleep(30)
            if scenario in (
                "execute-remote",
                "execute-exact-member",
                "execute-near-match",
                "execute-oversized-output",
                "execute-hanging-query",
                "execute-grep-failure",
                "execute-sudo-failure",
                "execute-query-status-3",
                "root-member",
                "root-not-member",
                "root-query-status-3",
                "root-invalid-tool-metadata",
            ):
                child_environment = os.environ.copy()
                if scenario.startswith("root-"):
                    child_environment["MAC2JB_FAKE_ROOT"] = "1"
                completed = subprocess.run(
                    ["/bin/sh", "-c", command],
                    stdin=subprocess.DEVNULL,
                    stdout=None,
                    stderr=subprocess.DEVNULL,
                    env=child_environment,
                    check=False,
                )
                raise SystemExit(completed.returncode)
            if scenario == "outer-timeout" and stage == "shell":
                time.sleep(3)
            if scenario == "env-canary-failure" and stage == "env-canary":
                print(expected[0], flush=True)
                raise SystemExit(70)
            if scenario == "trustcache-query-failure" and stage == "trustcache-membership":
                print(expected[0], flush=True)
                raise SystemExit(73)
            if scenario == "diagnostic-direct-255" and stage == "diagnostic-direct":
                print(expected[0], flush=True)
                raise SystemExit(255)
            if scenario == "invalid-output" and stage == "env-select":
                print("WRONG", flush=True)
                raise SystemExit(0)
            print("\\n".join(expected), flush=True)
            """
        ),
    )

    source = RUNNER.read_text(encoding="utf-8")
    source = replace_once(
        source,
        "readonly expected_probe_sha='87c958beee87b9ed585e34ffa3fc0ec39e4a96e293aa08a7c635b5bce3da8f2e'",
        f"readonly expected_probe_sha='{digest(probe)}'",
    )
    source = replace_once(
        source,
        "readonly expected_identity_sha='c44fae53d6364421bb4034c62ce53a4d363a7a31dde085cc7fc4c813c75f4a5f'",
        f"readonly expected_identity_sha='{digest(identity)}'",
    )
    source = replace_once(
        source,
        "readonly expected_known_hosts_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'",
        f"readonly expected_known_hosts_sha='{digest(known_hosts)}'",
    )
    source = replace_once(
        source,
        "readonly identity_file='/tmp/mac2jb-ipad-probe-ed25519'",
        f"readonly identity_file='{identity}'",
    )
    source = replace_once(
        source,
        "readonly known_hosts_file='/tmp/mac2jb-ipad-known-hosts'",
        f"readonly known_hosts_file='{known_hosts}'",
    )
    source = replace_once(
        source,
        "readonly remote_probe='/var/mobile/Documents/mac2jb-ios-probe-diagnostic-87c958beee87b9ed585e34ffa3fc0ec39e4a96e293aa08a7c635b5bce3da8f2e'",
        f"readonly remote_probe='{probe}'",
    )
    source = source.replace("/tmp/mac2jb-diag-isolation.", f"{root}/isolation.")
    source = source.replace("/var/mobile/Documents", str(root))
    source = replace_exact_count(
        source,
        "for timeout_candidate in /var/jb/usr/bin/timeout",
        f"for timeout_candidate in {fake_timeout} /var/jb/usr/bin/timeout",
        2,
    )
    source = replace_exact_count(
        source,
        "for jbctl_candidate in /var/jb/basebin/jbctl",
        f"for jbctl_candidate in {fake_jbctl} /var/jb/basebin/jbctl",
        2,
    )
    source = replace_once(
        source,
        "for sudo_candidate in /var/jb/usr/bin/sudo",
        f"for sudo_candidate in {fake_sudo} /var/jb/usr/bin/sudo",
    )
    source = replace_exact_count(
        source,
        "for grep_candidate in /var/jb/usr/bin/grep",
        f"for grep_candidate in {fake_grep} /var/jb/usr/bin/grep",
        2,
    )
    source = replace_once(
        source,
        "for stat_candidate in /usr/bin/stat",
        f"for stat_candidate in {fake_stat} /usr/bin/stat",
    )
    source = source.replace("/usr/bin/scp", str(fake_scp))
    source = source.replace("/usr/bin/ssh", str(fake_ssh))
    source = source.replace("timeout=20,", "timeout=1,")

    runner = root / "runner.sh"
    write_executable(runner, source)
    return runner, ssh_log, scp_log


def run_scenario(
    scenario: str, *runner_arguments: str
) -> tuple[subprocess.CompletedProcess[str], list[str], int, float]:
    with tempfile.TemporaryDirectory(prefix=f"mac2jb-isolation-test-{scenario}.") as temporary:
        root = Path(temporary)
        runner, ssh_log, scp_log = prepare_scenario(root, scenario)
        started = time.monotonic()
        completed = subprocess.run(
            ["/bin/sh", str(runner), *runner_arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        elapsed = time.monotonic() - started
        stages = ssh_log.read_text(encoding="utf-8").splitlines() if ssh_log.exists() else []
        scp_count = int(scp_log.read_text(encoding="utf-8") or "0") if scp_log.exists() else 0
        return completed, stages, scp_count, elapsed


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_success() -> None:
    result, stages, scp_count, _ = run_scenario("success")
    expect(result.returncode == 0, f"success failed: {result.stderr}")
    expect(stages == STAGES, f"wrong stage order: {stages}")
    expect(scp_count == 2, f"success used {scp_count} readbacks")
    expect(len(result.stdout.splitlines()) == len(STAGES), "success summary length changed")
    expect("detail=not-member" in result.stdout, "not-member result was not preserved")


def test_remote_commands_execute() -> None:
    result, stages, scp_count, _ = run_scenario("execute-remote")
    expect(result.returncode == 0, f"generated remote command failed: {result.stderr}")
    expect(stages == STAGES, f"generated commands ran the wrong stages: {stages}")
    expect(scp_count == 2, "generated commands skipped final attestation")


def test_exact_trustcache_token_matches() -> None:
    result, stages, scp_count, _ = run_scenario("execute-exact-member")
    expect(result.returncode == 0, f"exact token failed: {result.stderr}")
    expect(stages == STAGES, f"exact token changed stage order: {stages}")
    expect(scp_count == 2, "exact token skipped final attestation")
    expect("detail=member" in result.stdout, "exact token was not classified as member")


def test_embedded_trustcache_hash_does_not_match() -> None:
    result, stages, scp_count, _ = run_scenario("execute-near-match")
    expect(result.returncode == 0, f"near-match command failed: {result.stderr}")
    expect(stages == STAGES, f"near match changed stage order: {stages}")
    expect(scp_count == 2, "near match skipped final attestation")
    expect("detail=not-member" in result.stdout, "embedded hash falsely matched")


def test_oversized_trustcache_output_stops() -> None:
    result, stages, scp_count, _ = run_scenario("execute-oversized-output")
    expect(result.returncode != 0, "oversized output falsely passed")
    expected_stages = STAGES[: STAGES.index("trustcache-membership") + 1]
    expect(stages == expected_stages, f"oversized output continued: {stages}")
    expect(scp_count == 1, "oversized output performed a later readback")
    expect("status=74" in result.stdout, "oversized output did not report its boundary")


def test_hanging_trustcache_query_stops() -> None:
    result, stages, scp_count, elapsed = run_scenario("execute-hanging-query")
    expect(result.returncode != 0, "hanging query falsely passed")
    expected_stages = STAGES[: STAGES.index("trustcache-membership") + 1]
    expect(stages == expected_stages, f"hanging query continued: {stages}")
    expect(scp_count == 1, "hanging query performed a later readback")
    expect(elapsed < 10, f"hanging query was not bounded: {elapsed:.2f}s")
    boundary_lines = [line for line in result.stdout.splitlines() if "trustcache-membership" in line]
    expect(len(boundary_lines) == 1, "hanging query did not report exactly one boundary")
    expect("status=0" not in boundary_lines[0], "hanging query reported success")


def test_trustcache_parser_failure_stops() -> None:
    result, stages, scp_count, _ = run_scenario("execute-grep-failure")
    expect(result.returncode != 0, "parser failure falsely passed")
    expected_stages = STAGES[: STAGES.index("trustcache-membership") + 1]
    expect(stages == expected_stages, f"parser failure continued: {stages}")
    expect(scp_count == 1, "parser failure performed a later readback")
    expect("status=78" in result.stdout, "parser failure did not report its boundary")


def test_sudo_canary_failure_stops() -> None:
    result, stages, scp_count, _ = run_scenario("execute-sudo-failure")
    expect(result.returncode != 0, "sudo canary failure falsely passed")
    expected_stages = STAGES[: STAGES.index("trustcache-membership") + 1]
    expect(stages == expected_stages, f"sudo canary failure continued: {stages}")
    expect(scp_count == 1, "sudo canary failure performed a later readback")
    expect("status=79" in result.stdout, "sudo canary failure was not classified")


def test_query_status_3_stops() -> None:
    result, stages, scp_count, _ = run_scenario("execute-query-status-3")
    expect(result.returncode != 0, "query status 3 falsely passed")
    expected_stages = STAGES[: STAGES.index("trustcache-membership") + 1]
    expect(stages == expected_stages, f"query status 3 continued: {stages}")
    expect(scp_count == 1, "query status 3 performed a later readback")
    expect("status=87" in result.stdout, "query status 3 was not classified")


def test_root_member_stops_after_trust_query() -> None:
    result, stages, scp_count, _ = run_scenario("root-member", "root-trust-only")
    expected_stages = ["trustcache-membership"]
    expect(result.returncode == 0, f"root member failed: {result.stderr}")
    expect(stages == expected_stages, f"root member reached later stages: {stages}")
    expect(scp_count == 0, "root member performed an SCP readback")
    expect("detail=member" in result.stdout, "root member was not classified")


def test_root_nonmember_stops_after_trust_query() -> None:
    result, stages, scp_count, _ = run_scenario("root-not-member", "root-trust-only")
    expected_stages = ["trustcache-membership"]
    expect(result.returncode == 0, f"root nonmember failed: {result.stderr}")
    expect(stages == expected_stages, f"root nonmember reached later stages: {stages}")
    expect(scp_count == 0, "root nonmember performed an SCP readback")
    expect("detail=not-member" in result.stdout, "root nonmember was not classified")


def test_root_query_status_3_stops() -> None:
    result, stages, scp_count, _ = run_scenario("root-query-status-3", "root-trust-only")
    expected_stages = ["trustcache-membership"]
    expect(result.returncode != 0, "root query status 3 falsely passed")
    expect(stages == expected_stages, f"root query status 3 continued: {stages}")
    expect(scp_count == 0, "root query status 3 performed an SCP readback")
    expect("status=87" in result.stdout, "root query status 3 was not classified")


def test_root_auth_denial_stops_at_readback() -> None:
    result, stages, scp_count, _ = run_scenario("root-auth-denied", "root-trust-only")
    expect(result.returncode != 0, "root authentication denial falsely passed")
    expect(stages == [], f"root authentication denial reached SSH stages: {stages}")
    expect(scp_count == 0, "root authentication denial performed an SCP readback")


def test_root_invalid_tool_metadata_stops() -> None:
    result, stages, scp_count, _ = run_scenario(
        "root-invalid-tool-metadata", "root-trust-only"
    )
    expect(result.returncode != 0, "invalid root tool metadata falsely passed")
    expect(stages == ["trustcache-membership"], f"invalid metadata continued: {stages}")
    expect(scp_count == 0, "invalid metadata performed an SCP readback")
    expect("status=95" in result.stdout, "invalid stat metadata was not classified")


def test_env_canary_failure_stops() -> None:
    result, stages, scp_count, _ = run_scenario("env-canary-failure")
    expect(result.returncode != 0, "env canary failure falsely passed")
    expect(stages == STAGES[:4], f"env failure continued: {stages}")
    expect(scp_count == 1, "env failure performed a later readback")
    expect(
        "isolation-result: env-canary status=70 markers=1 output=valid" in result.stdout,
        "env failure prefix was not classified",
    )


def test_trustcache_member_is_accepted() -> None:
    result, stages, scp_count, _ = run_scenario("trustcache-member")
    expect(result.returncode == 0, f"member result failed: {result.stderr}")
    expect(stages == STAGES, f"member result changed stage order: {stages}")
    expect(scp_count == 2, "member result skipped final attestation")
    expect("detail=member" in result.stdout, "member result was not preserved")


def test_trustcache_query_failure_stops() -> None:
    result, stages, scp_count, _ = run_scenario("trustcache-query-failure")
    expect(result.returncode != 0, "trustcache query failure falsely passed")
    expected_stages = STAGES[: STAGES.index("trustcache-membership") + 1]
    expect(stages == expected_stages, f"trustcache failure continued: {stages}")
    expect(scp_count == 1, "trustcache failure performed a later readback")
    expect(
        "isolation-result: trustcache-membership status=73 markers=1 output=valid" in result.stdout,
        "trustcache failure boundary was not preserved",
    )


def test_diagnostic_disconnect_stops() -> None:
    result, stages, scp_count, _ = run_scenario("diagnostic-direct-255")
    expect(result.returncode != 0, "disconnect falsely passed")
    expected_stages = STAGES[: STAGES.index("diagnostic-direct") + 1]
    expect(stages == expected_stages, f"disconnect continued: {stages}")
    expect(scp_count == 1, "disconnect performed a later readback")
    expect(
        "isolation-result: diagnostic-direct status=255 markers=1 output=valid" in result.stdout,
        "disconnect boundary was not preserved",
    )


def test_invalid_output_stops() -> None:
    result, stages, scp_count, _ = run_scenario("invalid-output")
    expect(result.returncode != 0, "invalid output falsely passed")
    expect(stages == STAGES[:2], f"invalid output continued: {stages}")
    expect(scp_count == 1, "invalid output performed a later readback")
    expect("output=invalid" in result.stdout, "invalid output was not classified")


def test_outer_timeout_stops() -> None:
    result, stages, scp_count, elapsed = run_scenario("outer-timeout")
    expect(result.returncode != 0, "outer timeout falsely passed")
    expect(stages == STAGES[:1], f"outer timeout continued: {stages}")
    expect(scp_count == 1, "outer timeout performed a later readback")
    expect(elapsed < 10, f"outer timeout was not bounded: {elapsed:.2f}s")
    expect("status=125" in result.stdout, "outer timeout status was not preserved")


def test_stalled_scp_stops() -> None:
    result, stages, scp_count, elapsed = run_scenario("stalled-scp")
    expect(result.returncode != 0, "stalled SCP falsely passed")
    expect(stages == [], f"stalled SCP reached SSH: {stages}")
    expect(scp_count == 1, f"stalled SCP count changed: {scp_count}")
    expect(elapsed < 10, f"stalled SCP was not bounded: {elapsed:.2f}s")


def assert_signal_reaps_transport(signum: signal.Signals, scenario: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"mac2jb-isolation-test-{scenario}.") as temporary:
        root = Path(temporary)
        runner, ssh_log, scp_log = prepare_scenario(root, scenario)
        child_pid_file = root / "transport-child-pid"
        process = subprocess.Popen(
            ["/bin/sh", str(runner)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        deadline = time.monotonic() + 5
        while not child_pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        expect(child_pid_file.exists(), "fake SSH child did not start")
        child_pid = int(child_pid_file.read_text(encoding="utf-8"))
        os.killpg(process.pid, signum)
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise AssertionError(f"runner did not exit after {signum.name}")

        child_alive = True
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            child_alive = False
        if child_alive:
            try:
                os.killpg(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        stages = ssh_log.read_text(encoding="utf-8").splitlines() if ssh_log.exists() else []
        scp_count = int(scp_log.read_text(encoding="utf-8") or "0") if scp_log.exists() else 0
        expect(process.returncode == 128 + signum, f"{signum.name} returned {process.returncode}")
        expect(not child_alive, f"transport child remained alive after {signum.name}")
        expected_stages = ["shell"] if scenario == "interrupt" else []
        expect(stages == expected_stages, f"{signum.name} reached unexpected stages: {stages}")
        expect(scp_count == 1, f"{signum.name} performed later readback: {scp_count}")


def test_termination_signals_reap_ssh_child() -> None:
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        assert_signal_reaps_transport(signum, "interrupt")


def test_termination_reaps_scp_child() -> None:
    assert_signal_reaps_transport(signal.SIGTERM, "interrupt-scp")


def main() -> None:
    tests = [
        test_success,
        test_remote_commands_execute,
        test_exact_trustcache_token_matches,
        test_embedded_trustcache_hash_does_not_match,
        test_oversized_trustcache_output_stops,
        test_hanging_trustcache_query_stops,
        test_trustcache_parser_failure_stops,
        test_sudo_canary_failure_stops,
        test_query_status_3_stops,
        test_root_member_stops_after_trust_query,
        test_root_nonmember_stops_after_trust_query,
        test_root_query_status_3_stops,
        test_root_auth_denial_stops_at_readback,
        test_root_invalid_tool_metadata_stops,
        test_env_canary_failure_stops,
        test_trustcache_member_is_accepted,
        test_trustcache_query_failure_stops,
        test_diagnostic_disconnect_stops,
        test_invalid_output_stops,
        test_outer_timeout_stops,
        test_stalled_scp_stops,
        test_termination_signals_reap_ssh_child,
        test_termination_reaps_scp_child,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"PASS {len(tests)} diagnostic launch-isolation scenarios")


if __name__ == "__main__":
    main()
