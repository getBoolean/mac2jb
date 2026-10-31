#!/usr/bin/env python3
"""Hermetic failure-path tests for the read-only iPad diagnostic batch runner.

The production runner deliberately hard-codes every executable and credential
path. These tests preserve that production interface: for each scenario they
create a temporary copy, replace only the pinned local fixture paths and command
paths, and execute the resulting bytes against fake SSH/SCP programs. Nothing
connects to an iPad or another network endpoint.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import time


REPO_ROOT = Path(__file__).resolve().parents[6]
RUNNER = REPO_ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/run-diagnostic-phase-batch.sh"

PHASE_STEPS = {
    "launch": [],
    "identity": ["identity"],
    "serialization": ["encode"],
    "configuration-file": ["read-file"],
    "device-tree": ["read-tree"],
    "symbols": ["resolve"],
    "mutation-symbols": ["resolve-only"],
    "entitlements": ["read"],
    "controller-match": ["match"],
    "controller-metadata": ["match", "inspect"],
    "interface-match": ["match"],
    "interface-metadata": ["match", "inspect"],
    "controller-open": ["match", "open-close"],
    "interface-open": ["match", "open-close"],
    "private-readback": ["readback"],
    "full-no-report": ["collect-encode"],
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def marker_lines(phase: str) -> list[str]:
    lines = ["MAC2JB_DIAG_PROCESS v1", f"MAC2JB_DIAG_BEGIN v1 {phase}"]
    for step in PHASE_STEPS[phase]:
        lines.extend(
            [
                f"MAC2JB_DIAG_STEP v1 {phase} {step} begin",
                f"MAC2JB_DIAG_STEP v1 {phase} {step} ok",
            ]
        )
    lines.append(f"MAC2JB_DIAG_END v1 {phase} ok")
    return lines


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o700)


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise AssertionError(f"expected one occurrence of {old!r}, observed {count}")
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
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import sys
            import time

            phase = sys.argv[2]
            steps = {PHASE_STEPS!r}[phase]
            print("MAC2JB_DIAG_PROCESS v1", flush=True)
            print(f"MAC2JB_DIAG_BEGIN v1 {{phase}}", flush=True)
            if {scenario!r} == "remote-command-timeout" and phase == "identity":
                time.sleep(5)
            for step in steps:
                print(f"MAC2JB_DIAG_STEP v1 {{phase}} {{step}} begin", flush=True)
                print(f"MAC2JB_DIAG_STEP v1 {{phase}} {{step}} ok", flush=True)
            print(f"MAC2JB_DIAG_END v1 {{phase}} ok", flush=True)
            """
        ),
    )
    probe.chmod(0o500)

    ssh_log = root / "ssh-phases"
    scp_log = root / "scp-calls"
    fake_ssh = root / "ssh"
    fake_scp = root / "scp"
    fake_cat = root / "cat"
    fake_timeout = root / "timeout"

    write_executable(
        fake_timeout,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import os
            import signal
            import subprocess
            import sys

            if sys.argv[1:3] != ["-k", "1"] or sys.argv[3] not in ("0.1", "12"):
                raise SystemExit(125)
            process = subprocess.Popen(sys.argv[4:], start_new_session=True)
            is_canary = sys.argv[3] == "0.1"
            if {scenario!r} == "timeout-canary-failure" and is_canary:
                process.terminate()
                process.wait()
                raise SystemExit(125)
            deadline = 0.05 if is_canary else (0.25 if {scenario!r} == "remote-command-timeout" and sys.argv[-1] == "identity" else 5)
            try:
                return_code = process.wait(timeout=deadline)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise SystemExit(137)
                raise SystemExit(124)
            raise SystemExit(return_code if return_code >= 0 else 128 - return_code)
            """
        ),
    )
    fake_timeout.chmod(0o500)

    write_executable(
        fake_scp,
        textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import pathlib
            import shutil
            import sys
            import time

            log = pathlib.Path({str(scp_log)!r})
            count = int(log.read_text() or "0") if log.exists() else 0
            log.write_text(str(count + 1))
            if {scenario!r} == "stalled-scp" and count == 0:
                time.sleep(3)
            shutil.copyfile({str(probe)!r}, sys.argv[-1])
            """
        ),
    )

    write_executable(
        fake_ssh,
        textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import glob
            import os
            import pathlib
            import re
            import subprocess
            import sys
            import time

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
            match = re.search(r"--diagnostic-phase '([^']+)'", command)
            if match is None:
                raise SystemExit(64)
            phase = match.group(1)
            log = pathlib.Path({str(ssh_log)!r})
            with log.open("a", encoding="utf-8") as handle:
                handle.write(phase + "\\n")

            steps = {PHASE_STEPS!r}[phase]
            lines = ["MAC2JB_DIAG_PROCESS v1", f"MAC2JB_DIAG_BEGIN v1 {{phase}}"]
            for step in steps:
                lines.extend([
                    f"MAC2JB_DIAG_STEP v1 {{phase}} {{step}} begin",
                    f"MAC2JB_DIAG_STEP v1 {{phase}} {{step}} ok",
                ])
            lines.append(f"MAC2JB_DIAG_END v1 {{phase}} ok")

            scenario = {scenario!r}
            if scenario in ("remote-command-success", "remote-command-timeout", "timeout-canary-failure"):
                completed = subprocess.run(
                    ["/bin/sh", "-c", command],
                    stdin=subprocess.DEVNULL,
                    stdout=None,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                raise SystemExit(completed.returncode)
            if scenario == "outer-timeout" and phase == "identity":
                time.sleep(3)
            if scenario == "remote-preflight-failure" and phase == "launch":
                raise SystemExit(66)
            if scenario == "disconnect" and phase == "identity":
                raise SystemExit(255)
            if scenario == "empty-137" and phase == "identity":
                raise SystemExit(137)
            if scenario == "status-137" and phase == "controller-match":
                print("\\n".join(lines[:3]), flush=True)
                raise SystemExit(137)
            if scenario == "controlled-timeout" and phase == "identity":
                print("\\n".join(lines[:3]), flush=True)
                raise SystemExit(124)
            if scenario == "invalid-marker" and phase == "identity":
                print("MAC2JB_DIAG_PROCESS v1\\nWRONG", flush=True)
                raise SystemExit(137)

            print("\\n".join(lines), flush=True)
            if scenario == "append-failure" and phase == "launch":
                matches = glob.glob({str(root / 'batch.*' / 'results')!r})
                if len(matches) != 1:
                    raise SystemExit(70)
                os.chmod(matches[0], 0)
            """
        ),
    )

    write_executable(
        fake_cat,
        "#!/bin/sh\nexit 1\n" if scenario == "cat-failure" else "#!/bin/sh\nexec /bin/cat \"$@\"\n",
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
    source = replace_once(source, "readonly identity_file='/tmp/mac2jb-ipad-probe-ed25519'", f"readonly identity_file='{identity}'")
    source = replace_once(source, "readonly known_hosts_file='/tmp/mac2jb-ipad-known-hosts'", f"readonly known_hosts_file='{known_hosts}'")
    source = replace_once(
        source,
        "readonly remote_probe='/var/mobile/Documents/mac2jb-ios-probe-diagnostic-87c958beee87b9ed585e34ffa3fc0ec39e4a96e293aa08a7c635b5bce3da8f2e'",
        f"readonly remote_probe='{probe}'",
    )
    source = source.replace("/var/mobile/Documents", str(root))
    source = replace_once(
        source,
        "for timeout_candidate in /var/jb/usr/bin/timeout",
        f"for timeout_candidate in {fake_timeout} /var/jb/usr/bin/timeout",
    )
    source = source.replace("/tmp/mac2jb-diag-batch.", f"{root}/batch.")
    source = source.replace("/usr/bin/scp", str(fake_scp))
    source = source.replace("/usr/bin/ssh", str(fake_ssh))
    source = source.replace("/bin/cat", str(fake_cat))
    source = source.replace("timeout=20,", "timeout=1,")

    runner = root / "runner.sh"
    write_executable(runner, source)
    return runner, ssh_log, scp_log


def run_scenario(scenario: str) -> tuple[subprocess.CompletedProcess[str], list[str], int, float]:
    with tempfile.TemporaryDirectory(prefix=f"mac2jb-diag-test-{scenario}.") as temporary:
        root = Path(temporary)
        runner, ssh_log, scp_log = prepare_scenario(root, scenario)
        started = time.monotonic()
        completed = subprocess.run(
            ["/bin/sh", str(runner)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        elapsed = time.monotonic() - started
        phases = ssh_log.read_text(encoding="utf-8").splitlines() if ssh_log.exists() else []
        scp_count = int(scp_log.read_text(encoding="utf-8") or "0") if scp_log.exists() else 0
        return completed, phases, scp_count, elapsed


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_status_137_aborts_without_more_device_access() -> None:
    result, phases, scp_count, _ = run_scenario("status-137")
    lines = result.stdout.splitlines()
    expect(result.returncode != 0, "ambiguous status 137 falsely returned success")
    expect(phases[-1] == "controller-match", f"status 137 ended at the wrong phase: {phases}")
    expect(len(phases) == 9, f"status 137 continued with later phases: {phases}")
    expect(scp_count == 1, f"status 137 performed later device access: {scp_count} readbacks")
    expect(len(lines) == 9, f"status 137 emitted {len(lines)} summary lines")
    expect(
        "phase-result: controller-match status=137 markers=3 output=valid" in lines,
        "status-137 phase was not preserved as a valid prefix",
    )


def test_controlled_timeout_fails_after_continuation() -> None:
    result, phases, scp_count, _ = run_scenario("controlled-timeout")
    expect(result.returncode != 0, "controlled timeout falsely returned success")
    expect(len(phases) == 16, f"controlled timeout ran {len(phases)} phases instead of continuing")
    expect(scp_count == 2, "controlled timeout skipped final attestation")
    expect(
        "phase-result: identity status=124 markers=3 output=valid" in result.stdout.splitlines(),
        "controlled timeout was not preserved in the summary",
    )


def test_remote_command_success() -> None:
    result, phases, scp_count, _ = run_scenario("remote-command-success")
    expect(result.returncode == 0, f"generated remote command failed: {result.stderr}")
    expect(len(phases) == 16, f"generated remote command ran {len(phases)} phases")
    expect(scp_count == 2, "generated remote command skipped final attestation")


def test_remote_command_timeout_is_controlled() -> None:
    result, phases, scp_count, elapsed = run_scenario("remote-command-timeout")
    expect(result.returncode != 0, "behavioral remote timeout falsely returned success")
    expect(len(phases) == 16, f"behavioral remote timeout ran {len(phases)} phases")
    expect(scp_count == 2, "behavioral remote timeout skipped final attestation")
    expect(elapsed < 10, f"behavioral remote timeout was not bounded: {elapsed:.2f}s")
    expect(
        "phase-result: identity status=124 markers=2 output=valid" in result.stdout.splitlines(),
        "behavioral remote timeout was not classified as controlled",
    )


def test_remote_preflight_failure_aborts() -> None:
    result, phases, scp_count, _ = run_scenario("remote-preflight-failure")
    expect(result.returncode != 0, "remote preflight failure falsely returned success")
    expect(phases == ["launch"], f"remote preflight failure continued phases: {phases}")
    expect(scp_count == 1, "remote preflight failure performed later device access")
    expect("status=66 markers=0 output=invalid" in result.stdout, "remote status 66 was not summarized")


def test_timeout_canary_failure_aborts_before_probe() -> None:
    result, phases, scp_count, _ = run_scenario("timeout-canary-failure")
    expect(result.returncode != 0, "timeout canary failure falsely returned success")
    expect(phases == ["launch"], f"timeout canary failure continued phases: {phases}")
    expect(scp_count == 1, "timeout canary failure performed later device access")
    expect(
        "phase-result: launch status=70 markers=0 output=invalid" in result.stdout.splitlines(),
        "timeout canary failure did not stop before the probe markers",
    )


def test_disconnect_aborts_without_more_device_access() -> None:
    result, phases, scp_count, _ = run_scenario("disconnect")
    expect(result.returncode != 0, "SSH disconnect falsely returned success")
    expect(phases == ["launch", "identity"], f"SSH disconnect continued phases: {phases}")
    expect(scp_count == 1, "SSH disconnect performed later device access")


def test_empty_status_137_is_invalid() -> None:
    result, phases, scp_count, _ = run_scenario("empty-137")
    expect(result.returncode != 0, "zero-marker status 137 falsely returned success")
    expect(phases == ["launch", "identity"], f"zero-marker status 137 continued phases: {phases}")
    expect(scp_count == 1, "zero-marker status 137 performed later device access")
    expect(
        "phase-result: identity status=137 markers=0 output=invalid" in result.stdout.splitlines(),
        "zero-marker status 137 was not classified invalid",
    )


def test_local_watchdog_aborts_without_more_device_access() -> None:
    result, phases, scp_count, elapsed = run_scenario("outer-timeout")
    expect(result.returncode != 0, "local watchdog timeout falsely returned success")
    expect(phases == ["launch", "identity"], f"local watchdog continued with phases: {phases}")
    expect(scp_count == 1, f"local watchdog performed device access after timeout: {scp_count} SCP calls")
    expect(elapsed < 2.5, f"local watchdog did not bound the SSH process: {elapsed:.2f}s")


def test_invalid_marker_fails() -> None:
    result, phases, scp_count, _ = run_scenario("invalid-marker")
    expect(result.returncode != 0, "invalid marker falsely returned success")
    expect(phases == ["launch", "identity"], f"ambiguous status 137 continued phases: {phases}")
    expect(scp_count == 1, "ambiguous status 137 performed later device access")
    expect("output=invalid" in result.stdout, "invalid marker was not classified invalid")


def test_summary_append_failure_fails_closed() -> None:
    result, phases, _, _ = run_scenario("append-failure")
    expect(result.returncode != 0, "results append failure falsely returned success")
    expect(phases == ["launch"], f"append failure continued phases: {phases}")


def test_summary_output_failure_fails_closed() -> None:
    result, phases, scp_count, _ = run_scenario("cat-failure")
    expect(result.returncode != 0, "summary output failure falsely returned success")
    expect(len(phases) == 16, "summary output failure changed phase execution")
    expect(scp_count == 2, "summary output failure changed binary attestation")


def test_stalled_scp_is_bounded() -> None:
    result, phases, scp_count, elapsed = run_scenario("stalled-scp")
    expect(result.returncode != 0, "stalled SCP falsely returned success")
    expect(phases == [], "stalled preflight SCP allowed a diagnostic phase")
    expect(scp_count == 1, f"stalled preflight SCP was retried or continued: {scp_count}")
    expect(elapsed < 2.5, f"stalled SCP was not bounded: {elapsed:.2f}s")


def test_remote_supervision_is_present() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    required = [
        "timeout_path=",
        "sleep_path=",
        "for timeout_candidate in",
        "timeout_status=",
        r'exec \"\$timeout_path\" -k 1 12',
        "raise SystemExit(125)",
    ]
    missing = [fragment for fragment in required if fragment not in source]
    expect(not missing, f"remote/local timeout supervision fragments missing: {missing}")


def main() -> int:
    tests = [
        test_status_137_aborts_without_more_device_access,
        test_controlled_timeout_fails_after_continuation,
        test_remote_command_success,
        test_remote_command_timeout_is_controlled,
        test_remote_preflight_failure_aborts,
        test_timeout_canary_failure_aborts_before_probe,
        test_disconnect_aborts_without_more_device_access,
        test_empty_status_137_is_invalid,
        test_local_watchdog_aborts_without_more_device_access,
        test_invalid_marker_fails,
        test_summary_append_failure_fails_closed,
        test_summary_output_failure_fails_closed,
        test_stalled_scp_is_bounded,
        test_remote_supervision_is_present,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, subprocess.TimeoutExpired) as error:
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
