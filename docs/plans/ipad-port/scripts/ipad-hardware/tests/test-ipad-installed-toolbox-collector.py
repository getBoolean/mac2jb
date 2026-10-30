#!/usr/bin/env python3
"""Hermetic watchdog and transport tests for toolbox attestation collection."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time


ROOT = Path(__file__).resolve().parents[6]
RUNNER = ROOT / "scripts/ipad-hardware/collect-installed-toolbox-over-ssh.sh"
PAYLOAD = ROOT / "scripts/ipad-hardware/device/u1-readonly-installed-toolbox-archive.sh"
VALIDATOR = ROOT / "scripts/ipad-hardware/validate-installed-toolbox-archive.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validator_fixture() -> object:
    path = Path(__file__).with_name("test-ipad-installed-toolbox-validator.py")
    specification = importlib.util.spec_from_file_location("toolbox_validator_fixture", path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


FIXTURE = validator_fixture()


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o555)


def fake_codesign_source(marker: Path, child_pid: Path) -> str:
    return textwrap.dedent(
        f"""\
        import pathlib
        import subprocess
        import sys
        import time

        child = subprocess.Popen(
            [sys.executable, '-I', '-S', '-c', 'import time; time.sleep(30)'],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding='ascii')
        pathlib.Path({str(marker)!r}).write_text('codesign-started', encoding='ascii')
        time.sleep(30)
        """
    )


def prepare(root: Path, scenario: str) -> dict[str, Path]:
    script_dir = root / "scripts/ipad-hardware"
    device_dir = script_dir / "device"
    device_dir.mkdir(parents=True)
    payload = device_dir / PAYLOAD.name
    payload.write_bytes(PAYLOAD.read_bytes())
    payload.chmod(0o444)

    validator = script_dir / VALIDATOR.name
    validator_marker = root / "validator-started"
    child_pid = root / "validator-child-pid"
    validator_source = VALIDATOR.read_text(encoding="utf-8")
    if scenario in ("codesign-hang", "codesign-inner-timeout"):
        fake_codesign = root / "codesign"
        write_executable(
            fake_codesign,
            "#!/usr/bin/python3\n" + fake_codesign_source(validator_marker, child_pid),
        )
        validator_source = validator_source.replace(
            'CODESIGN = "/usr/bin/codesign"',
            f"CODESIGN = {str(fake_codesign)!r}",
        )
    if scenario == "codesign-inner-timeout":
        validator_source = validator_source.replace(
            "def run_tool(arguments: list[str], timeout: float = 8.0)",
            "def run_tool(arguments: list[str], timeout: float = 0.2)",
        )
    validator.write_text(validator_source, encoding="utf-8")
    validator.chmod(0o444)

    identity = root / "identity"
    known_hosts = root / "known-hosts"
    identity.write_bytes(b"test-identity\n")
    known_hosts.write_bytes(b"test-known-hosts\n")
    identity.chmod(0o600)
    known_hosts.chmod(0o600)
    evidence_parent = root / "evidence-parent"
    evidence_parent.mkdir()
    evidence_directory = evidence_parent / "installed-toolbox-attestation"
    staging_directory = evidence_parent / ".installed-toolbox-attestation.staging"
    ssh_marker = root / "ssh-runs"

    archive = root / "fixture.tar"
    archive.write_bytes(
        b"not-an-archive" if scenario == "invalid-archive" else FIXTURE.make_archive()
    )

    fake_ssh = root / "ssh"
    write_executable(
        fake_ssh,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import pathlib
            import sys
            import time

            scenario = {scenario!r}
            marker = pathlib.Path({str(ssh_marker)!r})
            previous = marker.read_text(encoding='ascii') if marker.exists() else ''
            marker.write_text(previous + 'ran\\n', encoding='ascii')
            sys.stdin.buffer.read()
            if scenario == 'ssh-failure':
                raise SystemExit(255)
            if scenario == 'ssh-hang':
                time.sleep(30)
                raise SystemExit(99)
            sys.stdout.buffer.write(pathlib.Path({str(archive)!r}).read_bytes())
            """
        ),
    )

    source = RUNNER.read_text(encoding="utf-8")
    replacements = {
        "readonly identity_file='/tmp/mac2jb-ipad-probe-ed25519'": (
            f"readonly identity_file='{identity}'"
        ),
        "readonly known_hosts_file='/tmp/mac2jb-ipad-known-hosts'": (
            f"readonly known_hosts_file='{known_hosts}'"
        ),
        "readonly expected_identity_sha='c44fae53d6364421bb4034c62ce53a4d363a7a31dde085cc7fc4c813c75f4a5f'": (
            f"readonly expected_identity_sha='{sha256(identity)}'"
        ),
        "readonly expected_known_hosts_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'": (
            f"readonly expected_known_hosts_sha='{sha256(known_hosts)}'"
        ),
        f"readonly expected_validator_sha='{sha256(VALIDATOR)}'": (
            f"readonly expected_validator_sha='{sha256(validator)}'"
        ),
        'evidence_parent="$repo_root/build/ipad-hardware"': (
            f"evidence_parent='{evidence_parent}'"
        ),
        "run_bounded 60 /usr/bin/ssh": f"run_bounded 0.3 {fake_ssh}",
        "run_bounded 20 /usr/bin/python3 -I -S": (
            "run_bounded 1 /usr/bin/python3 -I -S"
            if scenario == "codesign-hang"
            else "run_bounded 5 /usr/bin/python3 -I -S"
        ),
    }
    for old, new in replacements.items():
        if old not in source:
            raise AssertionError(f"runner fixture replacement missing: {old}")
        source = source.replace(old, new)
    if scenario == "payload-drift":
        source = source.replace(
            f"readonly expected_payload_sha='{sha256(PAYLOAD)}'",
            "readonly expected_payload_sha='" + ("0" * 64) + "'",
        )
    runner = script_dir / RUNNER.name
    write_executable(runner, source)
    return {
        "runner": runner,
        "evidence": evidence_directory,
        "staging": staging_directory,
        "ssh_marker": ssh_marker,
        "validator_marker": validator_marker,
        "child_pid": child_pid,
    }


def run_once(paths: dict[str, Path], timeout: float = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/sh", str(paths["runner"])],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def ssh_runs(paths: dict[str, Path]) -> int:
    marker = paths["ssh_marker"]
    return len(marker.read_text(encoding="ascii").splitlines()) if marker.exists() else 0


def process_is_live(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True


def assert_process_stops(process_id: int) -> None:
    deadline = time.monotonic() + 5
    while process_is_live(process_id) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not process_is_live(process_id), f"orphan process remained: {process_id}"


def test_success_uses_real_attestation() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-collector-test-") as directory:
        paths = prepare(Path(directory), "success")
        result = run_once(paths)
        assert result.returncode == 0, result.stderr
        assert ssh_runs(paths) == 1
        assert result.stdout.startswith("PASS installed toolbox attestation ")
        assert (paths["evidence"] / "attestation-manifest.json").is_file()
        assert not paths["staging"].exists()


def test_transport_and_validation_fail_closed() -> None:
    for scenario in ("ssh-failure", "invalid-archive"):
        with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-collector-test-") as directory:
            paths = prepare(Path(directory), scenario)
            result = run_once(paths)
            assert result.returncode != 0, scenario
            assert ssh_runs(paths) == 1, scenario
            assert not paths["evidence"].exists(), scenario
            assert not paths["staging"].exists(), scenario


def test_preflight_failures_never_contact_device() -> None:
    for condition in ("existing-output", "stale-staging", "payload-drift"):
        with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-collector-test-") as directory:
            scenario = "payload-drift" if condition == "payload-drift" else "success"
            paths = prepare(Path(directory), scenario)
            if condition == "existing-output":
                paths["evidence"].mkdir()
                (paths["evidence"] / "sentinel").write_text("preserve", encoding="ascii")
            if condition == "stale-staging":
                paths["staging"].mkdir()
                (paths["staging"] / "sentinel").write_text("preserve", encoding="ascii")
            result = run_once(paths)
            assert result.returncode != 0, condition
            assert ssh_runs(paths) == 0, condition
            if condition == "existing-output":
                assert (paths["evidence"] / "sentinel").read_text() == "preserve"
            if condition == "stale-staging":
                assert (paths["staging"] / "sentinel").read_text() == "preserve"


def test_hanging_ssh_is_killed_by_watchdog() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-collector-test-") as directory:
        paths = prepare(Path(directory), "ssh-hang")
        started = time.monotonic()
        result = run_once(paths)
        elapsed = time.monotonic() - started
        assert result.returncode != 0
        assert ssh_runs(paths) == 1
        assert elapsed < 3
        assert not paths["evidence"].exists()


def test_hanging_codesign_is_killed_and_stale_stage_blocks_retry() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-collector-test-") as directory:
        paths = prepare(Path(directory), "codesign-hang")
        started = time.monotonic()
        result = run_once(paths)
        elapsed = time.monotonic() - started
        assert result.returncode != 0
        assert elapsed < 3
        assert ssh_runs(paths) == 1
        assert paths["staging"].is_dir()
        process_id = int(paths["child_pid"].read_text(encoding="ascii"))
        assert_process_stops(process_id)
        retry = run_once(paths)
        assert retry.returncode != 0
        assert ssh_runs(paths) == 1, "stale-stage retry contacted SSH"


def test_inner_codesign_timeout_cannot_leave_a_descendant() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-collector-test-") as directory:
        paths = prepare(Path(directory), "codesign-inner-timeout")
        started = time.monotonic()
        result = run_once(paths)
        elapsed = time.monotonic() - started
        assert result.returncode != 0
        assert elapsed < 3
        assert ssh_runs(paths) == 1
        assert paths["validator_marker"].is_file()
        process_id = int(paths["child_pid"].read_text(encoding="ascii"))
        assert_process_stops(process_id)
        assert not paths["evidence"].exists()
        assert not paths["staging"].exists()


def test_handled_signals_forward_and_reap_validator_group() -> None:
    for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-collector-signal-") as directory:
            paths = prepare(Path(directory), "codesign-hang")
            process = subprocess.Popen(
                ["/bin/sh", str(paths["runner"])],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 10
                while (
                    not paths["validator_marker"].exists()
                    and process.poll() is None
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.005)
                assert paths["validator_marker"].exists(), handled_signal
                process.send_signal(handled_signal)
                stdout, stderr = process.communicate(timeout=10)
                assert process.returncode == 128 + handled_signal, (stdout, stderr)
                process_id = int(paths["child_pid"].read_text(encoding="ascii"))
                assert_process_stops(process_id)
                assert not paths["evidence"].exists()
                assert paths["staging"].is_dir()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


def main() -> None:
    test_success_uses_real_attestation()
    test_transport_and_validation_fail_closed()
    test_preflight_failures_never_contact_device()
    test_hanging_ssh_is_killed_by_watchdog()
    test_hanging_codesign_is_killed_and_stale_stage_blocks_retry()
    test_inner_codesign_timeout_cannot_leave_a_descendant()
    test_handled_signals_forward_and_reap_validator_group()
    print(
        "PASS installed-toolbox collector tests "
        "(7 groups, 13 scenarios, SSH/validator watchdogs, HUP/INT/TERM)"
    )


if __name__ == "__main__":
    main()
