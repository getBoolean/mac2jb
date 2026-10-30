#!/usr/bin/env python3
"""Hermetic transport tests for the installed-toolbox authorization batch.

Each scenario rewrites a temporary runner copy to use fake SSH, validators,
credentials, and attestation evidence. No network endpoint or iPad is used.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import textwrap
import time


ROOT = Path(__file__).resolve().parents[6]
RUNNER = ROOT / "scripts/ipad-hardware/run-installed-toolbox-authorization-batch.py"
OUTPUT_NAME = "probe-capture-capture-host-a-operator-not-observed"
VARIANTS = {
    "baseline": "mac2jb-u1-baseline",
    "setdescription": "Probes/mac2jb-u1-setdescription",
    "controller-client": "Probes/mac2jb-u1-controller-client",
    "interface-client": "Probes/mac2jb-u1-interface-client",
}
FILES = {
    "Info.plist": b"plist",
    "mac2jb-u1-baseline": b"baseline-signed",
    "Probes/mac2jb-u1-setdescription": b"setdescription-signed",
    "Probes/mac2jb-u1-controller-client": b"controller-signed",
    "Probes/mac2jb-u1-interface-client": b"interface-signed",
    "_CodeSignature/CodeResources": b"resources",
}
MODES = {
    "Info.plist": 0o644,
    "mac2jb-u1-baseline": 0o755,
    "Probes/mac2jb-u1-setdescription": 0o755,
    "Probes/mac2jb-u1-controller-client": 0o755,
    "Probes/mac2jb-u1-interface-client": 0o755,
    "_CodeSignature/CodeResources": 0o644,
}
CODE_RECORDS = {
    relative: {
        "entitlements": {},
        "identifier": f"fixture.{Path(relative).name}",
        "signatureStrippedSha256": "1" * 64,
    }
    for relative in VARIANTS.values()
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path: Path, data: bytes, mode: int = 0o400) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def write_executable(path: Path, source: str) -> None:
    write(path, source.encode(), 0o555)


def make_attestation(repo: Path) -> None:
    evidence = repo / "build/ipad-hardware/installed-toolbox-attestation"
    app = evidence / "Mac2JBU1-Toolbox.app"
    for relative, content in FILES.items():
        write(app / relative, content, 0o600)
    manifest = {
        "appDirectory": "Mac2JBU1-Toolbox.app",
        "archiveSha256": "a" * 64,
        "bundleIdentifier": "dev.mac2jb.u1probe.toolbox",
        "code": CODE_RECORDS,
        "directories": {
            ".": {"gid": 0, "mode": "0755", "uid": 0},
            "Probes": {"gid": 33, "mode": "0755", "uid": 33},
            "_CodeSignature": {"gid": 33, "mode": "0755", "uid": 33},
        },
        "files": {
            relative: {
                "gid": 33,
                "mode": f"{MODES[relative]:04o}",
                "sha256": digest(content),
                "size": len(content),
                "uid": 33,
            }
            for relative, content in FILES.items()
        },
        "schemaVersion": 2,
        "sourceFamily": "container",
    }
    write(
        evidence / "attestation-manifest.json",
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
        0o600,
    )


def fake_attestation_validator_source(scenario: str, child_pid: Path) -> str:
    return textwrap.dedent(
        f"""\
        import pathlib
        import resource
        import subprocess
        import sys
        import time

        APP_NAME = 'Mac2JBU1-Toolbox.app'
        MAX_MEMBER_SIZE = 4 * 1024 * 1024
        EXPECTED_CHILD_UID = 33
        EXPECTED_CHILD_GID = 33
        EXPECTED_INFO = {{'CFBundleIdentifier': 'dev.mac2jb.u1probe.toolbox'}}
        EXPECTED_DIRECTORY_METADATA = {{
            '': (0o755, 0, 0),
            'Probes': (0o755, 33, 33),
            '_CodeSignature': (0o755, 33, 33),
        }}
        EXPECTED_FILES = {MODES!r}
        EXPECTED_CODE = {{name: (name, {{}}) for name in {list(VARIANTS.values())!r}}}
        CODE_RECORDS = {CODE_RECORDS!r}

        def validate_reconstructed_app(app, scratch):
            if {scenario!r} in ('attestation-hang', 'attestation-signal'):
                child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
                pathlib.Path({str(child_pid)!r}).write_text(str(child.pid))
                time.sleep(60)
            if resource.getrlimit(resource.RLIMIT_FSIZE)[1] < MAX_MEMBER_SIZE:
                raise ValueError('attestation hard file limit below validator member cap')
            scratch_probe = scratch / '.large-signature-stripped-fixture'
            scratch_probe.write_bytes(b'x' * (128 * 1024))
            scratch_probe.unlink()
            for relative in EXPECTED_FILES:
                if not (app / relative).is_file():
                    raise ValueError('missing fixture file')
            return CODE_RECORDS
        """
    )


def fake_report_validator_source() -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import hashlib
        import json
        import pathlib
        import sys

        report, variant, peer, orientation, power = sys.argv[1:]
        data = pathlib.Path(report).read_bytes()
        try:
            document = json.loads(data)
        except Exception:
            raise SystemExit(65)
        if document.get('reject') or [document.get(key) for key in ('variant', 'peer', 'orientation', 'power')] != [variant, peer, orientation, power]:
            raise SystemExit(65)
        report_hash = hashlib.sha256(data[:-1]).hexdigest()
        print(f"PASS probe report {{report_hash}} {{document['topologyFingerprint']}}")
        """
    )


def fake_ssh_source(scenario: str, contacts: Path, output: Path, remote_pid: Path) -> str:
    return textwrap.dedent(
        f"""\
        #!{sys.executable}
        import hashlib
        import json
        import os
        import pathlib
        import shlex
        import sys
        import time

        scenario = {scenario!r}
        contacts = pathlib.Path({str(contacts)!r})
        output = pathlib.Path({str(output)!r})
        remote_pid = pathlib.Path({str(remote_pid)!r})
        payload = sys.stdin.buffer.read()
        if not payload:
            raise SystemExit(98)
        with contacts.open('a') as stream:
            stream.write('contact\\n')
        call = len(contacts.read_text().splitlines())
        remote_pid.write_text(str(os.getpid()))
        if scenario in ('hang', 'signal'):
            time.sleep(60)
        if scenario == 'ssh-fail':
            raise SystemExit(255)
        if scenario == 'oversize':
            sys.stdout.buffer.write(b'x' * (3 * 1024 * 1024))
            raise SystemExit(0)
        tokens = shlex.split(sys.argv[-1])
        marker = tokens.index('--')
        variant, peer, orientation, power, signed_hash = tokens[marker + 1:marker + 6]
        if len(signed_hash) != 64:
            raise SystemExit(97)
        topology = hashlib.sha256(variant.encode()).hexdigest()
        if scenario == 'topology-mismatch' and call == 2:
            topology = 'f' * 64
        document = {{
            'orientation': orientation,
            'peer': peer,
            'power': power,
            'topologyFingerprint': topology,
            'variant': variant,
        }}
        if scenario == 'validator-fail' and call == 3:
            document['reject'] = True
        print(json.dumps(document, sort_keys=True))
        if scenario == 'publication-race' and call == 8:
            output.mkdir()
            (output / 'attacker-marker').write_text('preserve')
        """
    )


def replace_constant(source: str, name: str, value: str) -> str:
    pattern = rf'^{name} = "[0-9a-f]{{64}}"$'
    updated, count = re.subn(pattern, f'{name} = "{value}"', source, flags=re.MULTILINE)
    assert count == 1, name
    return updated


def prepare(root: Path, scenario: str) -> dict[str, Path]:
    repo = root / "repo"
    script_dir = repo / "scripts/ipad-hardware"
    build = repo / "build/ipad-hardware"
    script_dir.mkdir(parents=True)
    build.mkdir(parents=True)
    make_attestation(repo)

    launcher = script_dir / "device/u1-readonly-run-installed-toolbox-probe.sh"
    launcher_data = b"#!/bin/sh\nexit 0\n"
    write(launcher, launcher_data, 0o555)
    report_validator = script_dir / "validate-probe-stdout.py"
    write_executable(report_validator, fake_report_validator_source())
    attestation_validator = script_dir / "validate-installed-toolbox-trollstore.py"
    attestation_child_pid = root / "attestation-child-pid"
    write(
        attestation_validator,
        fake_attestation_validator_source(scenario, attestation_child_pid).encode(),
        0o400,
    )
    identity = root / "identity"
    known_hosts = root / "known-hosts"
    write(identity, b"identity", 0o600)
    write(known_hosts, b"known-hosts", 0o600)
    contacts = root / "contacts"
    remote_pid = root / "remote-pid"
    output = build / OUTPUT_NAME
    fake_ssh = root / "ssh"
    write_executable(fake_ssh, fake_ssh_source(scenario, contacts, output, remote_pid))

    source = RUNNER.read_text()
    source = source.replace('IDENTITY_FILE = Path("/Users/boolean/.ssh/mac2jb-ipad/mac2jb-ipad-probe-ed25519")', f'IDENTITY_FILE = Path({str(identity)!r})')
    source = source.replace('KNOWN_HOSTS_FILE = Path("/Users/boolean/.ssh/mac2jb-ipad/mac2jb-ipad-known-hosts")', f'KNOWN_HOSTS_FILE = Path({str(known_hosts)!r})')
    source = source.replace('SSH = Path("/usr/bin/ssh")', f'SSH = Path({str(fake_ssh)!r})')
    source = source.replace('SSH_TIMEOUT = 45.0', 'SSH_TIMEOUT = 0.5')
    source = source.replace('VALIDATOR_TIMEOUT = 10.0', 'VALIDATOR_TIMEOUT = 0.5')
    source = source.replace('ATTESTATION_TIMEOUT = 60.0', 'ATTESTATION_TIMEOUT = 0.5')
    for name, path in (
        ("EXPECTED_IDENTITY_SHA", identity),
        ("EXPECTED_KNOWN_HOSTS_SHA", known_hosts),
        ("EXPECTED_LAUNCHER_SHA", launcher),
        ("EXPECTED_REPORT_VALIDATOR_SHA", report_validator),
        ("EXPECTED_ATTESTATION_VALIDATOR_SHA", attestation_validator),
    ):
        source = replace_constant(source, name, digest(path.read_bytes()))
    runner = script_dir / RUNNER.name
    write(runner, source.encode(), 0o500)
    return {
        "attestation_child_pid": attestation_child_pid,
        "attestation_validator": attestation_validator,
        "contacts": contacts,
        "launcher": launcher,
        "output": output,
        "remote_pid": remote_pid,
        "runner": runner,
        "staging": build / f".{OUTPUT_NAME}.staging",
    }


def invoke(paths: dict[str, Path]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "/usr/bin/python3", "-I", "-S", str(paths["runner"]),
            "capture-host", "a", "operator-not-observed",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=12,
        check=False,
    )


def contact_count(paths: dict[str, Path]) -> int:
    path = paths["contacts"]
    return len(path.read_text().splitlines()) if path.exists() else 0


def assert_no_capture(paths: dict[str, Path]) -> None:
    assert not paths["output"].exists()
    assert not paths["staging"].exists()


def test_success() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        paths = prepare(Path(temporary), "success")
        result = invoke(paths)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert result.stderr == ""
        assert contact_count(paths) == 8
        files = {item.name for item in paths["output"].iterdir()}
        assert files == {
            "batch-manifest.json",
            *{
                f"{variant}-round-{round_number}.json"
                for variant in VARIANTS
                for round_number in (1, 2)
            },
        }
        manifest = json.loads((paths["output"] / "batch-manifest.json").read_text())
        assert len(manifest["reports"]) == 8
        assert not paths["staging"].exists()


def test_failures_stop_later_contact() -> None:
    scenarios = {
        "ssh-fail": 1,
        "hang": 1,
        "oversize": 1,
        "topology-mismatch": 2,
        "validator-fail": 3,
    }
    for scenario, expected_contacts in scenarios.items():
        with tempfile.TemporaryDirectory() as temporary:
            paths = prepare(Path(temporary), scenario)
            result = invoke(paths)
            assert result.returncode == 65, (scenario, result.stdout, result.stderr)
            assert contact_count(paths) == expected_contacts, scenario
            assert_no_capture(paths)


def test_preflight_failures_make_no_contact() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        paths = prepare(Path(temporary), "success")
        paths["output"].mkdir()
        result = invoke(paths)
        assert result.returncode == 65
        assert contact_count(paths) == 0
    with tempfile.TemporaryDirectory() as temporary:
        paths = prepare(Path(temporary), "success")
        paths["launcher"].chmod(0o600)
        paths["launcher"].write_bytes(b"drift")
        result = invoke(paths)
        assert result.returncode == 65
        assert contact_count(paths) == 0
        assert_no_capture(paths)
    with tempfile.TemporaryDirectory() as temporary:
        paths = prepare(Path(temporary), "attestation-hang")
        result = invoke(paths)
        assert result.returncode == 65
        assert contact_count(paths) == 0
        child_pid = int(paths["attestation_child_pid"].read_text())
        deadline = time.monotonic() + 2
        while process_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not process_exists(child_pid)
        assert_no_capture(paths)


def test_publication_race_preserves_competing_path() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        paths = prepare(Path(temporary), "publication-race")
        result = invoke(paths)
        assert result.returncode == 65
        assert contact_count(paths) == 8
        assert (paths["output"] / "attacker-marker").read_text() == "preserve"
        assert not paths["staging"].exists()


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_signal_reaps_active_transport() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        paths = prepare(Path(temporary), "signal")
        process = subprocess.Popen(
            [
                "/usr/bin/python3", "-I", "-S", str(paths["runner"]),
                "capture-host", "a", "operator-not-observed",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 5
        while contact_count(paths) == 0 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert contact_count(paths) == 1
        remote_pid = int(paths["remote_pid"].read_text())
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=5)
        assert process.returncode == 143
        deadline = time.monotonic() + 2
        while process_exists(remote_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not process_exists(remote_pid)
        assert_no_capture(paths)


def test_signal_reaps_attestation_descendant() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        paths = prepare(Path(temporary), "attestation-signal")
        process = subprocess.Popen(
            [
                "/usr/bin/python3", "-I", "-S", str(paths["runner"]),
                "capture-host", "a", "operator-not-observed",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 5
        while not paths["attestation_child_pid"].exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert paths["attestation_child_pid"].exists()
        child_pid = int(paths["attestation_child_pid"].read_text())
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=5)
        assert process.returncode == 143
        deadline = time.monotonic() + 2
        while process_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not process_exists(child_pid)
        assert contact_count(paths) == 0
        assert_no_capture(paths)


def main() -> None:
    test_success()
    test_failures_stop_later_contact()
    test_preflight_failures_make_no_contact()
    test_publication_race_preserves_competing_path()
    test_signal_reaps_active_transport()
    test_signal_reaps_attestation_descendant()
    print("PASS installed-toolbox authorization batch tests (6 groups, 12 scenarios)")


if __name__ == "__main__":
    main()
