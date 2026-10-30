#!/usr/bin/env python3
"""Hermetic safety tests for the installed-toolbox stdout probe launcher."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[6]
PAYLOAD = ROOT / "scripts/ipad-hardware/device/u1-readonly-run-installed-toolbox-probe.sh"
EXECUTABLES = {
    "baseline": "mac2jb-u1-baseline",
    "setdescription": "Probes/mac2jb-u1-setdescription",
    "controller-client": "Probes/mac2jb-u1-controller-client",
    "interface-client": "Probes/mac2jb-u1-interface-client",
}


def write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o555)


def make_bundle(root: Path, container: str = "UUID") -> Path:
    app = root / container / "Mac2JBU1-Toolbox.app"
    executable_body = textwrap.dedent(
        f"""\
        #!{sys.executable}
        import json
        import os
        import sys

        print(json.dumps({{
            'arguments': sys.argv[1:],
            'executable': sys.argv[0],
            'environment': dict(os.environ),
        }}, sort_keys=True))
        """
    )
    for relative in EXECUTABLES.values():
        write_executable(app / relative, executable_body)
        (app / relative).chmod(0o755)
    for directory in (app, app / "Probes"):
        directory.chmod(0o755)
    return app


def snapshot(root: Path) -> dict[Path, tuple[bytes, int]]:
    return {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def prepare(root: Path, scenario: str) -> tuple[Path, Path, Path]:
    containers = root / "containers"
    applications = root / "applications"
    jb_applications = root / "jb-applications"
    for directory in (containers, applications, jb_applications):
        directory.mkdir()

    if scenario not in ("absent", "symlink-app", "symlink-container"):
        app = make_bundle(containers)
    else:
        app = containers / "UUID/Mac2JBU1-Toolbox.app"
    if scenario == "duplicate":
        make_bundle(applications, container="")
    if scenario == "symlink-app":
        real_app = make_bundle(root / "outside")
        (containers / "UUID").mkdir()
        app.symlink_to(real_app)
    if scenario == "symlink-container":
        real_container = root / "real-container"
        make_bundle(real_container, container="")
        link = containers / "UUID"
        link.symlink_to(real_container)
    if scenario == "symlink-probes":
        probes = app / "Probes"
        outside = root / "outside-probes"
        outside.mkdir()
        for child in list(probes.iterdir()):
            child.rename(outside / child.name)
        probes.rmdir()
        probes.symlink_to(outside)
    if scenario == "symlink-binary":
        binary = app / EXECUTABLES["controller-client"]
        target = root / "outside-probe"
        write_executable(target, binary.read_text(encoding="utf-8"))
        binary.unlink()
        binary.symlink_to(target)

    fake_timeout = root / "timeout"
    write_executable(
        fake_timeout,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import os
            import sys

            scenario = {scenario!r}
            arguments = sys.argv[1:]
            if len(arguments) < 4 or arguments[:2] != ['-k', '1']:
                raise SystemExit(98)
            command = arguments[3]
            if command.endswith('/sleep'):
                raise SystemExit(0 if scenario == 'timeout-canary-fail' else 124)
            if scenario == 'probe-timeout':
                raise SystemExit(124)
            if scenario == 'probe-failure':
                raise SystemExit(42)
            os.execv(command, arguments[3:])
            """
        ),
    )

    fake_stat = root / "stat"
    write_executable(
        fake_stat,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import pathlib
            import sys

            scenario = {scenario!r}
            if len(sys.argv) != 4 or sys.argv[1:3] != ['-f', '%u:%g:%Lp']:
                raise SystemExit(98)
            path = pathlib.Path(sys.argv[3])
            if path.name == 'Mac2JBU1-Toolbox.app':
                value = '33:33:755' if scenario == 'wrong-app-metadata' else '0:0:755'
            elif path.name == 'Probes':
                value = '0:0:755' if scenario == 'wrong-probes-metadata' else '33:33:755'
            else:
                value = '0:0:755' if scenario == 'wrong-binary-metadata' else '33:33:755'
            print(value)
            """
        ),
    )

    fake_sha256 = root / "sha256sum"
    write_executable(
        fake_sha256,
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import hashlib
            import pathlib
            import sys

            if len(sys.argv) != 2:
                raise SystemExit(98)
            path = pathlib.Path(sys.argv[1])
            print(f"{{hashlib.sha256(path.read_bytes()).hexdigest()}}  {{path}}")
            """
        ),
    )

    source = PAYLOAD.read_text(encoding="utf-8")
    timeout_block = """for candidate in \\
  /var/jb/usr/bin/timeout \\
  /var/jb/bin/timeout \\
  /usr/bin/timeout \\
  /bin/timeout \\
  /var/jb/usr/bin/gtimeout \\
  /var/jb/bin/gtimeout \\
  /usr/bin/gtimeout \\
  /bin/gtimeout
do"""
    source = source.replace(timeout_block, f"for candidate in '{fake_timeout}'\ndo")
    stat_block = "for candidate in /usr/bin/stat /bin/stat /var/jb/usr/bin/stat /var/jb/bin/stat\ndo"
    source = source.replace(stat_block, f"for candidate in '{fake_stat}'\ndo")
    sha256_block = """for candidate in \\
  /var/jb/usr/bin/sha256sum \\
  /var/jb/bin/sha256sum \\
  /usr/bin/sha256sum \\
  /bin/sha256sum
do"""
    source = source.replace(sha256_block, f"for candidate in '{fake_sha256}'\ndo")
    roots = """  /var/containers/Bundle/Application \\
  /Applications \\
  /var/jb/Applications"""
    fixture_roots = f"  '{containers}' \\\n  '{applications}' \\\n  '{jb_applications}'"
    source = source.replace(roots, fixture_roots)
    globs = """  /var/containers/Bundle/Application/*/Mac2JBU1-Toolbox.app \\
  /Applications/Mac2JBU1-Toolbox.app \\
  /var/jb/Applications/Mac2JBU1-Toolbox.app"""
    fixture_globs = f"""  '{containers}'/*/Mac2JBU1-Toolbox.app \\
  '{applications}'/Mac2JBU1-Toolbox.app \\
  '{jb_applications}'/Mac2JBU1-Toolbox.app"""
    source = source.replace(globs, fixture_globs)
    if source == PAYLOAD.read_text(encoding="utf-8"):
        raise AssertionError("launcher fixture rewrite did not apply")
    payload = root / "payload.sh"
    write_executable(payload, source)
    return payload, containers, app


def execute(
    scenario: str,
    *arguments: str,
    bind_digest: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-toolbox-launcher-test-") as directory:
        root = Path(directory)
        payload, fixture_root, app = prepare(root, scenario)
        invocation = list(arguments)
        if bind_digest and len(invocation) == 4:
            relative = EXECUTABLES.get(invocation[0])
            candidate = app / relative if relative else None
            digest = (
                hashlib.sha256(candidate.read_bytes()).hexdigest()
                if candidate is not None and candidate.is_file()
                else "0" * 64
            )
            invocation.append(digest)
        before = snapshot(fixture_root)
        result = subprocess.run(
            ["/bin/sh", str(payload), *invocation],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
        )
        after = snapshot(fixture_root)
        assert after == before
        return result


def expected_arguments(peer: str, orientation: str, power: str) -> list[str]:
    peer_identity = (
        "mac2jb-generic-capture-host-primary"
        if peer == "capture-host"
        else "mac2jb-nintendo-switch-primary"
    )
    return [
        "--soc", "T8112",
        "--port-family", "thunderbolt-usb4",
        "--dopamine-build", "3.0.12-1",
        "--trollstore-build", "2.1.1",
        "--peer-kind", peer,
        "--peer-id", peer_identity,
        "--cable-id", "mac2jb-known-good-usbc-cable-primary",
        "--orientation", orientation,
        "--power-state", power,
        "--client-type", "0",
        "--client-type", "123",
    ]


def test_all_variants_and_scenarios_use_exact_arguments() -> None:
    combinations = (
        ("capture-host", "a", "operator-observed-vbus-charging"),
        ("capture-host", "b", "operator-observed-vbus-not-charging"),
        ("switch", "a", "operator-observed-no-vbus"),
        ("switch", "b", "operator-not-observed"),
    )
    for variant, relative in EXECUTABLES.items():
        for peer, orientation, power in combinations:
            result = execute("success", variant, peer, orientation, power)
            assert result.returncode == 0, (variant, peer, orientation, result.stderr)
            assert result.stderr == b""
            document = json.loads(result.stdout)
            assert document["arguments"] == expected_arguments(peer, orientation, power)
            assert document["executable"].endswith(relative)
            environment = document["environment"]
            assert environment["LC_ALL"] == "C"
            assert environment["PATH"] == (
                "/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:"
                "/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin"
            )
            # Darwin may inject its text-encoding hint after `env -i`.
            assert set(environment) <= {"LC_ALL", "PATH", "__CF_USER_TEXT_ENCODING"}


def test_argument_allowlists_fail_before_launch() -> None:
    valid = [
        "baseline",
        "capture-host",
        "a",
        "operator-observed-vbus-charging",
    ]
    invalid = (
        [],
        valid + ["extra"],
        ["unknown", *valid[1:]],
        [valid[0], "other", *valid[2:]],
        [*valid[:2], "c", valid[3]],
        [*valid[:3], "arbitrary-power"],
    )
    for arguments in invalid:
        result = execute("success", *arguments)
        assert result.returncode == 64
        assert result.stdout == b""
    missing_digest = execute("success", *valid, bind_digest=False)
    assert missing_digest.returncode == 64
    malformed_digest = execute("success", *valid, "g" * 64)
    assert malformed_digest.returncode == 64


def test_bundle_and_binary_ambiguity_fail_closed() -> None:
    arguments = (
        "controller-client",
        "capture-host",
        "a",
        "operator-observed-vbus-charging",
    )
    expected = {
        "absent": 68,
        "duplicate": 65,
        "symlink-app": 66,
        "symlink-container": 66,
        "wrong-app-metadata": 66,
        "symlink-probes": 66,
        "wrong-probes-metadata": 66,
        "symlink-binary": 66,
        "wrong-binary-metadata": 66,
    }
    for scenario, status in expected.items():
        result = execute(scenario, *arguments)
        assert result.returncode == status, scenario
        assert result.stdout == b"", scenario

    wrong_digest = execute("success", *arguments, "f" * 64)
    assert wrong_digest.returncode == 66
    assert wrong_digest.stdout == b""


def test_timeout_and_probe_failures_propagate_without_output() -> None:
    arguments = (
        "baseline",
        "switch",
        "b",
        "operator-not-observed",
    )
    for scenario, status in (
        ("timeout-canary-fail", 67),
        ("probe-timeout", 124),
        ("probe-failure", 42),
    ):
        result = execute(scenario, *arguments)
        assert result.returncode == status, scenario
        assert result.stdout == b"", scenario


def main() -> None:
    test_all_variants_and_scenarios_use_exact_arguments()
    test_argument_allowlists_fail_before_launch()
    test_bundle_and_binary_ambiguity_fail_closed()
    test_timeout_and_probe_failures_propagate_without_output()
    print("PASS installed-toolbox probe launcher tests (4 groups, 37 scenarios)")


if __name__ == "__main__":
    main()
