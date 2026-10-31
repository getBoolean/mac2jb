#!/usr/bin/env python3
"""Hermetic transport, framing, timeout, and grammar tests for the app selector."""

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


ROOT = Path(__file__).resolve().parents[6]
RUNNER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/run-approved-readonly-device-probe.sh"
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-app-versions.sh"
CAPABILITY_PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-app-version-capabilities.sh"
ARCHIVE_CAPABILITY_PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-app-archive-capabilities.sh"
ARCHIVE_VARIANT_PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-app-archive-variants.sh"
APPSYNC_CAPABILITY_PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-appsync-install-capabilities.sh"
APPSYNC_QUERY_STATUS_PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-appsync-query-status.sh"
APPSYNC_MEMBERSHIP_PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u1-readonly-appsync-package-membership.sh"
STANDARD_BODY = (
    "dopamine-app: version=2.4.5 build=1 bundle-family=standard\n"
    "trollstore-app: version=2.1.0 build=210 bundle-family=stealth\n"
)
CAPABILITY_BODY = "\n".join(
    [
        "system-plutil-type: regular-file",
        "system-plutil-readable: yes",
        "system-plutil-writable: no",
        "system-plutil-executable: yes",
        "rootless-usr-plutil-type: symbolic-link",
        "rootless-usr-plutil-readable: yes",
        "rootless-usr-plutil-writable: no",
        "rootless-usr-plutil-executable: yes",
        "rootless-bin-plutil-type: absent",
        "rootless-bin-plutil-readable: no",
        "rootless-bin-plutil-writable: no",
        "rootless-bin-plutil-executable: no",
        "rootless-plistutil-type: regular-file",
        "rootless-plistutil-readable: yes",
        "rootless-plistutil-writable: no",
        "rootless-plistutil-executable: yes",
        "container-app-root-type: directory",
        "container-app-root-readable: yes",
        "container-app-root-searchable: yes",
        "system-app-root-type: directory",
        "system-app-root-readable: yes",
        "system-app-root-searchable: yes",
        "rootless-app-root-type: directory",
        "rootless-app-root-readable: yes",
        "rootless-app-root-searchable: yes",
    ]
) + "\n"
ARCHIVE_CAPABILITY_BODY = (
    "timeout-guard: canary-passed\n"
    "tar-family: gnu\n"
    "target-candidate-count: 2\n"
    "target-path-length: at-most-100\n"
    "single-file-success-count: 2\n"
    "single-file-failure-count: 0\n"
    "empty-archive-status: 0\n"
    "combined-archive-status: 0\n"
)
ARCHIVE_VARIANT_BODY = (
    "timeout-guard: canary-passed\n"
    "tar-family: gnu\n"
    "dd-candidate: present\n"
    "target-candidate-count: 2\n"
    "direct-read-success-count: 2\n"
    "direct-read-failure-count: 0\n"
    "relative-ustar-success-count: 2\n"
    "relative-ustar-failure-count: 0\n"
    "relative-default-success-count: 2\n"
    "relative-default-failure-count: 0\n"
    "relative-minimal-success-count: 2\n"
    "relative-minimal-failure-count: 0\n"
)
APPSYNC_CAPABILITY_BODY = (
    "dpkg-query: present\n"
    "appsync-package: installed version=116.0 architecture=iphoneos-arm64\n"
    "appinst-package: installed version=2.1.1 architecture=iphoneos-arm64\n"
    "ellekit-package: installed version=1.1.2 architecture=iphoneos-arm64\n"
    "appinst-binary-type: regular-file\n"
    "appinst-binary-readable: yes\n"
    "appinst-binary-writable: no\n"
    "appinst-binary-executable: yes\n"
    "appsync-installd-dylib-type: regular-file\n"
    "appsync-installd-dylib-readable: yes\n"
    "appsync-installd-dylib-writable: no\n"
    "appsync-installd-dylib-executable: yes\n"
    "appsync-installd-filter-type: regular-file\n"
    "appsync-installd-filter-readable: yes\n"
    "appsync-installd-filter-writable: no\n"
    "appsync-installd-filter-executable: no\n"
    "appsync-frontboard-dylib-type: regular-file\n"
    "appsync-frontboard-dylib-readable: yes\n"
    "appsync-frontboard-dylib-writable: no\n"
    "appsync-frontboard-dylib-executable: yes\n"
    "appsync-frontboard-filter-type: regular-file\n"
    "appsync-frontboard-filter-readable: yes\n"
    "appsync-frontboard-filter-writable: no\n"
    "appsync-frontboard-filter-executable: no\n"
)
APPSYNC_NOT_OBSERVED_BODY = APPSYNC_CAPABILITY_BODY.replace(
    "appinst-binary-type: regular-file\n"
    "appinst-binary-readable: yes\n"
    "appinst-binary-writable: no\n"
    "appinst-binary-executable: yes\n",
    "appinst-binary-type: not-observed\n"
    "appinst-binary-readable: no\n"
    "appinst-binary-writable: no\n"
    "appinst-binary-executable: no\n",
)
APPSYNC_QUERY_STATUS_BODY = (
    "appsync-query-status: 2\n"
    "appinst-query-status: 1\n"
    "ellekit-query-status: 0\n"
)
APPSYNC_MEMBERSHIP_BODY = (
    "dpkg-list-status: 0\n"
    "appsync-membership: not-observed\n"
    "appinst-membership: not-observed\n"
    "ellekit-membership: installed\n"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o555)


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def prepare(root: Path, body: str, mode: str = "normal", selector: str = "app-versions") -> Path:
    payload_directory = root / "device"
    payload_directory.mkdir()
    if selector == "app-versions":
        selected_payload = PAYLOAD
    elif selector == "app-version-capabilities":
        selected_payload = CAPABILITY_PAYLOAD
    elif selector == "app-archive-capabilities":
        selected_payload = ARCHIVE_CAPABILITY_PAYLOAD
    elif selector == "app-archive-variants":
        selected_payload = ARCHIVE_VARIANT_PAYLOAD
    elif selector == "appsync-install-capabilities":
        selected_payload = APPSYNC_CAPABILITY_PAYLOAD
    elif selector == "appsync-query-status":
        selected_payload = APPSYNC_QUERY_STATUS_PAYLOAD
    elif selector == "appsync-package-membership":
        selected_payload = APPSYNC_MEMBERSHIP_PAYLOAD
    else:
        raise AssertionError(selector)
    staged_payload = payload_directory / selected_payload.name
    if mode == "execute-valid-remote":
        write_executable(
            staged_payload,
            "#!/bin/sh\n"
            "command printf '%s\\n' "
            "'dopamine-app: version=2.4.5 build=1 bundle-family=standard' "
            "'trollstore-app: version=2.1.0 build=210 bundle-family=stealth'\n",
        )
    else:
        staged_payload.write_bytes(selected_payload.read_bytes())
        staged_payload.chmod(0o555)

    identity = root / "identity"
    known_hosts = root / "known-hosts"
    identity.write_text("fixture identity\n", encoding="ascii")
    known_hosts.write_text("fixture host pin\n", encoding="ascii")
    identity.chmod(0o600)
    known_hosts.chmod(0o600)

    fake_mode = "execute-remote" if mode in ("writable-env", "symlink-shell") else mode
    fake_ssh = root / "ssh"
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

            body = {body!r}
            mode = {fake_mode!r}
            scenario = {mode!r}
            root = pathlib.Path({str(root)!r})
            arguments = sys.argv[1:]
            for required in ("ServerAliveInterval=5", "ServerAliveCountMax=2"):
                if required not in arguments:
                    raise SystemExit(64)
            remote_command = sys.argv[-1]
            required_remote = (
                '[ ! -L "$candidate" ]',
                '[ ! -w "$candidate" ]',
                '[ ! -L "$shell_candidate" ]',
                '[ ! -w "$shell_candidate" ]',
            )
            if any(item not in remote_command for item in required_remote):
                raise SystemExit(64)
            if scenario != "symlink-shell" and "for shell_candidate in /bin/sh /usr/bin/sh" not in remote_command:
                raise SystemExit(64)
            match = re.search(r"MAC2JB_BEGIN_([0-9a-f]{{32}})", remote_command)
            if match is None:
                raise SystemExit(64)
            nonce = match.group(1)
            if mode == "hang":
                (root / "child-pid").write_text(str(os.getpid()), encoding="ascii")
                time.sleep(30)
            if mode == "nonzero":
                raise SystemExit(7)
            if mode in ("execute-remote", "execute-valid-remote"):
                completed = subprocess.run(
                    ["/bin/sh", "-c", remote_command],
                    stdin=sys.stdin.buffer,
                    stdout=sys.stdout.buffer,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                raise SystemExit(completed.returncode)
            sys.stdin.buffer.read()
            if mode == "prefix":
                sys.stdout.write("unexpected-prefix\\n")
            sys.stdout.write(f"MAC2JB_BEGIN_{{nonce}}\\n")
            if mode == "oversized":
                sys.stdout.write("x" * 4096)
            sys.stdout.write(body)
            end_status = 1 if mode == "bad-end" else 0
            sys.stdout.write(f"MAC2JB_END_{{nonce}}:{{end_status}}\\n")
            """
        ),
    )

    source = RUNNER.read_text(encoding="utf-8")
    source = source.replace(
        "readonly identity_file='/Users/boolean/.ssh/mac2jb-ipad/mac2jb-ipad-probe-ed25519'",
        f"readonly identity_file='{identity}'",
    )
    source = source.replace(
        "readonly known_hosts_file='/Users/boolean/.ssh/mac2jb-ipad/mac2jb-ipad-known-hosts'",
        f"readonly known_hosts_file='{known_hosts}'",
    )
    source = source.replace(
        "readonly expected_identity_sha='50cf47362f38ff6404979c120147e071bfe8beb924971a27b24210d2250c76dd'",
        f"readonly expected_identity_sha='{digest(identity)}'",
    )
    source = source.replace(
        "readonly expected_known_hosts_sha='1db3d7df81efc0ffafd7ce55bffff7b2efdf5b1ec86844278b436adf1b908b35'",
        f"readonly expected_known_hosts_sha='{digest(known_hosts)}'",
    )
    if mode == "execute-valid-remote":
        source = source.replace(
            f"expected_sha='{digest(PAYLOAD)}'",
            f"expected_sha='{digest(staged_payload)}'",
        )
    if mode == "writable-env":
        bad_env = root / "writable-env"
        write_executable(
            bad_env,
            f"#!/bin/sh\ncommand printf invoked > '{root / 'unsafe-invoked'}'\nexit 99\n",
        )
        bad_env.chmod(0o755)
        source = source.replace(
            "for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do",
            f"for candidate in '{bad_env}'; do",
        )
    if mode == "symlink-shell":
        real_shell = root / "unsafe-shell-real"
        write_executable(
            real_shell,
            f"#!/bin/sh\ncommand printf invoked > '{root / 'unsafe-invoked'}'\nexec /bin/sh \"$@\"\n",
        )
        bad_shell = root / "symlink-shell"
        bad_shell.symlink_to(real_shell)
        source = source.replace(
            "for shell_candidate in /bin/sh /usr/bin/sh /var/jb/bin/dash /var/jb/usr/bin/dash /var/jb/bin/bash /var/jb/usr/bin/bash; do",
            f"for shell_candidate in '{bad_shell}'; do",
        )
    ssh_line = '    /usr/bin/python3 -I -S -c "$process_runner_code" /usr/bin/ssh \\\n'
    fake_line = f'    /usr/bin/python3 -I -S -c "$process_runner_code" \'{fake_ssh}\' \\\n'
    source = source.replace(ssh_line, fake_line)
    source = source.replace("timeout=45", "timeout=1")
    source = source.replace("/tmp/mac2jb-ipad-probe.", f"{root}/app-probe.")
    runner = root / "runner.sh"
    write_executable(runner, source)
    return runner


def execute(
    body: str,
    mode: str = "normal",
    selector: str = "app-versions",
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-app-runner-test.") as temporary:
        root = Path(temporary)
        runner = prepare(root, body, mode, selector)
        result = subprocess.run(
            ["/bin/sh", str(runner), selector],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
        pid_file = root / "child-pid"
        if pid_file.exists():
            child_pid = int(pid_file.read_text(encoding="ascii"))
            if process_exists(child_pid):
                raise AssertionError(f"{mode} left child {child_pid} alive")
        if (root / "unsafe-invoked").exists():
            raise AssertionError(f"{mode} executed an untrusted remote candidate")
        leftovers = list(root.glob("app-probe.*"))
        if leftovers:
            raise AssertionError(f"{mode} left temporary evidence: {leftovers}")
        return result


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_standard_and_absent() -> None:
    for body in (
        STANDARD_BODY,
        "dopamine-app: not-observed\ntrollstore-app: not-observed\n",
    ):
        result = execute(body)
        expect(result.returncode == 0, result.stderr)
        expect(result.stdout == body, result.stdout)


def test_valid_remote_selection_executes_fixture() -> None:
    result = execute(STANDARD_BODY, "execute-valid-remote")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == STANDARD_BODY, result.stdout)


def test_capability_grammar() -> None:
    result = execute(CAPABILITY_BODY, selector="app-version-capabilities")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == CAPABILITY_BODY, result.stdout)
    result = execute(CAPABILITY_BODY + "extra\n", selector="app-version-capabilities")
    expect(result.returncode != 0, "extra capability line falsely passed")
    expect(result.stdout == "", "malformed capability output was released")
    result = execute(ARCHIVE_CAPABILITY_BODY, selector="app-archive-capabilities")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == ARCHIVE_CAPABILITY_BODY, result.stdout)
    result = execute(ARCHIVE_CAPABILITY_BODY + "extra\n", selector="app-archive-capabilities")
    expect(result.returncode != 0, "extra archive-capability line falsely passed")
    expect(result.stdout == "", "malformed archive-capability output was released")
    result = execute(ARCHIVE_VARIANT_BODY, selector="app-archive-variants")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == ARCHIVE_VARIANT_BODY, result.stdout)
    result = execute(ARCHIVE_VARIANT_BODY + "extra\n", selector="app-archive-variants")
    expect(result.returncode != 0, "extra archive-variant line falsely passed")
    expect(result.stdout == "", "malformed archive-variant output was released")
    result = execute(APPSYNC_CAPABILITY_BODY, selector="appsync-install-capabilities")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == APPSYNC_CAPABILITY_BODY, result.stdout)
    result = execute(
        APPSYNC_NOT_OBSERVED_BODY,
        selector="appsync-install-capabilities",
    )
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == APPSYNC_NOT_OBSERVED_BODY, result.stdout)
    contradictory = APPSYNC_NOT_OBSERVED_BODY.replace(
        "appinst-binary-readable: no\n",
        "appinst-binary-readable: yes\n",
    )
    result = execute(contradictory, selector="appsync-install-capabilities")
    expect(result.returncode != 0, "contradictory not-observed path falsely passed")
    expect(result.stdout == "", "contradictory path output was released")
    result = execute(
        APPSYNC_CAPABILITY_BODY + "extra\n",
        selector="appsync-install-capabilities",
    )
    expect(result.returncode != 0, "extra AppSync capability line falsely passed")
    expect(result.stdout == "", "malformed AppSync capability output was released")
    result = execute(APPSYNC_QUERY_STATUS_BODY, selector="appsync-query-status")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == APPSYNC_QUERY_STATUS_BODY, result.stdout)
    result = execute(
        APPSYNC_QUERY_STATUS_BODY.replace("appsync-query-status: 2", "appsync-query-status: 256"),
        selector="appsync-query-status",
    )
    expect(result.returncode != 0, "out-of-range AppSync query status falsely passed")
    expect(result.stdout == "", "out-of-range AppSync status output was released")
    result = execute(
        APPSYNC_QUERY_STATUS_BODY + "extra\n",
        selector="appsync-query-status",
    )
    expect(result.returncode != 0, "extra AppSync query-status line falsely passed")
    expect(result.stdout == "", "malformed AppSync query-status output was released")
    result = execute(APPSYNC_MEMBERSHIP_BODY, selector="appsync-package-membership")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == APPSYNC_MEMBERSHIP_BODY, result.stdout)
    installed_error = APPSYNC_MEMBERSHIP_BODY.replace(
        "appsync-membership: not-observed",
        "appsync-membership: installed-error",
    )
    result = execute(installed_error, selector="appsync-package-membership")
    expect(result.returncode == 0, result.stderr)
    expect(result.stdout == installed_error, result.stdout)
    result = execute(
        APPSYNC_MEMBERSHIP_BODY.replace("dpkg-list-status: 0", "dpkg-list-status: 2"),
        selector="appsync-package-membership",
    )
    expect(result.returncode != 0, "nonzero membership producer status falsely passed")
    expect(result.stdout == "", "nonzero membership output was released")
    result = execute(
        APPSYNC_MEMBERSHIP_BODY + "extra\n",
        selector="appsync-package-membership",
    )
    expect(result.returncode != 0, "extra AppSync membership line falsely passed")
    expect(result.stdout == "", "malformed AppSync membership output was released")


def test_archive_capability_payload_has_device_timeout_guard() -> None:
    source = ARCHIVE_CAPABILITY_PAYLOAD.read_text(encoding="utf-8")
    expect(
        '"$timeout_path" -k 1 0.1 "$sleep_path" 1' in source,
        "archive capability payload lacks the timeout behavior canary",
    )
    guarded_tar_prefix = '"$timeout_path" -k 1 3 "$tar_path"'
    expect(
        source.count(guarded_tar_prefix) == 4,
        "every archive capability tar invocation must use the device-side guard",
    )
    unguarded_invocations = [
        line
        for line in source.splitlines()
        if '"$tar_path"' in line
        and guarded_tar_prefix not in line
        and 'tar_path=' not in line
        and '[ -n "$tar_path" ]' not in line
        and '[ -z "$tar_path" ]' not in line
    ]
    expect(not unguarded_invocations, f"unguarded tar invocation(s): {unguarded_invocations}")


def execute_archive_capability_payload(
    statuses: list[int],
) -> tuple[subprocess.CompletedProcess[str], int]:
    with tempfile.TemporaryDirectory(prefix="mac2jb-archive-capability-test.") as temporary:
        root = Path(temporary)
        fake_tar = root / "tar"
        fake_sleep = root / "sleep"
        fake_timeout = root / "timeout"
        status_file = root / "statuses"
        state_file = root / "state"
        app_directory = root / "container" / "Dopamine.app"
        app_directory.mkdir(parents=True)
        plist = app_directory / "Info.plist"
        plist.write_bytes(b"fixture")
        status_file.write_text("\n".join(str(item) for item in statuses) + "\n", encoding="ascii")
        state_file.write_text("0\n", encoding="ascii")
        write_executable(fake_tar, "#!/bin/sh\nexit 99\n")
        write_executable(fake_sleep, "#!/bin/sh\nexit 99\n")
        write_executable(
            fake_timeout,
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import os
                import pathlib
                import sys

                arguments = sys.argv[1:]
                if len(arguments) < 4 or arguments[:2] != ["-k", "1"]:
                    raise SystemExit(98)
                command = arguments[3]
                if command == {str(fake_sleep)!r}:
                    raise SystemExit(124)
                if command != {str(fake_tar)!r}:
                    raise SystemExit(97)
                state = pathlib.Path(os.environ["MAC2JB_FAKE_STATE"])
                available = [
                    int(item)
                    for item in pathlib.Path(os.environ["MAC2JB_FAKE_STATUSES"])
                    .read_text(encoding="ascii")
                    .splitlines()
                ]
                index = int(state.read_text(encoding="ascii").strip())
                state.write_text(f"{{index + 1}}\\n", encoding="ascii")
                if index >= len(available):
                    raise SystemExit(96)
                status = available[index]
                if arguments[4:] == ["--version"] and status == 0:
                    print("tar (GNU tar) fixture")
                raise SystemExit(status)
                """
            ),
        )

        source = ARCHIVE_CAPABILITY_PAYLOAD.read_text(encoding="utf-8")
        selection_start = source.index("tar_path=\n")
        selection_end = source.index("timeout_guard=not-observed\n")
        source = (
            source[:selection_start]
            + f"tar_path='{fake_tar}'\ntimeout_path='{fake_timeout}'\nsleep_path='{fake_sleep}'\n\n"
            + source[selection_end:]
        )
        glob_start = source.index("for plist in \\\n")
        glob_end = source.index("\ndo\n", glob_start) + len("\ndo")
        source = source[:glob_start] + f"for plist in '{plist}'\ndo" + source[glob_end:]
        staged = root / "payload.sh"
        write_executable(staged, source)
        environment = os.environ.copy()
        environment["MAC2JB_FAKE_STATUSES"] = str(status_file)
        environment["MAC2JB_FAKE_STATE"] = str(state_file)
        result = subprocess.run(
            ["/bin/sh", str(staged)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=4,
            check=False,
            env=environment,
        )
        invocation_count = int(state_file.read_text(encoding="ascii").strip())
        return result, invocation_count


def test_archive_capability_aborts_timeout_wrapper_failures() -> None:
    scenarios = [
        ([124], 1, 71),
        ([125], 1, 70),
        ([137], 1, 70),
        ([0, 124], 2, 71),
        ([0, 125], 2, 70),
        ([0, 137], 2, 70),
        ([0, 0, 124], 3, 71),
        ([0, 0, 125], 3, 70),
        ([0, 0, 137], 3, 70),
        ([0, 0, 0, 124], 4, 71),
        ([0, 0, 0, 125], 4, 70),
        ([0, 0, 0, 137], 4, 70),
    ]
    for statuses, expected_invocations, expected_status in scenarios:
        result, invocation_count = execute_archive_capability_payload(statuses)
        expect(result.returncode == expected_status, f"{statuses} returned {result.returncode}")
        expect(result.stdout == "", f"{statuses} released partial output")
        expect(
            invocation_count == expected_invocations,
            f"{statuses} reached a later tar invocation",
        )


def test_archive_capability_accepts_bounded_tar_statuses() -> None:
    for status in (1, 2):
        result, invocation_count = execute_archive_capability_payload([0, status, 0, 2])
        expect(result.returncode == 0, f"bounded status {status} failed: {result.stderr}")
        expect(invocation_count == 4, f"bounded status {status} skipped a diagnostic")
        expect("single-file-failure-count: 1\n" in result.stdout, result.stdout)
        expect(result.stdout.endswith("combined-archive-status: 2\n"), result.stdout)

    for status in (1, 2):
        result, invocation_count = execute_archive_capability_payload([status, 0, 0, 0])
        expect(result.returncode == 0, f"version status {status} failed: {result.stderr}")
        expect(invocation_count == 4, f"version status {status} skipped a diagnostic")
        expect("tar-family: not-observed\n" in result.stdout, result.stdout)


def test_untrusted_remote_candidates_are_rejected() -> None:
    for mode in ("writable-env", "symlink-shell"):
        result = execute(STANDARD_BODY, mode)
        expect(result.returncode != 0, f"{mode} falsely passed")
        expect(result.stdout == "", f"{mode} released output")


def test_malformed_or_forged_output_is_discarded() -> None:
    bodies = [
        "dopamine-app: version=2.4.5 build=1 bundle-family=standard\n",
        STANDARD_BODY + "extra\n",
        "dopamine-app: version=bad/value build=1 bundle-family=standard\n"
        "trollstore-app: not-observed\n",
        "dopamine-app: not-observed\ntrollstore-app: not-observed",
    ]
    for body in bodies:
        result = execute(body)
        expect(result.returncode != 0, f"malformed body falsely passed: {body!r}")
        expect(result.stdout == "", "malformed body was released")
    for mode in ("prefix", "bad-end", "nonzero", "oversized"):
        result = execute(STANDARD_BODY, mode)
        expect(result.returncode != 0, f"{mode} transport falsely passed")
        expect(result.stdout == "", f"{mode} transport released output")


def test_hang_is_bounded_and_reaped() -> None:
    started = time.monotonic()
    result = execute(STANDARD_BODY, "hang")
    elapsed = time.monotonic() - started
    expect(result.returncode != 0, "hung client falsely passed")
    expect(result.stdout == "", "hung client released output")
    expect(elapsed < 5, f"hung client took {elapsed:.2f}s")


def test_signals_reap_child_and_cleanup() -> None:
    for sent_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        with tempfile.TemporaryDirectory(prefix="mac2jb-app-runner-test.") as temporary:
            root = Path(temporary)
            runner = prepare(root, STANDARD_BODY, "hang")
            process = subprocess.Popen(
                ["/bin/sh", str(runner), "app-versions"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            pid_file = root / "child-pid"
            deadline = time.monotonic() + 4
            child_pid = None
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    candidate = pid_file.read_text(encoding="ascii").strip()
                except FileNotFoundError:
                    candidate = ""
                if candidate.isdecimal() and int(candidate) > 0:
                    child_pid = int(candidate)
                    break
                time.sleep(0.02)
            expect(child_pid is not None, f"{sent_signal.name} fixture child did not start")
            os.killpg(process.pid, sent_signal)
            stdout, stderr = process.communicate(timeout=4)
            expect(
                process.returncode == 128 + sent_signal,
                f"{sent_signal.name} exit was {process.returncode}: {stderr}",
            )
            expect(stdout == "", f"{sent_signal.name} released output")
            expect(not process_exists(child_pid), f"{sent_signal.name} left child {child_pid} alive")
            expect(not list(root.glob("app-probe.*")), f"{sent_signal.name} left temporary evidence")


def main() -> None:
    tests = [
        test_standard_and_absent,
        test_valid_remote_selection_executes_fixture,
        test_capability_grammar,
        test_archive_capability_payload_has_device_timeout_guard,
        test_archive_capability_aborts_timeout_wrapper_failures,
        test_archive_capability_accepts_bounded_tar_statuses,
        test_untrusted_remote_candidates_are_rejected,
        test_malformed_or_forged_output_is_discarded,
        test_hang_is_bounded_and_reaped,
        test_signals_reap_child_and_cleanup,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"PASS {len(tests)} app-version runner scenarios")


if __name__ == "__main__":
    main()
