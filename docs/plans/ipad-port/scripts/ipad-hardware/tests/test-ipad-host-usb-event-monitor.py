#!/usr/bin/env python3
"""Compile and exercise the generic-host U1 USB event monitor locally.

Only the monitor's synthetic `--self-test` path is executed. The harness never
subscribes to IOKit, opens a USB device, starts SSH, or contacts the iPad.
"""

from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[6]
SOURCE = REPO_ROOT / "scripts/ipad-hardware/host/u1-usb-event-monitor.swift"
SWIFTC = Path("/usr/bin/xcrun")
HANDLED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
ACTIVE_PROCESS: subprocess.Popen[str] | None = None
RECEIVED_SIGNAL = 0


class HarnessInterrupted(Exception):
    pass


def handle_signal(signum: int, _frame: object) -> None:
    global RECEIVED_SIGNAL
    RECEIVED_SIGNAL = signum
    raise HarnessInterrupted()


def kill_group(process: subprocess.Popen[str]) -> tuple[str, str]:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return process.communicate()


def invoke(
    arguments: list[str],
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    global ACTIVE_PROCESS
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    if extra_environment:
        environment.update(extra_environment)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED_SIGNALS)

    def restore_child_mask() -> None:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    try:
        try:
            process = subprocess.Popen(
                arguments,
                cwd=REPO_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
                start_new_session=True,
                preexec_fn=restore_child_mask,
            )
            ACTIVE_PROCESS = process
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            stdout, stderr = kill_group(process)
            return subprocess.CompletedProcess(arguments, 125, stdout, stderr)
        except HarnessInterrupted:
            stdout, stderr = kill_group(process)
            return subprocess.CompletedProcess(
                arguments,
                128 + RECEIVED_SIGNAL,
                stdout,
                stderr,
            )
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return subprocess.CompletedProcess(
            arguments,
            process.returncode,
            stdout,
            stderr,
        )
    except HarnessInterrupted:
        stdout, stderr = kill_group(process)
        return subprocess.CompletedProcess(
            arguments,
            128 + RECEIVED_SIGNAL,
            stdout,
            stderr,
        )
    except BaseException:
        if "process" in locals():
            kill_group(process)
        raise
    finally:
        ACTIVE_PROCESS = None


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    required = (
        "IOServiceAddMatchingNotification",
        "kIOFirstMatchNotification",
        "kIOTerminatedNotification",
        "IOUSBHostDevice",
        "IORegistryEntryCreateCFProperty",
        "lifecycleObservationPassed",
        "observationScope",
    )
    for token in required:
        assert token in source
    for forbidden in (
        "IOServiceOpen(",
        "DeviceRequest",
        "subprocess",
        "/usr/bin/ssh",
        "mobile@",
    ):
        assert forbidden not in source

    with tempfile.TemporaryDirectory(prefix="mac2jb-host-usb-monitor-") as temporary:
        binary = Path(temporary) / "u1-usb-event-monitor"
        module_cache = Path(temporary) / "module-cache"
        module_cache.mkdir()
        build = invoke([
            str(SWIFTC),
            "--sdk", "macosx",
            "swiftc",
            str(SOURCE),
            "-framework", "IOKit",
            "-framework", "CryptoKit",
            "-o", str(binary),
        ], {
            "CLANG_MODULE_CACHE_PATH": str(module_cache),
            "SWIFT_MODULECACHE_PATH": str(module_cache),
            "TMPDIR": temporary,
        })
        assert build.returncode == 0, (build.stdout, build.stderr)
        self_test = invoke([str(binary), "--self-test"])
        assert self_test.returncode == 0, (self_test.stdout, self_test.stderr)
        assert self_test.stdout == "PASS host USB event monitor self-test (17 scenarios)\n"
        assert self_test.stderr == ""

        for arguments in ([], ["05ac"], ["05ac", "12ab", "0"], ["zzzz", "12ab", "1"]):
            result = invoke([str(binary), *arguments])
            assert result.returncode == 64
            assert result.stdout == ""
            assert result.stderr.startswith("Usage: u1-usb-event-monitor ")

        before = set(Path(temporary).iterdir())
        self_test = invoke([str(binary), "--self-test"])
        after = set(Path(temporary).iterdir())
        assert self_test.returncode == 0
        assert before == after

    print("PASS host USB event monitor tests (3 groups, 22 scenarios)")


if __name__ == "__main__":
    for handled_signal in HANDLED_SIGNALS:
        signal.signal(handled_signal, handle_signal)
    main()
