#!/usr/bin/env python3
"""Bind one reviewed U1 capture-host batch to a host USB lifecycle window.

What this code does:
1. Before any network-capable child starts, verifies the exact reviewed host
   monitor source and authorization runner, refuses existing local evidence,
   and compiles the monitor in a private temporary directory with a bounded
   process group and private module cache.
2. Starts the passive monitor for one fixed Apple vendor/product pair, validates
   its exact `ready` record, and only then starts the reviewed authorization
   runner for `capture-host`, one orientation, and one observed power label.
3. Requires the runner to finish inside the host observation window, validates
   its exact receipt and published batch-manifest digest, then requires an
   event-free, complete lifecycle summary from the monitor.
4. Publishes the private monitor NDJSON plus a binding manifest beneath ignored
   build storage with a Darwin no-replace rename. It never changes the batch
   directory and never deletes failure evidence published by the batch runner.

The wrapper itself is Mac-local. Its only iPad access is the already-reviewed
read-only runner it invokes after monitor readiness. Do not execute this file
against the iPad until its exact bytes and invocation receive adversarial PASS
under the owner's no-harm, no-SSH/USB-breakage, and no-harmful-permanent-change
conditions. Installation and successful installed-toolbox attestation remain
separate prerequisites enforced by the nested runner.

Security boundary: the local macOS account is assumed honest, with no
concurrent same-UID process replacing private temporary compiler output. The
wrapper executes privately copied, digest-pinned runner source; this boundary
remains necessary for the compiled monitor because macOS provides no portable
Python ``fexecve`` path for binding its pathname launch to an already-open FD.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
REPO_ROOT = (SCRIPT_DIRECTORY.parents[4]
             if SCRIPT_DIRECTORY.parent.parent.name == "ipad-port"
             else SCRIPT_DIRECTORY.parent.parent)
BUILD_DIRECTORY = REPO_ROOT / "build/ipad-hardware"
MONITOR_SOURCE = SCRIPT_DIRECTORY / "host/u1-usb-event-monitor.swift"
BATCH_RUNNER = SCRIPT_DIRECTORY / "run-installed-toolbox-authorization-batch.py"
XCRUN = Path("/usr/bin/xcrun")
PYTHON = Path("/usr/bin/python3")
EXPECTED_MONITOR_SOURCE_SHA256 = "da900b13b41435fc13f7e596f1ed76c88079ad04edd8733440d2a75406079199"
EXPECTED_BATCH_RUNNER_SHA256 = "581dc411f2651fd7c3349304bdcfc2cb8337d96395a0e220d3ea8043d583659b"
EXPECTED_SCOPE = "IOUSBHostDevice lifecycle notifications plus final registry presence"
MONITOR_DURATION = 90
BATCH_TIMEOUT = 75.0
READY_TIMEOUT = 10.0
COMPILE_TIMEOUT = 30.0
MAX_SOURCE_SIZE = 2 * 1024 * 1024
MAX_BINARY_SIZE = 32 * 1024 * 1024
MAX_BUILD_LOG_SIZE = 1024 * 1024
COMPILER_FILE_LIMIT = 64 * 1024 * 1024
MAX_MONITOR_OUTPUT_SIZE = 128 * 1024
MAX_RUNNER_RECEIPT_SIZE = 4096
MAX_BATCH_MANIFEST_SIZE = 2 * 1024 * 1024
NESTED_RUNNER_FILE_LIMIT = 4 * 1024 * 1024
RENAME_EXCL = 0x00000004
POWERS = {
    "operator-observed-vbus-charging",
    "operator-observed-vbus-not-charging",
    "operator-observed-no-vbus",
    "operator-not-observed",
}
HEX64 = re.compile(r"[0-9a-f]{64}")
RUNNER_PASS = re.compile(
    rb"PASS authorization batch ([0-9a-f]{64}) "
    rb"(probe-capture-capture-host-[ab]-[a-z-]+)\n"
)
# Execute the already-pinned private runner bytes with their staged pathname as
# ``__file__`` so the internal attestation helper re-executes the same reviewed
# bytes. A separate fixed environment contract points only to the real
# repository directory whose dependencies the runner independently pins before
# opening SSH.
PINNED_RUNNER_BOOTSTRAP = """import hashlib
import os
import stat
import sys

source_path, expected_digest, *runner_arguments = sys.argv[1:]
descriptor = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    status = os.fstat(descriptor)
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or not 0 < status.st_size <= 2097152:
        raise SystemExit(65)
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > 2097152:
            raise SystemExit(65)
        chunks.append(chunk)
finally:
    os.close(descriptor)
source = b\"\".join(chunks)
if len(source) != status.st_size or hashlib.sha256(source).hexdigest() != expected_digest:
    raise SystemExit(65)
sys.argv = [source_path, *runner_arguments]
namespace = {
    \"__name__\": \"__main__\",
    \"__file__\": source_path,
    \"__package__\": None,
    \"__spec__\": None,
    \"__cached__\": None,
}
exec(compile(source, source_path, \"exec\"), namespace, namespace)
"""
HANDLED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
ACTIVE_PROCESS: subprocess.Popen[bytes] | None = None
MONITOR_PROCESS: subprocess.Popen[bytes] | None = None
RECEIVED_SIGNAL = 0


class Rejection(Exception):
    pass


class Interrupted(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejection(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise Rejection("duplicate JSON key")
        value[key] = item
    return value


def read_fd(descriptor: int, maximum: int) -> bytes:
    status = os.fstat(descriptor)
    require(
        stat.S_ISREG(status.st_mode)
        and status.st_nlink == 1
        and 0 < status.st_size <= maximum,
        "unsafe local file",
    )
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        total += len(chunk)
        require(total <= maximum, "local file exceeded cap")
        chunks.append(chunk)
    data = b"".join(chunks)
    require(len(data) == status.st_size, "local file extent changed")
    return data


def read_regular(path: Path, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        return read_fd(descriptor, maximum)
    finally:
        os.close(descriptor)


def copy_pinned(source: Path, destination: Path, expected: str, maximum: int) -> bytes:
    data = read_regular(source, maximum)
    require(sha256(data) == expected, "pinned input digest")
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o400,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            require(written > 0, "short local write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require(sha256(read_regular(destination, maximum)) == expected, "staged input digest")
    return data


def safe_host_tool(path: Path) -> None:
    status = os.lstat(path)
    require(
        stat.S_ISREG(status.st_mode)
        and status.st_uid == 0
        and status.st_gid == 0
        and stat.S_IMODE(status.st_mode) == 0o755
        and not (status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)),
        "unsafe host tool",
    )


def kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait()
    except ChildProcessError:
        pass


def terminate_process_group(process: subprocess.Popen[bytes], grace: float = 65.0) -> None:
    # The reviewed nested runner traps TERM and kills/reaps its separate-session
    # child before returning. Its longest child deadline is 60 seconds. Waiting
    # longer than that bound avoids orphaning an SSH or validator child before a
    # last-resort KILL of the runner's own process group.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        kill_process_group(process)
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def handle_signal(signum: int, _frame: object) -> None:
    global RECEIVED_SIGNAL
    RECEIVED_SIGNAL = signum
    raise Interrupted()


def child_setup(previous_mask: set[signal.Signals], output_limit: int) -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit, output_limit))
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def run_bounded(
    arguments: list[str],
    output: Path,
    *,
    timeout: float,
    output_limit: int,
    environment: dict[str, str],
    graceful_termination: bool = False,
    merge_stderr: bool = True,
    file_limit: int | None = None,
) -> int:
    global ACTIVE_PROCESS
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED_SIGNALS)
    try:
        try:
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
                env=environment,
                start_new_session=True,
                preexec_fn=lambda: child_setup(
                    previous_mask,
                    file_limit if file_limit is not None else output_limit,
                ),
            )
            ACTIVE_PROCESS = process
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        require(process.stdout is not None, "child output pipe")
        pipe_descriptor = process.stdout.fileno()
        os.set_blocking(pipe_descriptor, False)
        deadline = time.monotonic() + timeout
        total = 0
        pipe_closed = False
        while not pipe_closed or process.poll() is None:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                if graceful_termination:
                    terminate_process_group(process)
                else:
                    kill_process_group(process)
                return 125
            readable, _, _ = select.select(
                [] if pipe_closed else [pipe_descriptor],
                [],
                [],
                min(0.1, remaining_time),
            )
            if readable:
                try:
                    chunk = os.read(pipe_descriptor, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    pipe_closed = True
                    continue
                total += len(chunk)
                if total > output_limit:
                    if graceful_termination:
                        terminate_process_group(process)
                    else:
                        kill_process_group(process)
                    return 126
                offset = 0
                while offset < len(chunk):
                    written = os.write(descriptor, chunk[offset:])
                    require(written > 0, "short child-output write")
                    offset += written
        process.wait()
        status = process.returncode
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return status if status is not None and status >= 0 else 125
    except BaseException:
        if "process" in locals():
            if graceful_termination:
                terminate_process_group(process)
            else:
                kill_process_group(process)
        raise
    finally:
        ACTIVE_PROCESS = None
        if "process" in locals() and process.stdout is not None:
            process.stdout.close()
        os.close(descriptor)


def start_monitor(binary: Path, output: Path) -> tuple[subprocess.Popen[bytes], int]:
    global MONITOR_PROCESS
    descriptor = os.open(
        output,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED_SIGNALS)
    try:
        try:
            process = subprocess.Popen(
                [str(binary), "05ac", "12ab", str(MONITOR_DURATION)],
                stdin=subprocess.DEVNULL,
                stdout=descriptor,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                start_new_session=True,
                preexec_fn=lambda: child_setup(previous_mask, MAX_MONITOR_OUTPUT_SIZE),
            )
            MONITOR_PROCESS = process
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    except BaseException:
        os.close(descriptor)
        raise
    return process, descriptor


def wait_ready(process: subprocess.Popen[bytes], descriptor: int) -> bytes:
    deadline = time.monotonic() + READY_TIMEOUT
    while time.monotonic() < deadline:
        data = os.pread(descriptor, 16385, 0)
        if b"\n" in data:
            line, remainder = data.split(b"\n", 1)
            require(not remainder, "monitor emitted before batch start")
            require(len(line) <= 16384, "monitor ready line")
            return line + b"\n"
        require(len(data) <= 16384, "monitor ready cap")
        if process.poll() is not None:
            raise Rejection("monitor exited before ready")
        time.sleep(0.02)
    raise Rejection("monitor ready timeout")


def decode_object(data: bytes) -> dict[str, object]:
    require(data.endswith(b"\n") and not data.endswith(b"\n\n"), "JSON line framing")
    try:
        value = json.loads(
            data[:-1].decode("ascii"),
            object_pairs_hook=reject_duplicate_pairs,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejection("invalid JSON line") from error
    require(isinstance(value, dict), "JSON object")
    return value


def validate_ready(data: bytes) -> dict[str, object]:
    value = decode_object(data)
    require(
        set(value)
        == {
            "observationScope",
            "schemaVersion",
            "startedAt",
            "target",
            "type",
            "windowSeconds",
        }
        and value["schemaVersion"] == 1
        and value["type"] == "ready"
        and value["observationScope"] == EXPECTED_SCOPE
        and value["windowSeconds"] == MONITOR_DURATION,
        "monitor ready record",
    )
    target = value["target"]
    require(
        isinstance(target, dict)
        and set(target) == {"locationSha256", "productID", "vendorID"}
        and target["vendorID"] == "0x05ac"
        and target["productID"] == "0x12ab"
        and isinstance(target["locationSha256"], str)
        and HEX64.fullmatch(target["locationSha256"]) is not None,
        "monitor target",
    )
    require(isinstance(value["startedAt"], str), "monitor start time")
    return value


def validate_monitor_output(data: bytes, ready: dict[str, object]) -> dict[str, object]:
    require(0 < len(data) <= MAX_MONITOR_OUTPUT_SIZE and data.endswith(b"\n"), "monitor output")
    lines = data.splitlines(keepends=True)
    require(len(lines) == 2, "unexpected lifecycle event record")
    require(decode_object(lines[0]) == ready, "monitor ready changed")
    summary = decode_object(lines[1])
    require(
        set(summary)
        == {
            "eventCount",
            "eventsTruncated",
            "finishedAt",
            "lifecycleObservationPassed",
            "observationScope",
            "schemaVersion",
            "type",
            "windowCompleted",
        }
        and summary["schemaVersion"] == 1
        and summary["type"] == "summary"
        and summary["observationScope"] == EXPECTED_SCOPE
        and summary["eventCount"] == 0
        and summary["eventsTruncated"] is False
        and summary["windowCompleted"] is True
        and summary["lifecycleObservationPassed"] is True
        and isinstance(summary["finishedAt"], str),
        "monitor lifecycle summary",
    )
    return summary


def write_exclusive(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            require(written > 0, "short evidence write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def rename_exclusive(parent: Path, source: str, destination: str) -> None:
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        library = ctypes.CDLL(None, use_errno=True)
        function = library.renameatx_np
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        if function(
            descriptor,
            os.fsencode(source),
            descriptor,
            os.fsencode(destination),
            RENAME_EXCL,
        ) != 0:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(
    output: Path,
    staging: Path,
    monitor_data: bytes,
    manifest: dict[str, object],
    *,
    manifest_filename: str = "binding-manifest.json",
) -> str:
    os.mkdir(staging, 0o700)
    status = os.lstat(staging)
    published = False
    try:
        write_exclusive(staging / "monitor.ndjson", monitor_data)
        manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("ascii")
        write_exclusive(staging / manifest_filename, manifest_data)
        fsync_directory(staging)
        rename_exclusive(output.parent, staging.name, output.name)
        published = True
        return sha256(manifest_data)
    finally:
        if not published:
            try:
                current = os.lstat(staging)
                if current.st_dev == status.st_dev and current.st_ino == status.st_ino:
                    shutil.rmtree(staging)
            except FileNotFoundError:
                pass


def run(arguments: list[str]) -> int:
    global MONITOR_PROCESS
    if len(arguments) != 2:
        print(
            "Usage: run-capture-host-authorization-window.py ORIENTATION POWER_STATE",
            file=sys.stderr,
        )
        return 64
    orientation, power = arguments
    if orientation not in {"a", "b"} or power not in POWERS:
        return 64

    batch_name = f"probe-capture-capture-host-{orientation}-{power}"
    output_name = f"host-lifecycle-capture-host-{orientation}-{power}"
    batch_directory = BUILD_DIRECTORY / batch_name
    output = BUILD_DIRECTORY / output_name
    staging = BUILD_DIRECTORY / f".{output_name}.staging"
    rejected_name = f"rejected-{output_name}"
    rejected_output = BUILD_DIRECTORY / rejected_name
    rejected_staging = BUILD_DIRECTORY / f".{rejected_name}.staging"
    try:
        build_status = os.lstat(BUILD_DIRECTORY)
        require(stat.S_ISDIR(build_status.st_mode), "build directory")
        for path in (
            batch_directory,
            output,
            staging,
            rejected_output,
            rejected_staging,
        ):
            require(not path.exists() and not path.is_symlink(), "existing capture path")
        safe_host_tool(XCRUN)
        safe_host_tool(PYTHON)

        with tempfile.TemporaryDirectory(prefix="mac2jb-u1-host-window-") as temporary:
            root = Path(temporary)
            source = root / "monitor.swift"
            staged_runner = root / "batch-runner.py"
            binary = root / "monitor"
            build_log = root / "build.log"
            monitor_output = root / "monitor.ndjson"
            runner_receipt = root / "runner.receipt"
            module_cache = root / "module-cache"
            os.mkdir(module_cache, 0o700)
            copy_pinned(
                MONITOR_SOURCE,
                source,
                EXPECTED_MONITOR_SOURCE_SHA256,
                MAX_SOURCE_SIZE,
            )
            copy_pinned(
                BATCH_RUNNER,
                staged_runner,
                EXPECTED_BATCH_RUNNER_SHA256,
                MAX_SOURCE_SIZE,
            )
            compile_status = run_bounded(
                [
                    str(XCRUN),
                    "--sdk",
                    "macosx",
                    "swiftc",
                    str(source),
                    "-framework",
                    "IOKit",
                    "-framework",
                    "CryptoKit",
                    "-o",
                    str(binary),
                ],
                build_log,
                timeout=COMPILE_TIMEOUT,
                output_limit=MAX_BUILD_LOG_SIZE,
                file_limit=COMPILER_FILE_LIMIT,
                environment={
                    "CLANG_MODULE_CACHE_PATH": str(module_cache),
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                    "SWIFT_MODULECACHE_PATH": str(module_cache),
                    "TMPDIR": temporary,
                },
            )
            require(compile_status == 0, "monitor compilation")
            binary_data = read_regular(binary, MAX_BINARY_SIZE)
            binary_status = os.lstat(binary)
            require(
                stat.S_ISREG(binary_status.st_mode)
                and binary_status.st_nlink == 1
                and binary_status.st_uid == os.getuid()
                and bool(binary_status.st_mode & stat.S_IXUSR),
                "monitor binary metadata",
            )

            monitor_started = time.monotonic_ns()
            monitor, monitor_descriptor = start_monitor(binary, monitor_output)
            try:
                ready_data = wait_ready(monitor, monitor_descriptor)
                ready = validate_ready(ready_data)
                ready_observed = time.monotonic_ns()
                batch_started = time.monotonic_ns()
                runner_status = run_bounded(
                    [
                        str(PYTHON),
                        "-I",
                        "-S",
                        "-c",
                        PINNED_RUNNER_BOOTSTRAP,
                        str(staged_runner),
                        EXPECTED_BATCH_RUNNER_SHA256,
                        "capture-host",
                        orientation,
                        power,
                    ],
                    runner_receipt,
                    timeout=BATCH_TIMEOUT,
                    # The nested reviewed attestation helper needs a 4 MiB
                    # scratch-file ceiling while stripping signatures. Preserve
                    # that inherited hard limit; the receipt itself is limited
                    # to 4 KiB and exact-matched below.
                    output_limit=MAX_RUNNER_RECEIPT_SIZE,
                    file_limit=NESTED_RUNNER_FILE_LIMIT,
                    environment={
                        "LC_ALL": "C",
                        "MAC2JB_SCRIPT_DIRECTORY": str(SCRIPT_DIRECTORY),
                        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                        "TMPDIR": temporary,
                    },
                    graceful_termination=True,
                    merge_stderr=False,
                )
                batch_finished = time.monotonic_ns()
                require(runner_status == 0, "authorization batch")
                require(monitor.poll() is None, "monitor ended before batch completion")
                require(
                    os.pread(monitor_descriptor, MAX_MONITOR_OUTPUT_SIZE + 1, 0)
                    == ready_data,
                    "monitor emitted before batch completion",
                )
                require(
                    sha256(read_regular(BATCH_RUNNER, MAX_SOURCE_SIZE))
                    == EXPECTED_BATCH_RUNNER_SHA256,
                    "batch runner changed during execution",
                )
                remaining = max(
                    0.1,
                    (monitor_started + (MONITOR_DURATION + 10) * 1_000_000_000
                     - time.monotonic_ns()) / 1_000_000_000,
                )
                try:
                    monitor.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    kill_process_group(monitor)
                    raise Rejection("monitor completion timeout")
                monitor_finished = time.monotonic_ns()
                status = monitor.returncode
                try:
                    os.killpg(monitor.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.fsync(monitor_descriptor)
                os.lseek(monitor_descriptor, 0, os.SEEK_SET)
                monitor_data = read_fd(monitor_descriptor, MAX_MONITOR_OUTPUT_SIZE)
                require(
                    monitor_finished - monitor_started
                    >= MONITOR_DURATION * 1_000_000_000,
                    "monitor duration shorter than declared window",
                )
            except BaseException:
                if monitor.poll() is None:
                    kill_process_group(monitor)
                raise
            finally:
                MONITOR_PROCESS = None
                os.close(monitor_descriptor)

            receipt_data = read_regular(runner_receipt, MAX_RUNNER_RECEIPT_SIZE)
            match = RUNNER_PASS.fullmatch(receipt_data)
            require(match is not None, "runner receipt")
            batch_manifest_sha = match.group(1).decode()
            require(match.group(2).decode() == batch_name, "runner output name")
            batch_status = os.lstat(batch_directory)
            require(stat.S_ISDIR(batch_status.st_mode), "batch output directory")
            batch_manifest_data = read_regular(
                batch_directory / "batch-manifest.json",
                MAX_BATCH_MANIFEST_SIZE,
            )
            require(sha256(batch_manifest_data) == batch_manifest_sha, "batch manifest receipt")
            if status != 0:
                if status == 65:
                    rejection = {
                        "accepted": False,
                        "batchDirectory": batch_name,
                        "batchManifestSha256": batch_manifest_sha,
                        "batchRunnerSha256": EXPECTED_BATCH_RUNNER_SHA256,
                        "monitorExitStatus": status,
                        "monitorOutputSha256": sha256(monitor_data),
                        "monitorSourceSha256": EXPECTED_MONITOR_SOURCE_SHA256,
                        "observationScope": EXPECTED_SCOPE,
                        "reason": "monitor-lifecycle-rejected",
                        "schemaVersion": 1,
                    }
                    publish(
                        rejected_output,
                        rejected_staging,
                        monitor_data,
                        rejection,
                        manifest_filename="rejection-manifest.json",
                    )
                raise Rejection("monitor lifecycle failure")
            summary = validate_monitor_output(monitor_data, ready)
            require(
                ready_observed <= batch_started <= batch_finished <= monitor_finished,
                "observation interval binding",
            )
            binding = {
                "batchDirectory": batch_name,
                "batchDurationMilliseconds": (batch_finished - batch_started) // 1_000_000,
                "batchManifestSha256": batch_manifest_sha,
                "batchRunnerSha256": EXPECTED_BATCH_RUNNER_SHA256,
                "batchStartedAfterReadyMilliseconds": (batch_started - ready_observed) // 1_000_000,
                "monitorBinarySha256": sha256(binary_data),
                "monitorFinishedAfterBatchMilliseconds": (monitor_finished - batch_finished) // 1_000_000,
                "monitorOutputSha256": sha256(monitor_data),
                "monitorSourceSha256": EXPECTED_MONITOR_SOURCE_SHA256,
                "observationScope": EXPECTED_SCOPE,
                "orientation": orientation,
                "peer": "capture-host",
                "powerState": power,
                "schemaVersion": 1,
                "summary": summary,
            }
            published_sha = publish(output, staging, monitor_data, binding)
    except Interrupted:
        if ACTIVE_PROCESS is not None:
            terminate_process_group(ACTIVE_PROCESS)
        if MONITOR_PROCESS is not None:
            kill_process_group(MONITOR_PROCESS)
        return 128 + RECEIVED_SIGNAL
    except (OSError, Rejection, ValueError, subprocess.SubprocessError):
        if MONITOR_PROCESS is not None:
            kill_process_group(MONITOR_PROCESS)
            MONITOR_PROCESS = None
        print("Capture-host authorization window rejected; no binding was accepted.", file=sys.stderr)
        return 65
    print(f"PASS bound host lifecycle {published_sha} {output_name}")
    return 0


if __name__ == "__main__":
    for handled in HANDLED_SIGNALS:
        signal.signal(handled, handle_signal)
    raise SystemExit(run(sys.argv[1:]))
