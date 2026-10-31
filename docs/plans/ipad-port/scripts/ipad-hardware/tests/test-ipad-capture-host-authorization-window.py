#!/usr/bin/env python3
"""Hermetically test capture-host lifecycle/batch orchestration.

The harness copies the wrapper into a temporary fake repository and replaces
only its pinned source hashes, compiler path, and short test deadlines. Fake
compiler, monitor, and batch-runner processes never open IOKit, SSH, or network
sockets and never contact the iPad.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time


REPO_ROOT = Path(__file__).resolve().parents[6]
SOURCE = REPO_ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/run-capture-host-authorization-window.py"
POWER = "operator-not-observed"
OUTPUT_NAME = f"host-lifecycle-capture-host-a-{POWER}"
REJECTED_NAME = f"rejected-{OUTPUT_NAME}"
BATCH_NAME = f"probe-capture-capture-host-a-{POWER}"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def fixture(base: Path, scenario: str = "success") -> dict[str, Path]:
    root = Path(tempfile.mkdtemp(dir=base))
    script_directory = root / "docs/plans/ipad-port/scripts/ipad-hardware"
    host_directory = script_directory / "host"
    build_directory = root / "build/ipad-hardware"
    host_directory.mkdir(parents=True)
    build_directory.mkdir(parents=True)
    scenario_path = root / "scenario"
    scenario_path.write_text(scenario, encoding="ascii")
    contact_path = root / "contact.log"

    monitor_source = host_directory / "u1-usb-event-monitor.swift"
    monitor_source.write_text("// fake reviewed monitor source\n", encoding="ascii")

    runner = script_directory / "run-installed-toolbox-authorization-batch.py"
    runner_source = f'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import resource
import runpy
import signal
import stat
import subprocess
import sys
import time
root = Path({str(root)!r})
scenario = (root / "scenario").read_text().strip()
resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))
if sys.argv[1:2] == ["--internal-attestation"]:
    if Path(os.environ.get("MAC2JB_SCRIPT_DIRECTORY", "")).resolve() != (root / "docs/plans/ipad-port/scripts/ipad-hardware").resolve():
        raise SystemExit(65)
    raise SystemExit(0)
saved_arguments = sys.argv
sys.argv = [str(Path(__file__).resolve()), "--internal-attestation"]
try:
    try:
        runpy.run_path(str(Path(__file__).resolve()), run_name="__main__")
    except SystemExit as internal_exit:
        if internal_exit.code != 0:
            raise SystemExit(65)
finally:
    sys.argv = saved_arguments
with (root / "contact.log").open("a") as stream:
    stream.write("runner\\n")
if scenario == "runner-path-unavailable":
    original_runner = root / "docs/plans/ipad-port/scripts/ipad-hardware/run-installed-toolbox-authorization-batch.py"
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if stat.S_IMODE(original_runner.stat().st_mode) == 0o755:
            break
        time.sleep(0.01)
    else:
        raise SystemExit(65)
if scenario == "runner-fail":
    raise SystemExit(65)
if scenario == "runner-oversize-receipt":
    sys.stdout.buffer.write(b"x" * 8192)
    sys.stdout.buffer.flush()
    raise SystemExit(0)
if scenario == "runner-hang":
    time.sleep(30)
if scenario == "runner-grandchild":
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    (root / "grandchild.pid").write_text(str(child.pid))
    def stop(_signum, _frame):
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, stop)
    time.sleep(30)
if scenario == "summary-before-batch-end":
    time.sleep(0.3)
peer, orientation, power = sys.argv[1:]
name = f"probe-capture-{{peer}}-{{orientation}}-{{power}}"
output = root / "build/ipad-hardware" / name
output.mkdir()
data = (json.dumps({{"schemaVersion": 1}}, sort_keys=True) + "\\n").encode()
(output / "batch-manifest.json").write_bytes(data)
if scenario == "publish-race":
    competitor = root / "build/ipad-hardware" / f"host-lifecycle-{{peer}}-{{orientation}}-{{power}}"
    competitor.mkdir()
    (competitor / "competitor").write_text("preserve me")
value = "0" * 64 if scenario == "manifest-mismatch" else hashlib.sha256(data).hexdigest()
print(f"PASS authorization batch {{value}} {{name}}")
'''
    write_executable(runner, runner_source)

    fake_xcrun = root / "fake-xcrun"
    monitor_program = f'''#!{sys.executable}
import json
from pathlib import Path
import sys
import time
root = Path({str(root)!r})
scenario = (root / "scenario").read_text().strip()
with (root / "contact.log").open("a") as stream:
    stream.write("monitor\\n")
duration = int(sys.argv[3])
if scenario == "monitor-early":
    raise SystemExit(65)
ready = {{
    "observationScope": "IOUSBHostDevice lifecycle notifications plus final registry presence",
    "schemaVersion": 1,
    "startedAt": "2026-10-29T20:00:00Z",
    "target": {{"locationSha256": "a" * 64, "productID": "0x12ab", "vendorID": "0x05ac"}},
    "type": "ready",
    "windowSeconds": duration,
}}
print(json.dumps(ready, sort_keys=True), flush=True)
if scenario == "runner-path-unavailable":
    runner = root / "docs/plans/ipad-port/scripts/ipad-hardware/run-installed-toolbox-authorization-batch.py"
    runner.chmod(0)
    deadline = time.monotonic() + 2
    try:
        while time.monotonic() < deadline:
            if (root / "contact.log").read_text().splitlines().count("runner") == 1:
                break
            time.sleep(0.01)
    finally:
        runner.chmod(0o755)
if scenario == "summary-before-batch-end":
    time.sleep(0.1)
elif scenario == "short-window":
    time.sleep(0.2)
else:
    time.sleep(duration + 0.05)
if scenario == "monitor-event":
    print(json.dumps({{
        "elapsedNanoseconds": 1,
        "kind": "terminated",
        "productID": "0x12ab",
        "schemaVersion": 1,
        "type": "event",
        "vendorID": "0x05ac",
    }}, sort_keys=True))
summary = {{
    "eventCount": 1 if scenario == "monitor-event" else 0,
    "eventsTruncated": False,
    "finishedAt": "2026-10-29T20:00:01Z",
    "lifecycleObservationPassed": scenario not in {{"monitor-event", "invalid-summary"}},
    "observationScope": "IOUSBHostDevice lifecycle notifications plus final registry presence",
    "schemaVersion": 1,
    "type": "summary",
    "windowCompleted": True,
}}
print(json.dumps(summary, sort_keys=True), flush=True)
raise SystemExit(65 if scenario == "monitor-event" else 0)
'''
    xcrun_source = f'''#!{sys.executable}
import os
from pathlib import Path
import resource
import sys
root = Path({str(root)!r})
scenario = (root / "scenario").read_text().strip()
with (root / "contact.log").open("a") as stream:
    stream.write("compiler\\n")
if scenario == "compiler-fail":
    raise SystemExit(65)
if resource.getrlimit(resource.RLIMIT_FSIZE)[1] < 64 * 1024 * 1024:
    raise SystemExit(65)
cache_probe = Path(os.environ["CLANG_MODULE_CACHE_PATH"]) / "large-fixture.pcm"
cache_probe.write_bytes(b"x" * (2 * 1024 * 1024))
if scenario == "compiler-oversize-log":
    sys.stdout.buffer.write(b"x" * (1024 * 1024 + 1))
    sys.stdout.buffer.flush()
    raise SystemExit(0)
output = Path(sys.argv[sys.argv.index("-o") + 1])
output.write_text({monitor_program!r})
output.chmod(0o755)
'''
    write_executable(fake_xcrun, xcrun_source)

    wrapper = script_directory / SOURCE.name
    source = SOURCE.read_text(encoding="utf-8")
    replacements = {
        'XCRUN = Path("/usr/bin/xcrun")': f"XCRUN = Path({str(fake_xcrun)!r})",
        'PYTHON = Path("/usr/bin/python3")': f"PYTHON = Path({sys.executable!r})",
        'EXPECTED_MONITOR_SOURCE_SHA256 = "da900b13b41435fc13f7e596f1ed76c88079ad04edd8733440d2a75406079199"':
            f'EXPECTED_MONITOR_SOURCE_SHA256 = "{digest(monitor_source.read_bytes())}"',
        'EXPECTED_BATCH_RUNNER_SHA256 = "581dc411f2651fd7c3349304bdcfc2cb8337d96395a0e220d3ea8043d583659b"':
            f'EXPECTED_BATCH_RUNNER_SHA256 = "{digest(runner.read_bytes())}"',
        "MONITOR_DURATION = 90": "MONITOR_DURATION = 1",
        "BATCH_TIMEOUT = 75.0": "BATCH_TIMEOUT = 0.5",
        "READY_TIMEOUT = 10.0": "READY_TIMEOUT = 1.0",
        "COMPILE_TIMEOUT = 30.0": "COMPILE_TIMEOUT = 2.0",
        "safe_host_tool(XCRUN)": 'require(XCRUN.is_file(), "test compiler")',
        "safe_host_tool(PYTHON)": 'require(PYTHON.is_file(), "test python")',
    }
    for original, replacement in replacements.items():
        assert original in source
        source = source.replace(original, replacement, 1)
    wrapper.write_text(source, encoding="utf-8")
    wrapper.chmod(0o755)
    return {
        "batch": build_directory / BATCH_NAME,
        "build": build_directory,
        "contact": contact_path,
        "output": build_directory / OUTPUT_NAME,
        "rejected": build_directory / REJECTED_NAME,
        "root": root,
        "runner": runner,
        "scenario": scenario_path,
        "wrapper": wrapper,
    }


def invoke(paths: dict[str, Path], arguments: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-I", "-S", str(paths["wrapper"])]
    command.extend(arguments if arguments is not None else ["a", POWER])
    process = subprocess.Popen(
        command,
        cwd=paths["root"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        start_new_session=True,
    )
    try:
        try:
            stdout, stderr = process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            return subprocess.CompletedProcess(command, 125, stdout, stderr)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise


def invoke_with_signal(
    paths: dict[str, Path],
    signum: int,
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-I", "-S", str(paths["wrapper"]), "a", POWER]
    process = subprocess.Popen(
        command,
        cwd=paths["root"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not (paths["root"] / "grandchild.pid").exists():
            time.sleep(0.01)
        assert (paths["root"] / "grandchild.pid").exists()
        os.kill(process.pid, signum)
        stdout, stderr = process.communicate(timeout=8)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def assert_rejected(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 65, (result.returncode, result.stdout, result.stderr)
    assert result.stdout == ""
    assert result.stderr == "Capture-host authorization window rejected; no binding was accepted.\n"


def test_success(base: Path) -> None:
    paths = fixture(base)
    result = invoke(paths)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert re.fullmatch(
        rf"PASS bound host lifecycle [0-9a-f]{{64}} {re.escape(OUTPUT_NAME)}\n",
        result.stdout,
    )
    assert result.stderr == ""
    assert paths["output"].is_dir()
    assert {item.name for item in paths["output"].iterdir()} == {
        "binding-manifest.json",
        "monitor.ndjson",
    }
    manifest = json.loads((paths["output"] / "binding-manifest.json").read_text())
    assert manifest["batchDirectory"] == BATCH_NAME
    assert manifest["batchManifestSha256"] == digest(
        (paths["batch"] / "batch-manifest.json").read_bytes()
    )
    assert manifest["summary"]["lifecycleObservationPassed"] is True
    assert paths["contact"].read_text().splitlines() == ["compiler", "monitor", "runner"]

    paths = fixture(base, "runner-path-unavailable")
    result = invoke(paths)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert paths["output"].is_dir()
    assert paths["contact"].read_text().splitlines() == ["compiler", "monitor", "runner"]


def test_preflight_stops_before_children(base: Path) -> None:
    paths = fixture(base)
    paths["runner"].write_text("drift\n")
    assert_rejected(invoke(paths))
    assert not paths["contact"].exists()

    paths = fixture(base)
    paths["output"].mkdir()
    assert_rejected(invoke(paths))
    assert not paths["contact"].exists()


def test_child_failures(base: Path) -> None:
    for scenario in (
        "runner-fail",
        "runner-oversize-receipt",
        "runner-hang",
        "runner-grandchild",
        "manifest-mismatch",
        "invalid-summary",
        "monitor-early",
        "compiler-fail",
        "compiler-oversize-log",
        "short-window",
        "summary-before-batch-end",
    ):
        paths = fixture(base, scenario)
        assert_rejected(invoke(paths))
        assert not paths["output"].exists()

    paths = fixture(base, "monitor-event")
    assert_rejected(invoke(paths))
    assert not paths["output"].exists()
    assert paths["rejected"].is_dir()
    assert {item.name for item in paths["rejected"].iterdir()} == {
        "monitor.ndjson",
        "rejection-manifest.json",
    }
    rejection = json.loads((paths["rejected"] / "rejection-manifest.json").read_text())
    assert rejection["accepted"] is False
    assert rejection["monitorExitStatus"] == 65
    assert rejection["reason"] == "monitor-lifecycle-rejected"

    paths = fixture(base, "publish-race")
    assert_rejected(invoke(paths))
    assert (paths["output"] / "competitor").read_text() == "preserve me"


def assert_pid_gone(pid: int) -> None:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    raise AssertionError(f"grandchild {pid} survived")


def test_separate_session_cleanup(base: Path) -> None:
    paths = fixture(base, "runner-grandchild")
    assert_rejected(invoke(paths))
    assert_pid_gone(int((paths["root"] / "grandchild.pid").read_text()))

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        paths = fixture(base, "runner-grandchild")
        result = invoke_with_signal(paths, signum)
        assert result.returncode == 128 + signum
        assert not paths["output"].exists()
        assert_pid_gone(int((paths["root"] / "grandchild.pid").read_text()))


def test_arguments(base: Path) -> None:
    paths = fixture(base)
    for arguments in ([], ["c", POWER], ["a", "unknown"]):
        result = invoke(paths, arguments)
        assert result.returncode == 64
        assert not paths["contact"].exists()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="mac2jb-host-window-tests-") as temporary:
        base = Path(temporary)
        test_success(base)
        test_preflight_stops_before_children(base)
        test_child_failures(base)
        test_separate_session_cleanup(base)
        test_arguments(base)
    print("PASS capture-host authorization window tests (5 groups, 24 scenarios)")


if __name__ == "__main__":
    main()
