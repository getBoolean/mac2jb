#!/usr/bin/env python3
"""Verify the real watchdog waits before restoring after worker death on Mac.

This links the real native service to the existing file-backed fake controller
and enables only the v6 timing flag. It contacts no iPad or USB controller.
The assertion checks the observable gap between worker loss and the second
controller call; it cannot prove iPad USB enumeration or recovery.
"""

import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[6]
FIXTURE = runpy.run_path(str(ROOT / "scripts/ipad-hardware/tests/test-u2-native-service-fixture.py"))


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u2-settle-fixture-", dir="/tmp") as temporary:
        root = Path(temporary)
        binary = root / "settled-service-fixture"
        env = dict(os.environ, CLANG_MODULE_CACHE_PATH=str(root / "clang"),
                   SWIFT_MODULE_CACHE_PATH=str(root / "swift"))
        command = ["/usr/bin/xcrun", "swiftc", "-D", "MAC2JB_U2_SETTLED_RECOVERY",
                   *(str(ROOT / path) for path in FIXTURE["SOURCES"]),
                   "-o", str(binary)]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=60, env=env)
        if result.returncode:
            raise AssertionError("settled service fixture compile failed")
        case = root / "worker-death"
        case.mkdir(mode=0o700)
        service = FIXTURE["Service"](binary, case)
        try:
            assert service.command("prepare") == "OK prepared"
            worker = service.connect("watch")
            assert worker.recv(256) == b"OK watching\n"
            assert service.command("publish-noop") == "OK published"
            assert service.count() == 1
            started = time.monotonic()
            worker.close()
            deadline = started + 9
            while service.count() != 2 and time.monotonic() < deadline:
                time.sleep(0.05)
            elapsed = time.monotonic() - started
            assert service.count() == 2 and 4.7 <= elapsed <= 8.0, elapsed
            service.phase("awaitingVerification")
            assert service.command("confirm " + "a" * 64) == "OK verified-and-cleared"
        finally:
            service.stop()
        case = root / "watchdog-restart"
        case.mkdir(mode=0o700)
        service = FIXTURE["Service"](binary, case)
        try:
            assert service.command("prepare") == "OK prepared"
            worker = service.connect("watch")
            assert worker.recv(256) == b"OK watching\n"
            assert service.command("publish-noop") == "OK published"
            assert service.count() == 1
            service.stop()
            worker.close()
            started = time.monotonic()
            service.start(timeout=8)
            elapsed = time.monotonic() - started
            assert service.count() == 2 and 4.7 <= elapsed <= 8.0, elapsed
            service.phase("awaitingVerification")
            assert service.command("confirm " + "b" * 64) == "OK verified-and-cleared"
        finally:
            service.stop()
    print("PASS native U2 settled recovery fixture: worker death and watchdog restart wait before second controller call")


if __name__ == "__main__":
    main()
