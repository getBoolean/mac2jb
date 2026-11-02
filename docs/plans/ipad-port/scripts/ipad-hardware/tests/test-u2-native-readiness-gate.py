#!/usr/bin/env python3
"""Prove worker death cannot issue a second USB call before readiness.

This compiles the real Swift watchdog against a Mac file-backed fake
controller. The readiness signal is a temporary file controlled by this test.
It never contacts the iPad or a real USB controller.
"""

import os
from pathlib import Path
import runpy
import tempfile
import time


ROOT = Path(__file__).resolve().parents[6]
FIXTURE = runpy.run_path(str(ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/tests/test-u2-native-service-fixture.py"))


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u2-gate-", dir="/tmp") as temporary:
        root = Path(temporary)
        binary = root / "native-service-fixture"
        FIXTURE["build"](binary, root)
        case = root / "worker-death"
        case.mkdir(mode=0o700)
        readiness = case / "ready"
        readiness.write_text("0", encoding="ascii")
        service = FIXTURE["Service"](
            binary, case,
            env=dict(os.environ, MAC2JB_U2_FIXTURE_READINESS_FILE=str(readiness)))
        try:
            assert service.command("prepare") == "OK prepared"
            worker = service.connect("watch")
            assert worker.recv(256) == b"OK watching\n"
            assert service.command("publish-noop") == "OK published"
            assert service.count() == 1
            worker.close()
            time.sleep(8)
            assert service.count() == 1, "recovery ran before configuration"
            readiness.write_text("1", encoding="ascii")
            time.sleep(8)
            assert service.count() == 2, "recovery did not follow configuration"
            service.phase("awaitingVerification")
        finally:
            service.stop()
        case = root / "timeout"
        case.mkdir(mode=0o700)
        readiness = case / "ready"
        readiness.write_text("0", encoding="ascii")
        service = FIXTURE["Service"](
            binary, case,
            env=dict(os.environ, MAC2JB_U2_FIXTURE_READINESS_FILE=str(readiness)))
        try:
            assert service.command("prepare") == "OK prepared"
            worker = service.connect("watch")
            assert worker.recv(256) == b"OK watching\n"
            assert service.command("publish-noop") == "OK published"
            worker.close()
            time.sleep(18)
            assert service.count() == 1, "timeout issued a second controller call"
            service.phase("recoveryRequired")
        finally:
            service.stop()
    print("PASS native U2 readiness gate: waits for configuration and fails closed on timeout")


if __name__ == "__main__":
    main()
