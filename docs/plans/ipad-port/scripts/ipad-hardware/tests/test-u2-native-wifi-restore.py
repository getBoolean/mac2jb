#!/usr/bin/env python3
"""Prove `restore-after-failure` republishes once only when USB is lost.

Compiles the real Swift watchdog against the Mac file-backed fake controller.
The configured-state signal is a temporary file. Never contacts the iPad.
"""

import os
from pathlib import Path
import runpy
import tempfile
import time


ROOT = Path(__file__).resolve().parents[6]
FIXTURE = runpy.run_path(str(ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/tests/test-u2-native-service-fixture.py"))


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u2-wifi-restore-", dir="/tmp") as temporary:
        root = Path(temporary)
        binary = root / "native-service-fixture"
        FIXTURE["build"](binary, root)
        case = root / "failed-trial"
        case.mkdir(mode=0o700)
        configured = case / "ready"
        configured.write_text("0", encoding="ascii")
        service = FIXTURE["Service"](
            binary, case,
            env=dict(os.environ, MAC2JB_U2_FIXTURE_READINESS_FILE=str(configured)))
        try:
            assert service.command("restore-after-failure").startswith("ERR"), "no journal accepted"
            assert service.command("prepare") == "OK prepared"
            worker = service.connect("watch")
            assert worker.recv(256) == b"OK watching\n"
            assert service.command("publish-noop") == "OK published"
            worker.close()
            time.sleep(18)
            assert service.count() == 1
            service.phase("recoveryRequired")
            assert service.command("restore-after-failure").startswith("OK restore-after-failure-issued")
            assert service.count() == 2, "recoveryRequired did not republish once"
            service.phase("awaitingVerification")
            assert service.command("restore") == "OK awaiting-verification"
            assert service.count() == 2, "plain restore must stay a no-op"
            configured.write_text("1", encoding="ascii")
            assert service.command("restore-after-failure").startswith("ERR"), "configured accepted"
            assert service.count() == 2, "configured controller was republished"
            service.phase("awaitingVerification")
            configured.write_text("0", encoding="ascii")
            assert service.command("restore-after-failure").startswith("OK restore-after-failure-issued")
            assert service.count() == 3, "awaitingVerification did not republish once"
            service.phase("awaitingVerification")
        finally:
            service.stop()
    print("PASS native U2 restore-after-failure: once per request, only while unconfigured, never confirms")


if __name__ == "__main__":
    main()
