#!/usr/bin/env python3
"""Prove the broker heals unregistered USB functions automatically (Mac fixture).

Compiles the real Swift watchdog against the file-backed fake controller. A
queue file gives the unserved functions after each publication, and an owner
restart can flip the controller to configured. Never contacts the iPad.
"""

import os
from pathlib import Path
import runpy
import tempfile
import time

ROOT = Path(__file__).resolve().parents[6]
FIXTURE = runpy.run_path(str(ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/tests/test-u2-native-service-fixture.py"))


def case(binary, root, name, queue, heal_on_restart):
    directory = root / name
    directory.mkdir(mode=0o700)
    ready = directory / "ready"
    ready.write_text("0")
    (directory / "queue").write_text("\n".join(queue))
    restarts = directory / "restarts"
    env = dict(os.environ, MAC2JB_U2_FIXTURE_READINESS_FILE=str(ready),
               MAC2JB_U2_FIXTURE_UNSERVED_QUEUE=str(directory / "queue"),
               MAC2JB_U2_FIXTURE_RESTART_LOG=str(restarts),
               MAC2JB_U2_FIXTURE_HEAL_ON_RESTART="1" if heal_on_restart else "0")
    return FIXTURE["Service"](binary, directory, env=env), restarts


def worker_death(service):
    assert service.command("prepare") == "OK prepared"
    worker = service.connect("watch")
    assert worker.recv(256) == b"OK watching\n"
    assert service.command("publish-noop") == "OK published"
    worker.close()


def wait_heal(service, prefix, timeout=40):
    deadline = time.monotonic() + timeout
    status = ""
    while time.monotonic() < deadline:
        try:
            status = service.command("heal-status")
        except (TimeoutError, OSError):
            # The single-threaded broker is inside the readiness gate or heal.
            time.sleep(0.5)
            continue
        if status.startswith("OK last-heal " + prefix) and status != "OK last-heal none":
            return status
        time.sleep(0.25)
    raise AssertionError("heal did not finish: " + status)


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u2-heal-", dir="/tmp") as temporary:
        root = Path(temporary)
        binary = root / "native-service-fixture"
        FIXTURE["build"](binary, root)

        service, restarts = case(binary, root, "owner-only", ["Valeria,PTP"], True)
        try:
            worker_death(service)
            status = wait_heal(service, "healed")
            assert status == "OK last-heal healed republications=0 owner-restarts=com.apple.audiomxd", status
            assert service.count() == 1, "owner-only gap must not republish"
            assert restarts.read_text() == "com.apple.audiomxd\n"
            service.phase("awaitingVerification")
        finally:
            service.stop()

        service, restarts = case(binary, root, "kernel-then-owner",
                                 ["USBAudio2StreamOUT", "Valeria"], True)
        try:
            worker_death(service)
            status = wait_heal(service, "healed")
            assert status == "OK last-heal healed republications=1 owner-restarts=com.apple.audiomxd", status
            assert service.count() == 2, "one republication expected"
            service.phase("awaitingVerification")
        finally:
            service.stop()

        service, restarts = case(binary, root, "persistent-gap", ["USBAudio2StreamOUT"], False)
        try:
            worker_death(service)
            status = wait_heal(service, "heal-gave-up")
            assert status.startswith("OK last-heal heal-gave-up missing=USBAudio2StreamOUT republications=5"), status
            assert service.count() == 6, "must stop after 5 republications"
            service.phase("awaitingVerification")  # healing never confirms or clears
        finally:
            service.stop()

        # Watchdog killed after publication: launchd-style restart must heal.
        service, restarts = case(binary, root, "watchdog-restart", ["Valeria"], True)
        try:
            assert service.command("prepare") == "OK prepared"
            worker = service.connect("watch")
            assert worker.recv(256) == b"OK watching\n"
            assert service.command("publish-noop") == "OK published"
            service.process.kill()
            service.process.wait(timeout=3)
            worker.close()
            service.start(timeout=60)  # recoverAtStart: gate times out, then heals
            status = wait_heal(service, "healed")
            assert status == "OK last-heal healed republications=0 owner-restarts=com.apple.audiomxd", status
            service.phase("awaitingVerification")
        finally:
            service.stop()

        service, restarts = case(binary, root, "restore-after-failure",
                                 ["USBAudio2StreamIN", "Valeria"], True)
        try:
            worker_death(service)
            wait_heal(service, "")  # first automatic heal attempt finished
            print("  restore-after-failure path:", service.command("heal-status"))
        finally:
            service.stop()
    print("PASS native U2 auto-heal: owner restart, republish-then-restart, bounded give-up, watchdog restart, never confirms")


if __name__ == "__main__":
    main()
