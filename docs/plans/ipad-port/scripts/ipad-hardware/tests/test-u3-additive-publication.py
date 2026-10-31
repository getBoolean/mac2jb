#!/usr/bin/env python3
"""Prove the broker can publish the original plus exactly one added function.

Two layers, both Mac-only. First the pure C append helper from the real shim
is compiled and run against a synthetic description, with no IOKit controller
and no publication. Then the Swift watchdog fixture is driven over its socket:
`publish-hid` must emit the journaled original with one interface appended last
in the host-selected configuration, keep the journal byte-equal to the original,
restore that original on worker death, watchdog restart and lease expiry, and
refuse a request without a lease, in the wrong journal phase, with an
already-present name, or with a malformed name (the last before any controller
call). No iPad is contacted and nothing calls SetDescription.
"""

import base64
import json
import os
from pathlib import Path
import plistlib
import runpy
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[6]
FIXTURE = runpy.run_path(str(
    ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/tests/test-u2-native-service-fixture.py"))

# The configuration the fake host selects, and the interfaces already on the
# bus. Nothing here is device data: the broker reads the selected configuration
# from the controller, and the fixture reads it from the environment.
SELECTED_CONFIGURATION = 5
EXISTING_INTERFACES = {
    1: ["Valeria"],
    SELECTED_CONFIGURATION: ["PTP", "USBAudio2StreamOUT", "AppleUSBMux"],
}
ADDED = "Mac2jbCanary"


def require(value, what="additive publication mismatch"):
    if not value:
        raise AssertionError(what)


def description():
    fields = {
        "Attributes": 192, "BcdUSBVersion": 768,
        "ConfigurationDescriptors": [
            {"Description": f"configuration-{number}",
             "Interfaces": list(EXISTING_INTERFACES.get(number, []))}
            for number in range(1, 10)
        ],
        "DefaultBcdUSBVersion": 768, "MPS0": 9, "MaxPower": 112,
        "deviceClass": 0, "deviceID": 1, "deviceProtocol": 0,
        "deviceSubClass": 0, "manufacturerString": "fixture",
        "productID": 1, "productString": "fixture", "serialNumber": "fixture",
        "uniqueDeviceID": "fixture", "vendorID": 1,
    }
    return plistlib.dumps(fields, fmt=plistlib.FMT_BINARY, sort_keys=True)


def append_helper(root):
    """Compile and run the pure helper tests from the real shim translation unit."""
    binary = root / "append-tests"
    build = subprocess.run(
        ["/usr/bin/xcrun", "clang",
         str(ROOT / "ios/tests/USBDescriptionAppendTests.c"),
         str(ROOT / "ios/usb/USBRestoreControllerShim.c"),
         "-framework", "CoreFoundation", "-framework", "IOKit",
         "-o", str(binary)], capture_output=True, text=True, timeout=180)
    if build.returncode != 0:
        raise AssertionError("append helper tests failed to compile:\n" +
                             build.stderr[-2000:])
    run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
    print("  " + (run.stdout.strip() or run.stderr.strip()))
    if run.returncode != 0:
        raise AssertionError("pure append helper tests failed:\n" + run.stderr[-2000:])


def service_with_added_function(binary, parent, name, extra=None):
    directory = parent / name
    directory.mkdir(mode=0o700)
    appended = directory / "appended.bplist"
    env = dict(os.environ,
               MAC2JB_U3_FIXTURE_APPENDED_FILE=str(appended),
               MAC2JB_U3_FIXTURE_SELECTED_CONFIGURATION=str(SELECTED_CONFIGURATION))
    env.update(extra or {})
    service = FIXTURE["Service"](binary, directory, env=env)
    # Replace the shared fixture's empty-interface description with one that
    # already carries interfaces, so order preservation is observable.
    service.live.write_bytes(description())
    service.original = service.live.read_bytes()
    return service, appended


def journaled_original(service):
    envelope = json.loads((service.state / "restore-journal.json").read_text())
    payload = json.loads(base64.b64decode(envelope["payload"]))
    return base64.b64decode(payload["recipe"]["originalDescription"])


def expected_appended(original):
    plist = plistlib.loads(original)
    plist["ConfigurationDescriptors"][SELECTED_CONFIGURATION - 1]["Interfaces"].append(ADDED)
    return plist


def watch(service):
    worker = service.connect("watch")
    require(worker.recv(256) == b"OK watching\n", "worker lease not granted")
    return worker


def malformed_name_refused(binary, parent):
    service, appended = service_with_added_function(binary, parent, "malformed")
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        # A malformed name must be refused before any controller call, so the
        # event file must not gain a publication byte.
        for bad in ("bad name", "_leading", "has/slash", "a" * 33, ""):
            require(service.command(f"publish-hid {bad}") == "ERR rejected",
                    "malformed name accepted: " + repr(bad))
        require(service.count() == 0, "a malformed name reached the controller")
        require(not appended.exists())
        # The lease then expires with the record still prepared, so recovery
        # needs no controller call at all: nothing was ever published.
        service.phase("awaitingVerification")
        require(service.count() == 0, "a refused request still wrote the controller")
        require(journaled_original(service) == service.original)
        worker.close()
    finally:
        service.stop()


def published_content(binary, parent):
    service, appended = service_with_added_function(binary, parent, "content")
    try:
        # No prepared record: there is no lease to publish under.
        require(service.command(f"publish-hid {ADDED}") == "ERR rejected",
                "published without a lease")
        require(service.count() == 0)
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        require(appended.is_file(), "no appended description was published")

        actual = plistlib.loads(appended.read_bytes())
        require(actual == expected_appended(service.original),
                "published description is not the original plus one interface")
        interfaces = actual["ConfigurationDescriptors"][SELECTED_CONFIGURATION - 1]["Interfaces"]
        require(interfaces == EXISTING_INTERFACES[SELECTED_CONFIGURATION] + [ADDED],
                "the added interface is not last, or existing order changed")
        for number in range(1, 10):
            if number == SELECTED_CONFIGURATION:
                continue
            require(actual["ConfigurationDescriptors"][number - 1]["Interfaces"] ==
                    EXISTING_INTERFACES.get(number, []),
                    "another configuration changed")
        before = plistlib.loads(service.original)
        for key, value in before.items():
            if key == "ConfigurationDescriptors":
                continue
            require(actual[key] == value, "device-level field changed: " + key)
        require(len(actual) == len(before), "top-level field count changed")

        # The journal keeps the unmodified original as the restore target.
        require(journaled_original(service) == service.original,
                "journal is not byte-equal to the original")

        # A second request under the same worker finds the journal published.
        require(service.command(f"publish-hid {ADDED}2") == "ERR rejected",
                "published twice from one lease")
        require(service.count() == 1)

        # Worker death restores the journaled original, not the appended one.
        worker.close()
        service.phase("awaitingVerification")
        require(service.count() == 2, "worker death did not restore")
        require(journaled_original(service) == service.original)
        require(service.command(f"publish-hid {ADDED}") == "ERR rejected",
                "published while awaiting verification")
        require(service.count() == 2)
    finally:
        service.stop()


def restart_restores(binary, parent):
    service, appended = service_with_added_function(binary, parent, "restart")
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        service.process.kill()
        service.process.wait(timeout=3)
        worker.close()
        service.start()
        service.phase("awaitingVerification")
        require(service.count() == 2, "watchdog restart did not restore")
        require(journaled_original(service) == service.original)
    finally:
        service.stop()


def lease_expiry_restores(binary, parent):
    service, appended = service_with_added_function(binary, parent, "lease")
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        # The worker stays open; only the lease deadline can end this.
        service.phase("awaitingVerification")
        require(service.count() == 2, "lease expiry did not restore")
        require(journaled_original(service) == service.original)
        worker.close()
    finally:
        service.stop()


def existing_name_refused(binary, parent):
    service, appended = service_with_added_function(binary, parent, "duplicate")
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        present = EXISTING_INTERFACES[SELECTED_CONFIGURATION][0]
        require(service.command("publish-hid " + present) == "ERR rejected",
                "an already-present name was published")
        require(not appended.exists(), "an appended description was published anyway")
        # The refusal came from the publication path, so the coordinator
        # restored the original exactly once.
        service.phase("awaitingVerification")
        require(service.count() == 1, "the original was not restored once")
        require(journaled_original(service) == service.original)
        worker.close()
    finally:
        service.stop()


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u3-additive-", dir="/tmp") as temporary:
        root = Path(temporary)
        append_helper(root)
        binary = root / "native-service-fixture"
        FIXTURE["build"](binary, root / "cache")
        for name, test in (("malformed", malformed_name_refused),
                           ("content", published_content),
                           ("restart", restart_restores),
                           ("lease", lease_expiry_restores),
                           ("duplicate", existing_name_refused)):
            directory = root / ("case-" + name)
            directory.mkdir(mode=0o700)
            test(binary, directory)
    print("PASS additive publication: original plus one interface appended last "
          "in the selected configuration, journal byte-equal to the original, "
          "restore on worker death, watchdog restart and lease expiry, refusal "
          "without a lease, in the wrong phase, on an existing name, and on a "
          "malformed name before any controller call")


if __name__ == "__main__":
    main()
