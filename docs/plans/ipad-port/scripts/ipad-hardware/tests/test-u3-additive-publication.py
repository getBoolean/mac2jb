#!/usr/bin/env python3
"""Prove the broker can publish the original plus exactly one added function.

Two layers, both Mac-only. First the pure C append helper from the real shim
is compiled and run against a synthetic description, with no IOKit controller
and no publication. Then the Swift watchdog fixture is driven over its socket:
`publish-hid` must emit the journaled original with one interface appended last
in the host-selected configuration, keep the journal byte-equal to the original,
and restore that original on worker death, watchdog restart, lease expiry and an
explicit restore request. The fake controller keeps the description it was last
given, so every restore case compares the bytes actually put back with the
journaled original instead of only counting events. It must also refuse a
request without a lease, in the wrong journal phase, with an already-present
name, or with a malformed name, and a refused name must leave the journal
unpublished so no restore swap is needed at all. A publication whose controller
call fails must still restore, and the fallback that makes that work must not
be able to publish over a description the journal never recorded. No iPad is
contacted and nothing calls SetDescription.
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
# A raw controller return that is neither success nor a value anything here
# interprets: the reply has to carry it through unchanged.
BUS_CYCLE_RETURN = 0xE0000001


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
    # The description the fake controller currently has on the bus. It is
    # written by every publication, including a restore, so a restore that put
    # back the wrong bytes is visible here.
    published = directory / "published.bplist"
    env = dict(os.environ,
               MAC2JB_U3_FIXTURE_APPENDED_FILE=str(published),
               MAC2JB_U3_FIXTURE_SELECTED_CONFIGURATION=str(SELECTED_CONFIGURATION))
    env.update(extra or {})
    service = FIXTURE["Service"](binary, directory, env=env)
    # Replace the shared fixture's empty-interface description with one that
    # already carries interfaces, so order preservation is observable.
    service.live.write_bytes(description())
    service.original = service.live.read_bytes()
    return service, published


def require_original_restored(service, published):
    """The bytes on the bus are the journaled original, with nothing appended."""
    require(published.is_file(), "nothing was ever published")
    restored = published.read_bytes()
    require(restored == journaled_original(service),
            "the restored description is not the journaled original")
    require(restored == service.original,
            "the restored description is not byte-equal to the original")
    for entry in plistlib.loads(restored)["ConfigurationDescriptors"]:
        require(ADDED not in entry.get("Interfaces", []),
                "an appended interface survived the restore")


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
    service, published = service_with_added_function(binary, parent, "malformed")
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        # A malformed name must be refused before any controller call, so the
        # event file must not gain a publication byte.
        for bad in ("bad name", "_leading", "has/slash", "a" * 33, ""):
            require(service.command(f"publish-hid {bad}") == "ERR rejected",
                    "malformed name accepted: " + repr(bad))
        require(service.count() == 0, "a malformed name reached the controller")
        require(not published.exists())
        # The lease then expires with the record still prepared, so recovery
        # needs no controller call at all: nothing was ever published.
        service.phase("awaitingVerification")
        require(service.count() == 0, "a refused request still wrote the controller")
        require(journaled_original(service) == service.original)
        worker.close()
    finally:
        service.stop()


def published_content(binary, parent):
    service, published = service_with_added_function(binary, parent, "content")
    try:
        # No prepared record: there is no lease to publish under.
        require(service.command(f"publish-hid {ADDED}") == "ERR rejected",
                "published without a lease")
        require(service.count() == 0)
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        require(published.is_file(), "no appended description was published")

        actual = plistlib.loads(published.read_bytes())
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
        require_original_restored(service, published)
        require(service.command(f"publish-hid {ADDED}") == "ERR rejected",
                "published while awaiting verification")
        require(service.count() == 2)
    finally:
        service.stop()


def restart_restores(binary, parent):
    service, published = service_with_added_function(binary, parent, "restart")
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
        require_original_restored(service, published)
    finally:
        service.stop()


def lease_expiry_restores(binary, parent):
    service, published = service_with_added_function(binary, parent, "lease")
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        # The worker stays open; only the lease deadline can end this.
        service.phase("awaitingVerification")
        require(service.count() == 2, "lease expiry did not restore")
        require_original_restored(service, published)
        worker.close()
    finally:
        service.stop()


def explicit_restore_after_additive(binary, parent):
    """A successful additive publication must still be restorable.

    The fake controller refuses a publication whose description does not match
    what it already has on the bus, exactly as the controller backend refuses a
    clone that is not the journaled original. So a restore that ignores the
    function it appended is rejected here and the journal ends in
    recoveryRequired instead of awaitingVerification.
    """
    service, published = service_with_added_function(binary, parent, "restore")
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        require(plistlib.loads(published.read_bytes()) ==
                expected_appended(service.original))
        require(service.command("restore") == "OK restore-issued",
                "an additive publication could not be restored")
        service.phase("awaitingVerification")
        require(service.count() == 2)
        require_original_restored(service, published)
        worker.close()
    finally:
        service.stop()


def failed_controller_call_still_restores(binary, parent):
    """A publication whose controller call fails must still be restorable.

    The dry run passes, so the journal is already published and carries the
    function it meant to append, but the controller wrote nothing: the live
    description has no appended function and the strip is refused. The restore
    then falls back to publishing the original unchanged, so the device never
    ends up stuck with a journal it cannot act on.
    """
    service, published = service_with_added_function(
        binary, parent, "failed-call",
        extra={"MAC2JB_FIXTURE_FAIL_APPENDING_PUBLISH": "1"})
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command(f"publish-hid {ADDED}") == "ERR rejected",
                "a failed controller call was reported as published")
        # The failure path restored immediately, and the restore had to publish
        # the original without a strip.
        service.phase("awaitingVerification")
        require(service.count() == 1, "the failed publication was not restored")
        require_original_restored(service, published)
        worker.close()
    finally:
        service.stop()


def retry_never_drops_an_interface(binary, parent):
    """The fallback cannot become a way to publish something unjournaled.

    The live description is replaced with one carrying an interface the journal
    never recorded. The strip is refused because the recorded name is not
    there, and the plain publish that follows is refused too, because the
    description on the bus is not the journaled original. Nothing is written
    and the journal keeps the appended function for a deliberate decision.
    """
    service, published = service_with_added_function(binary, parent, "no-drop")
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        foreign = plistlib.loads(service.original)
        foreign["ConfigurationDescriptors"][SELECTED_CONFIGURATION - 1][
            "Interfaces"].append("Foreign")
        published.write_bytes(plistlib.dumps(foreign, fmt=plistlib.FMT_BINARY))
        require(service.command("restore") == "ERR rejected",
                "a description the journal never recorded was republished over")
        service.phase("recoveryRequired")
        require(service.count() == 1, "the refused restore still wrote the controller")
        require(plistlib.loads(published.read_bytes()) == foreign,
                "an interface was dropped by the fallback")
        worker.close()
    finally:
        service.stop()


def existing_name_refused(binary, parent):
    service, published = service_with_added_function(binary, parent, "duplicate")
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        present = EXISTING_INTERFACES[SELECTED_CONFIGURATION][0]
        require(service.command("publish-hid " + present) == "ERR rejected",
                "an already-present name was published")
        require(not published.exists(), "an appended description was published anyway")
        # The name is checked against the live description before the journal
        # moves to published, so the refusal leaves nothing to undo: the lease
        # then expires on a prepared record, which needs no controller call.
        service.phase("awaitingVerification")
        require(service.count() == 0, "a refused name still swapped the description")
        require(journaled_original(service) == service.original)
        worker.close()
    finally:
        service.stop()


def bus_cycle_only_while_a_publication_is_live(binary, parent):
    """The standalone bus cycle: refused outside a live publication, publishes nothing.

    Publishing cycles the bus, so the host reads the configuration descriptor
    before the appended interface has a class, descriptors or endpoints.
    Committing the interface afterwards changes only the device's own state, so
    the host never requests a report descriptor for it. A second cycle, with the
    interface configured and the lease still held, is what makes the host
    re-enumerate - and it is only ever meaningful there, so it is refused with
    no worker, with no journal and once the original is back.
    """
    cycles = parent / "bus-cycles"
    service, published = service_with_added_function(
        binary, parent, "cycle",
        extra={"MAC2JB_U3_FIXTURE_BUS_CYCLE_LOG": str(cycles),
               "MAC2JB_U3_FIXTURE_BUS_CYCLE_RETURN": str(BUS_CYCLE_RETURN)})
    try:
        # No journal: nothing has been published, so a cycle would only
        # disturb a connection that is already healthy.
        require(service.command("cycle-bus") == "ERR rejected",
                "the bus was cycled with no journal")
        require(service.command("prepare") == "OK prepared")
        # Journalled, but no worker holds the lease: outside a live trial a
        # cycle has nothing to make visible and nothing to restore it.
        require(service.command("cycle-bus") == "ERR rejected",
                "the bus was cycled with no worker holding the lease")
        worker = watch(service)
        # A lease, but no publication yet.
        require(service.command("cycle-bus") == "ERR rejected",
                "the bus was cycled before anything was published")
        require(not cycles.exists(), "a refused cycle reached the controller")
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        appended = published.read_bytes()

        reply = service.command("cycle-bus")
        require(reply == "OK bus-cycled io=0x%08x" % BUS_CYCLE_RETURN,
                "the raw bus-cycle return was not reported verbatim: " + str(reply))
        require(len(cycles.read_bytes()) == 1,
                "the accepted cycle did not reach the controller exactly once")
        # It publishes nothing: the description on the bus is the one the
        # additive publication wrote, and no publication event was recorded.
        require(published.read_bytes() == appended,
                "a bus cycle changed the live description")
        require(service.count() == 1, "a bus cycle published something")

        # Once the original is back, cycling is pointless and refused again.
        worker.close()
        service.phase("awaitingVerification")
        require(service.count() == 2)
        require_original_restored(service, published)
        require(service.command("cycle-bus") == "ERR rejected",
                "the bus was cycled after the original was already back")
        require(len(cycles.read_bytes()) == 1, "a refused cycle reached the controller")
    finally:
        service.stop()


def conservative_variant_has_no_appending_command(binary, parent):
    """A broker built without the appending capability refuses the command.

    The rollback target is meant to be the broker shape the hardware trials
    passed, so the capability must be absent from the artifact rather than
    merely unused. A build's file name cannot carry that guarantee; this can.
    """
    service, published = service_with_added_function(binary, parent, "conservative")
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        reply = service.command(f"publish-hid {ADDED}")
        require(reply == "ERR rejected",
                "a broker without the appending command must refuse it: " + str(reply))
        # The standalone bus cycle exists only for an appended function, so it
        # is behind the same compile-time condition and is equally absent here.
        cycled = service.command("cycle-bus")
        require(cycled == "ERR rejected",
                "a broker without the appending command must refuse the bus "
                "cycle too: " + str(cycled))
        require(not published.exists(),
                "a broker lacking the command still published an appended description")
        require(service.count() == 0, "a refused command still called the controller")
        require(journaled_original(service) == service.original)
        worker.close()
    finally:
        service.stop()


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u3-additive-", dir="/tmp") as temporary:
        root = Path(temporary)
        append_helper(root)
        binary = root / "native-service-fixture"
        # The appending command exists only in the variant that carries it.
        FIXTURE["build"](binary, root / "cache",
                         defines=("MAC2JB_U3_ADDITIVE_FUNCTION",))
        for name, test in (("malformed", malformed_name_refused),
                           ("content", published_content),
                           ("restart", restart_restores),
                           ("lease", lease_expiry_restores),
                           ("restore", explicit_restore_after_additive),
                           ("failed-call", failed_controller_call_still_restores),
                           ("no-drop", retry_never_drops_an_interface),
                           ("duplicate", existing_name_refused),
                           ("cycle", bus_cycle_only_while_a_publication_is_live)):
            directory = root / ("case-" + name)
            directory.mkdir(mode=0o700)
            test(binary, directory)
        # Same sources, no appending capability compiled in: the conservative
        # rollback artifact must genuinely lack the command.
        conservative = root / "native-service-fixture-conservative"
        FIXTURE["build"](conservative, root / "cache-conservative")
        require(conservative.read_bytes() != binary.read_bytes(),
                "the two broker variants must not be identical binaries")
        directory = root / "case-conservative"
        directory.mkdir(mode=0o700)
        conservative_variant_has_no_appending_command(conservative, directory)
    print("PASS additive publication: original plus one interface appended last "
          "in the selected configuration, journal byte-equal to the original, "
          "the exact original bytes put back on worker death, watchdog restart, "
          "lease expiry and an explicit restore, refusal without a lease, in "
          "the wrong phase, on an existing name and on a malformed name, both "
          "before any controller write and with nothing to undo, recovery "
          "from a failed controller call, a fallback that refuses to "
          "publish over a description the journal never recorded, and a "
          "standalone bus cycle that publishes nothing, reports its raw "
          "return verbatim and is refused with no worker, with no journal, "
          "before anything is published and once the original is back")


if __name__ == "__main__":
    main()
