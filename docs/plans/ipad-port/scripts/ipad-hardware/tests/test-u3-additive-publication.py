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


def journaled_record(service):
    envelope = json.loads((service.state / "restore-journal.json").read_text())
    return json.loads(base64.b64decode(envelope["payload"]))


def journaled_original(service):
    return base64.b64decode(journaled_record(service)["recipe"]["originalDescription"])


def wait_phase(service, expected, timeout=30):
    """Like Service.phase, but tolerant of a broker busy inside a heal or gate."""
    deadline = time.monotonic() + timeout
    status = ""
    while time.monotonic() < deadline:
        try:
            status = service.command("status")
        except (TimeoutError, OSError):
            time.sleep(0.25)
            continue
        if status == f"OK phase={expected} publication=enabled":
            return
        time.sleep(0.05)
    raise AssertionError(f"expected journal phase {expected}, saw {status}")


def heal_now(service, timeout=90):
    """Run the broker's heal synchronously; it blocks the single-threaded loop."""
    with service.connect("heal") as peer:
        peer.settimeout(timeout)
        return peer.recv(256).decode("ascii").strip()


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


def renewal_keeps_one_publication_alive_and_capped(binary, parent):
    """A live worker renews its lease; the total life of one publication is capped.

    The device takes far longer to come back on bus than one lease quantum, so
    a publication that cannot outlive its first lease can never be observed.
    Renewal is the worker proving it is alive, which is what the lease bounds:
    a worker that stops renewing is still restored within one quantum, and no
    number of renewals extends one publication past the cap.
    """
    service, published = service_with_added_function(
        binary, parent, "renewal",
        extra={"MAC2JB_U2_FIXTURE_LEASE_NS": str(2_000_000_000),
               "MAC2JB_U3_FIXTURE_PUBLICATION_LIFE_NS": str(8_000_000_000)})
    try:
        # Nothing to renew: no journal, and then no registered worker.
        require(service.command("renew-lease") == "ERR rejected",
                "renewed with no journal")
        require(service.command("prepare") == "OK prepared")
        require(service.command("renew-lease") == "ERR rejected",
                "renewed with no worker holding the lease")
        worker = watch(service)
        # A lease is meaningful before publication too.
        reply = service.command("renew-lease")
        require(reply.startswith("OK lease-renewed remaining="), reply)
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        appended = published.read_bytes()

        deadlines = [journaled_record(service)["leaseDeadlineUptime"]]
        recipe = journaled_record(service)["recipe"]
        refused = False
        stop = time.monotonic() + 20
        while time.monotonic() < stop:
            reply = service.command("renew-lease")
            if reply == "ERR rejected":
                # The cap is reached, or the lease has run out. Either way the
                # journal must never have been rewritten by a refusal.
                refused = True
                break
            require(reply.startswith("OK lease-renewed remaining="), reply)
            record = journaled_record(service)
            require(record["phase"] == "published",
                    "a renewal changed the phase: " + record["phase"])
            require(record["recipe"] == recipe, "a renewal changed the recipe")
            require(record["appendedFunctionName"] == ADDED,
                    "a renewal forgot the appended function")
            # An absent key is how the record encodes no external proof.
            require("externalVerificationSHA256" not in record,
                    "a renewal invented verification proof")
            require(record["leaseDeadlineUptime"] > deadlines[-1],
                    "a renewal did not move the deadline forward")
            deadlines.append(record["leaseDeadlineUptime"])
            # The publication is still on the bus, unrestored, because the
            # worker is alive: this is the window no trial has ever had.
            require(published.read_bytes() == appended,
                    "the appended description was restored while the lease was live")
            time.sleep(0.4)
        require(refused, "renewals were never capped")
        require(len(deadlines) > 2, "the lease was never actually extended")
        capped = journaled_record(service)["leaseDeadlineUptime"]
        require(capped == deadlines[-1], "a refused renewal still wrote the journal")

        # Renewal stopped, so the bare original comes back on its own, within
        # the same bound as a lease that was never renewed at all.
        wait_phase(service, "awaitingVerification")
        require(service.count() == 2, "the capped publication was not restored")
        require_original_restored(service, published)
        require(service.command("renew-lease") == "ERR rejected",
                "renewed a lease in a phase where none applies")
        worker.close()
    finally:
        service.stop()


def renewal_state_is_lost_with_the_broker(binary, parent):
    """A restarted broker cannot renew: the journaled deadline is what applies."""
    service, published = service_with_added_function(
        binary, parent, "renewal-restart",
        extra={"MAC2JB_U2_FIXTURE_LEASE_NS": str(20_000_000_000),
               "MAC2JB_U3_FIXTURE_PUBLICATION_LIFE_NS": str(25_000_000_000)})
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command("renew-lease").startswith("OK lease-renewed"))
        journaled = journaled_record(service)["leaseDeadlineUptime"]
        service.process.kill()
        service.process.wait(timeout=3)
        worker.close()
        service.start()
        # The new instance has neither the worker nor the anchor the cap is
        # measured from, so there is nothing it may extend.
        require(service.command("renew-lease") == "ERR rejected",
                "a restarted broker renewed a lease it knows nothing about")
        require(journaled_record(service)["leaseDeadlineUptime"] == journaled,
                "a restart changed the journaled deadline")
        require(not published.exists(), "a restart published something")
    finally:
        service.stop()


def heal_during_a_live_lease_keeps_the_appended_function(binary, parent):
    """The mechanism that recovers USB must not delete what it is recovering.

    A description swap leaves a random function unregistered and the controller
    off bus; the healer re-publishes to recreate every nub. With a publication
    still live, that re-publication has to put the intended description back -
    the journaled original plus the appended function - because the bare
    original would take the appended function off and there would again be
    nothing to observe. The journal stays published and keeps the unmodified
    original as the restore target, so every restore path is unchanged.
    """
    directory = parent / "live-heal"
    directory.mkdir(mode=0o700)
    ready = directory / "ready"
    ready.write_text("0")
    (directory / "queue").write_text("USBAudio2StreamOUT\nValeria")
    service, published = service_with_added_function(
        binary, parent, "live-heal-state",
        extra={"MAC2JB_U2_FIXTURE_READINESS_FILE": str(ready),
               "MAC2JB_U2_FIXTURE_UNSERVED_QUEUE": str(directory / "queue"),
               "MAC2JB_U2_FIXTURE_RESTART_LOG": str(directory / "restarts"),
               "MAC2JB_U2_FIXTURE_HEAL_ON_RESTART": "1",
               "MAC2JB_U2_FIXTURE_LEASE_NS": str(25_000_000_000)})
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        expected = expected_appended(service.original)
        require(plistlib.loads(published.read_bytes()) == expected)
        # A kernel-owned gap first, so the heal must re-publish rather than
        # restart an owner, then the owner-owned gap it can fix.
        reply = heal_now(service)
        require(reply == "OK healed republications=1 "
                         "owner-restarts=com.apple.audiomxd", reply)
        require(service.count() == 2, "exactly one re-publication expected")
        require(plistlib.loads(published.read_bytes()) == expected,
                "the heal re-published the bare original and lost the function")
        require(journaled_original(service) == service.original,
                "the heal changed the restore target")
        record = journaled_record(service)
        require(record["phase"] == "published",
                "a heal during a live lease ended the publication: " + record["phase"])
        require(record["appendedFunctionName"] == ADDED)
        # And it is still restorable, to exactly the original bytes.
        worker.close()
        wait_phase(service, "awaitingVerification")
        require(service.count() == 3, "worker death did not restore")
        require_original_restored(service, published)
    finally:
        service.stop()


def heal_without_a_live_lease_restores_the_bare_original(binary, parent):
    """Once the lease is gone, every heal re-publication is a restore.

    The lease expires with the appended function on the bus and the controller
    off bus, so the readiness gate times out and the broker heals. That heal is
    not continuing a trial, so each of its bounded re-publications must put the
    journaled original back - the appended function comes off and stays off.
    """
    directory = parent / "dead-heal"
    directory.mkdir(mode=0o700)
    ready = directory / "ready"
    ready.write_text("0")
    (directory / "queue").write_text("USBAudio2StreamOUT")
    service, published = service_with_added_function(
        binary, parent, "dead-heal-state",
        extra={"MAC2JB_U2_FIXTURE_READINESS_FILE": str(ready),
               "MAC2JB_U2_FIXTURE_UNSERVED_QUEUE": str(directory / "queue"),
               "MAC2JB_U2_FIXTURE_RESTART_LOG": str(directory / "restarts"),
               "MAC2JB_U2_FIXTURE_HEAL_ON_RESTART": "0"})
    try:
        require(service.command("prepare") == "OK prepared")
        worker = watch(service)
        require(service.command(f"publish-hid {ADDED}") == "OK published-additive")
        require(service.count() == 1)
        # The one-second lease expires, the readiness gate times out, and the
        # bounded heal re-publishes. Never the appended description.
        status = ""
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                status = service.command("heal-status")
            except (TimeoutError, OSError):
                time.sleep(0.5)
                continue
            if status.startswith("OK last-heal heal-gave-up"):
                break
            time.sleep(0.25)
        require(status.startswith("OK last-heal heal-gave-up "
                                  "missing=USBAudio2StreamOUT republications=5"), status)
        require(service.count() == 6, "must stop after 5 re-publications")
        require_original_restored(service, published)
        require(service.command("renew-lease") == "ERR rejected",
                "a lease that is gone was renewed")
        worker.close()
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
        # The renewable lease exists to observe an appended function, so the
        # rollback artifact keeps the single hard-bounded lease the U2 hardware
        # trials passed with and has no renewal command at all.
        renewed = service.command("renew-lease")
        require(renewed == "ERR rejected",
                "a broker without the appending command must refuse lease "
                "renewal too: " + str(renewed))
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
                           ("cycle", bus_cycle_only_while_a_publication_is_live),
                           ("renewal", renewal_keeps_one_publication_alive_and_capped),
                           ("renewal-restart", renewal_state_is_lost_with_the_broker),
                           ("live-heal", heal_during_a_live_lease_keeps_the_appended_function),
                           ("dead-heal", heal_without_a_live_lease_restores_the_bare_original)):
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
          "before anything is published and once the original is back, a "
          "heartbeat-renewable lease that moves its deadline forward only, is "
          "refused with no journal, no worker, a restarted broker or a phase "
          "where no lease applies, caps the total life of one publication "
          "however many renewals arrive and restores on its own when renewal "
          "stops, and a heal that re-publishes the intended description while "
          "that lease is live but the bare journaled original once it is not")


if __name__ == "__main__":
    main()
