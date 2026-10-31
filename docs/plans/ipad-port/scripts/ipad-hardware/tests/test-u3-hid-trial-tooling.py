#!/usr/bin/env python3
"""Mac-only fixtures for the HID enumeration comparator and the HID trial runner.

No device, no network, no USB: every input here is synthetic. The comparator is
driven with hand-built raw configuration descriptors and a hand-built ioreg
transcript; the runner is driven with an injected command surface that models
the broker's real preconditions - `watch` accepted only while the journal is
prepared, one worker at a time, and no publication without one - so the
refusals, the publication ordering and the single rule that matters most - no
`confirm` without the strict external check's own output as proof - are
observable without a trial.

The host-side report reader is the one part with a compiled helper. It is built
here and run only in a mode that can bind nothing: the identifiers it is given
belong to no device, so it refuses and stops at its deadline. Nothing in this
file opens, seizes or reads a device, and no report ever reaches this Mac's own
HID stack from a test.
"""

import hashlib
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
CAPTURE = runpy.run_path(str(HOST / "capture-u2-hid-enumeration.py"))
RUNNER = runpy.run_path(str(HOST / "run-u2-hid-trial-wifi.py"))
REPORTS = runpy.run_path(str(HOST / "capture-u2-hid-reports.py"))
READER = HOST / "u2-hid-report-reader.swift"

VENDOR, PRODUCT = 0x05AC, 0x12AB
FAKE_SERIAL = "F4KESER1ALNUMBER0001"
FAKE_UDID = "00008103-000A1B2C3D4E5F60"
# Identifiers no attached device carries, so the reader binds nothing.
UNBOUND_VENDOR, UNBOUND_PRODUCT = 0xFFFF, 0xFFFF
TEMPORARIES = []


def interface(number, triple, endpoints):
    return bytes((9, 4, number, 0, endpoints, *triple, 0))


def endpoint(address=0x81, attributes=0x03, size=8, interval=10):
    return bytes((7, 5, address, attributes, size & 0xFF, size >> 8, interval))


def hid_descriptor(length=65):
    return bytes((9, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, length & 0xFF, length >> 8))


def configuration(number, bodies):
    body = b"".join(bodies)
    length = 9 + len(body)
    return bytes((9, 2, length & 0xFF, length >> 8, 1, number, 0, 0x80, 50)) + body


def envelope(configurations):
    return b"U2CFGD1\0" + bytes((len(configurations),)) + b"".join(
        len(raw).to_bytes(2, "little") + raw for raw in configurations)


def stock_bodies():
    """Three stock interfaces with one bulk endpoint each."""
    return [part for number in range(3) for part in
            (interface(number, (6, 1, 1), 1), endpoint(address=0x82, attributes=0x02, size=512, interval=0))]


def published(triple=(3, 1, 1), endpoints=(endpoint(),), descriptor=hid_descriptor()):
    bodies = stock_bodies() + [interface(3, triple, len(endpoints)), descriptor, *endpoints]
    return envelope([configuration(number, stock_bodies()) for number in (1, 2)] +
                    [configuration(5, bodies)])


def ioreg(descriptor=None, vendor=VENDOR, product=PRODUCT, usage=(1, 6)):
    """A synthetic ioreg transcript seeded with identifiers that must not escape."""
    nodes = [
        '+-o AppleUSBHostPort  <class AppleUSBHostPort, id 0x100000111, registered>',
        '    {',
        '      "UniqueDeviceID" = "%s"' % FAKE_UDID,
        '      "USB Serial Number" = "%s"' % FAKE_SERIAL,
        '    }',
        '+-o OtherHIDDevice  <class AppleUserUSBHostHIDDevice, id 0x100000222, registered>',
        '    {',
        '      "VendorID" = 1118',
        '      "ProductID" = 654',
        '      "PrimaryUsagePage" = 1',
        '      "PrimaryUsage" = 6',
        '      "ReportDescriptor" = <0501090602>',
        '    }',
        '+-o AppleUserUSBHostHIDDevice  <class AppleUserUSBHostHIDDevice, id 0x100000333, registered>',
        '    {',
        '      "VendorID" = %d' % vendor,
        '      "ProductID" = %d' % product,
        '      "PrimaryUsagePage" = %d' % usage[0],
        '      "PrimaryUsage" = %d' % usage[1],
        '      "Transport" = "USB"',
        '      "SerialNumber" = "%s"' % FAKE_SERIAL,
        '      "kUSBSerialNumberString" = "%s"' % FAKE_SERIAL,
    ]
    if descriptor is not None:
        nodes.append('      "ReportDescriptor" = <%s>' % descriptor.hex())
    nodes.append('    }')
    return "\n".join(nodes) + "\n"


def evaluate(raw=None, text=None, reports=None, stock=3):
    if text is None:
        text = ioreg(CAPTURE["REPORT_DESCRIPTOR"])
    return CAPTURE["evaluate"](raw, stock, text, reports, VENDOR, PRODUCT, 5)


def observed(expected=None, mutate=None):
    sequence = list(CAPTURE["expected_reports"]() if expected is None else expected)
    if mutate:
        sequence = mutate(sequence)
    return "\n".join(item.hex() for item in sequence) + "\n"


def failure_text(result):
    return " ".join(result["failures"])


def comparator():
    good = evaluate(published(), reports=CAPTURE["parse_reports"](observed()))
    assert good["outcome"] == "pass", good

    absent = evaluate(None, reports=CAPTURE["parse_reports"](observed()))
    assert absent["outcome"] == "not-enumerated", absent
    assert absent["outcome"] != good["outcome"]

    nothing = evaluate(envelope([configuration(5, stock_bodies())]),
                       reports=CAPTURE["parse_reports"](observed()))
    assert nothing["outcome"] == "interface-absent", nothing

    missing = evaluate(published(), text=ioreg(None),
                       reports=CAPTURE["parse_reports"](observed()))
    assert missing["outcome"] == "report-descriptor-missing", missing
    assert missing["outcome"] not in (good["outcome"], absent["outcome"])

    changed = bytearray(CAPTURE["REPORT_DESCRIPTOR"])
    changed[17] ^= 0xFF
    wrong = evaluate(published(), text=ioreg(bytes(changed)),
                     reports=CAPTURE["parse_reports"](observed()))
    assert wrong["outcome"] == "report-descriptor-mismatch", wrong
    assert "offset=17" in failure_text(wrong), wrong

    short = evaluate(published(), text=ioreg(CAPTURE["REPORT_DESCRIPTOR"][:-1]),
                     reports=CAPTURE["parse_reports"](observed()))
    assert short["outcome"] == "report-descriptor-mismatch", short
    assert "length=64" in failure_text(short), short

    for triple in ((3, 1, 2), (3, 0, 1), (3, 1, 0)):
        tuple_wrong = evaluate(published(triple=triple),
                               reports=CAPTURE["parse_reports"](observed()))
        assert tuple_wrong["outcome"] == "interface-mismatch", tuple_wrong

    for endpoints, reason in (
            ((endpoint(address=0x01),), "direction"),
            ((endpoint(size=64),), "max-packet-size"),
            ((endpoint(attributes=0x02),), "transfer-type"),
            ((endpoint(interval=1),), "interval"),
            ((endpoint(), endpoint(address=0x83)), "count"),
            ((), "count")):
        bad = evaluate(published(endpoints=endpoints),
                       reports=CAPTURE["parse_reports"](observed()))
        assert bad["outcome"] == "endpoint-mismatch", (reason, bad)
        assert reason in failure_text(bad), (reason, bad)

    hid_wrong = evaluate(published(descriptor=hid_descriptor(length=93)),
                         reports=CAPTURE["parse_reports"](observed()))
    assert hid_wrong["outcome"] == "hid-descriptor-mismatch", hid_wrong
    assert "offset=7" in failure_text(hid_wrong), hid_wrong

    extra = evaluate(published(), reports=CAPTURE["parse_reports"](
        observed(mutate=lambda s: s[:3] + [s[2]] + s[3:])))
    assert extra["outcome"] == "reports-mismatch", extra
    assert "index=3" in failure_text(extra), extra
    assert "extra" in failure_text(extra), extra

    dropped = evaluate(published(), reports=CAPTURE["parse_reports"](
        observed(mutate=lambda s: s[:2] + s[3:])))
    assert dropped["outcome"] == "reports-mismatch", dropped
    assert "index=2" in failure_text(dropped), dropped

    truncated = evaluate(published(), reports=CAPTURE["parse_reports"](
        observed(mutate=lambda s: s[:-1])))
    assert truncated["outcome"] == "reports-mismatch", truncated
    assert "missing" in failure_text(truncated), truncated

    unobserved = evaluate(published(), reports=None)
    assert unobserved["outcome"] == "reports-unobserved", unobserved
    assert unobserved["outcome"] != good["outcome"]

    # The host's control requests are evidence only where macOS exposes them.
    statuses = dict(good["control_requests"])
    assert statuses["get-descriptor configuration"] == "observed"
    assert statuses["get-descriptor hid-report"] == "observed"
    assert statuses["set-idle"] == "expected-not-exposed"
    assert dict(missing["control_requests"])["get-descriptor hid-report"] == "not-observed"

    for result in (good, absent, missing, wrong, extra, unobserved):
        text = CAPTURE["render"](result)
        for secret in (FAKE_SERIAL, FAKE_UDID, "SerialNumber", "UniqueDeviceID", "udid"):
            assert secret not in text, (secret, text)
        CAPTURE["assert_identifier_free"](text)
    rejected(lambda: CAPTURE["assert_identifier_free"]("serial=%s" % FAKE_SERIAL))
    rejected(lambda: CAPTURE["assert_identifier_free"]("udid=%s" % FAKE_UDID))
    # The comparator's keystroke table and the canary's own table are two
    # hardcoded lists that have to agree. Compare them, or a divergence is a
    # silent mismatch discovered only on a device.
    source = (ROOT / "ios/canary/HIDKeyboardReport.swift").read_text()
    table = re.search(r"canaryKeystrokes[^=]*=\s*\[(.*?)\]", source, re.S)
    assert table, "could not find the canary's keystroke table"
    canary = [(character, int(keycode, 16), modifiers.strip() != "0")
              for character, modifiers, keycode in
              re.findall(r'\(\s*"(.)"\s*,\s*([^,]+?)\s*,\s*(0x[0-9A-Fa-f]+)\s*\)',
                         table.group(1))]
    assert canary, "could not parse the canary's keystroke table"
    assert canary == list(CAPTURE["KEYSTROKES"]), (
        "the canary types %r but this comparator expects %r"
        % (canary, list(CAPTURE["KEYSTROKES"])))
    assert "".join(character for character, _, _ in canary).isupper(), (
        "the accepted canary string is upper case, so a shifted character must "
        "exercise the modifier byte")
    print("PASS HID enumeration comparator outcomes and identifier redaction")


def descriptors():
    """A device-supplied length is untrusted: every bad one is refused by offset."""
    header = configuration(5, [])[:9]
    for body, reason in ((bytes((0,)), "zero length"),
                         (bytes((1,)), "header-less descriptor"),
                         (bytes((20, 4, 0)), "declared length past the buffer"),
                         (bytes((4, 4, 0, 0)), "interface shorter than an interface")):
        message = rejected(lambda body=body: CAPTURE["interface_groups"](header + body),
                           "malformed-descriptor offset=9")
        assert message.startswith("malformed-descriptor offset=9"), (reason, message)

    groups = CAPTURE["interface_groups"](
        configuration(5, [interface(3, (3, 1, 1), 1), endpoint()]))
    assert len(groups) == 1 and len(groups[0]["endpoints"]) == 1, groups

    # The same refusal through the tool itself: no outcome at all, never a pass.
    with tempfile.TemporaryDirectory(prefix="u3-hid-malformed-") as temporary:
        raw = Path(temporary) / "raw-configs.bin"
        raw.write_bytes(envelope([configuration(5, [bytes((4, 4, 0, 0))])]))
        registry = Path(temporary) / "ioreg.txt"
        registry.write_text(ioreg(CAPTURE["REPORT_DESCRIPTOR"]))
        result = subprocess.run(
            [sys.executable, str(HOST / "capture-u2-hid-enumeration.py"),
             "--configuration=5", "--stock-interfaces=3",
             "--vendor=0x%04x" % VENDOR, "--product=0x%04x" % PRODUCT,
             "--raw-configs=%s" % raw, "--ioreg=%s" % registry],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
        text = result.stdout.decode("ascii", "replace")
        assert result.returncode == 1, (result.returncode, text)
        assert "rejected (malformed-descriptor" in text, text
        assert "outcome=pass" not in text, text

    # A divergence is named for what it is: a differing report at the same
    # index is wrong, a dropped one missing, an inserted one extra.
    expected = CAPTURE["expected_reports"]()
    for reports, name in ((([bytes([1] * 8)] + expected[1:]), "wrong"),
                          (expected[1:], "missing"),
                          (([bytes([1] * 8)] + expected), "extra")):
        result = evaluate(published(), reports=reports)
        assert result["outcome"] == "reports-mismatch", (name, result)
        assert "index=0 %s" % name in failure_text(result), (name, result)
    print("PASS HID descriptor length refusals and report divergence labels")


def rejected(action, contains=None):
    try:
        action()
    except ValueError as error:
        if contains is not None and contains not in str(error):
            raise AssertionError("wrong refusal: %s" % error)
        return str(error)
    raise AssertionError("unsafe HID tooling input accepted")


class Surface:
    """An injected command surface with the broker's own preconditions.

    The broker registers a worker only on a held `watch` connection, accepts
    that `watch` only while the journal is prepared, and refuses `publish-hid`
    with no worker registered - which is what makes a worker's death restore
    the original. The canary is that worker, so the lease is taken here when it
    starts and given back when it is collected. Every step the runner takes is
    recorded in order, because the order is the thing being proven.
    """

    def __init__(self, **overrides):
        self.asked = []
        self.steps = []
        self.evidence = {}
        self.phase = "absent"
        self.worker = False
        # A fresh, randomly named evidence directory, as the real run has: the
        # provenance check accepts a reports file only inside this one.
        self.trial = Path(tempfile.mkdtemp(prefix="u3-hid-trial-"))
        TEMPORARIES.append(self.trial)
        self.state = dict(
            local={"canary": "a" * 64, "broker": "b" * 64},
            staged="a" * 64, reachable=True,
            status="OK phase=absent publication=enabled",
            function="absent-service", kit=0, canary=(0, b"reports written=12\n"),
            lease=True, capture=None, reports="reports-recorded", sequence=None,
            publish=None, usb=True, strict=(True, b"U2_V7_CURRENT ok\n"))
        self.state.update(overrides)

    def ask(self, command):
        self.asked.append(command)
        if command == "status":
            return self.state["status"]
        if command == "prepare":
            self.phase = "prepared"
            return "OK prepared"
        if command.startswith("publish-hid "):
            self.steps.append("publish-hid")
            if self.state["publish"] is not None:
                return self.state["publish"]
            if not self.worker or self.phase != "prepared":
                return "ERR rejected"
            self.phase = "published"
            return "OK published-additive"
        if command == "heal-status":
            return "OK last-heal none"
        if command.startswith("confirm "):
            self.phase = "absent"
            return "OK verified-and-cleared"
        raise AssertionError("unexpected broker command %r" % command)

    def start_canary(self):
        self.steps.append("start-canary")
        return {"collected": False}

    def await_lease(self, handle):
        """The canary's `watch`: refused unless the journal is prepared and free."""
        self.steps.append("await-lease")
        if not self.state["lease"] or self.worker or self.phase != "prepared":
            return False
        self.worker = True
        return True

    def collect_canary(self, handle):
        self.steps.append("collect-canary")
        handle["collected"] = True
        self.worker = False  # the lease goes back when the canary exits
        return self.state["canary"]

    def start_reports(self, stage):
        self.steps.append("start-reports")
        return {"outcome": self.state["reports"]}

    def collect_reports(self, handle):
        """The seizing reader's own file, written where this run can own it."""
        self.steps.append("collect-reports")
        outcome = handle["outcome"]
        if outcome in ("reports-recorded", "no-reports"):
            sequence = (CAPTURE["expected_reports"]() if self.state["sequence"] is None
                        else self.state["sequence"])
            if outcome == "no-reports":
                sequence = []
            (self.trial / "reports.txt").write_text(
                "".join(item.hex() + "\n" for item in sequence))
        path = RUNNER["captured_reports_path"](outcome, self.trial, "reports.txt")
        return outcome, "%s outcome=%s\n" % (REPORTS["PREFIX"], outcome), path

    def start_capture(self, stage, reports):
        self.steps.append("start-capture")
        return (stage, reports)

    def collect_capture(self, handle):
        self.steps.append("collect-capture")
        if self.state["capture"] is not None:
            return self.state["capture"]
        # The real comparator, on synthetic descriptors plus whatever the
        # capture step actually wrote: a pass can only come through that file.
        reports = (CAPTURE["parse_reports"](Path(handle[1]).read_text())
                   if handle[1] else None)
        result = evaluate(published(), reports=reports)
        return result["outcome"], CAPTURE["render"](result)

    def environment(self):
        return {
            "local_digests": lambda: self.state["local"],
            "staged_canary_digest": lambda: self.state["staged"],
            "ssh_reachable": lambda: self.state["reachable"],
            "ask": self.ask,
            "function_outcome": lambda name: self.state["function"],
            "restore_kit": lambda: self.state["kit"],
            "observe": lambda body: (body(), b'{"type":"ready"}\n'),
            "start_canary": self.start_canary,
            "await_lease": self.await_lease,
            "collect_canary": self.collect_canary,
            "start_reports": self.start_reports,
            "collect_reports": self.collect_reports,
            "start_capture": self.start_capture,
            "collect_capture": self.collect_capture,
            "usb_present": lambda: self.state["usb"],
            "strict": lambda phase: self.state["strict"],
            "syslog": lambda: None,
            "stop_syslog": lambda handle: None,
            "evidence": lambda name, data: self.evidence.__setitem__(name, data),
            "sleep": lambda seconds: None,
        }


def options(**overrides):
    values = {"broker": "v13", "function": "hidcanary", "controller": 4294967297,
              "canary_path": "/var/jb/usr/local/bin/hid-canary",
              "canary_sha256": "a" * 64, "broker_sha256": "b" * 64,
              "reports": None, "configuration": 5, "stock_interfaces": 3,
              "mode": "full"}
    values.update(overrides)
    return values


def runner():
    surface = Surface()
    summary = RUNNER["main"](options(), surface.environment())
    assert summary["confirmed"] is True, summary
    # The observed sequence the capture step recorded is what makes a pass
    # reachable at all, and it only matches because it is the canary's own.
    assert summary["hid_proof"] == "pass", summary
    assert summary["enumeration"] == "pass", summary
    assert surface.asked[:3] == ["status", "prepare", "publish-hid hidcanary"], surface.asked
    # The report reader is armed *before* the publication, which is the whole
    # safety argument: from the moment the interface appears until something
    # seizes it, the device's reports are real keyboard input to this Mac, so
    # the seize must not race the system binding the new keyboard. Everything
    # else runs while the lease is held and the function is live - the canary's
    # exit releases the lease and the interface goes away - and the descriptor
    # capture starts after the reports are collected, because the comparator
    # reads the observed sequence when it starts.
    assert surface.steps == ["start-canary", "await-lease", "start-reports",
                             "publish-hid", "collect-reports", "start-capture",
                             "collect-canary", "collect-capture"], surface.steps
    assert surface.steps.index("start-reports") < surface.steps.index("publish-hid"), (
        "the reader must be waiting before the keyboard can appear")
    live = surface.steps.index("collect-canary")
    for step in ("collect-reports", "start-capture"):
        assert surface.steps.index("publish-hid") < surface.steps.index(step) < live, step

    # The rule that matters most: the confirm argument is the digest of the
    # strict external check's own output and of nothing else.
    confirms = [item for item in surface.asked if item.startswith("confirm ")]
    assert confirms == ["confirm " + hashlib.sha256(b"U2_V7_CURRENT ok\n").hexdigest()], (
        confirms)
    assert "heal-status" in surface.asked
    # Different check output, different digest: the length alone proves nothing.
    other_output = b"U2_V7_CURRENT ok with different detail\n"
    other = Surface(strict=(True, other_output))
    assert RUNNER["main"](options(), other.environment())["confirmed"] is True
    other_confirms = [item for item in other.asked if item.startswith("confirm ")]
    assert other_confirms == ["confirm " + hashlib.sha256(other_output).hexdigest()], (
        other_confirms)
    assert other_confirms != confirms, other_confirms

    # A refused publication still collects the reader that was already armed:
    # one left running holds a device seized on this Mac.
    stillborn = Surface(publish="ERR rejected")
    rejected(lambda: RUNNER["main"](options(), stillborn.environment()),
             "additive publication")
    assert stillborn.steps == ["start-canary", "await-lease", "start-reports",
                               "publish-hid", "collect-reports",
                               "collect-canary"], stillborn.steps

    # No lease, no publication: the broker would refuse it anyway, and the
    # canary that was started is collected rather than left running.
    no_lease = Surface(lease=False)
    rejected(lambda: RUNNER["main"](options(), no_lease.environment()), "lease held")
    assert not [item for item in no_lease.asked if item.startswith("publish-hid")], (
        no_lease.asked)
    assert no_lease.steps == ["start-canary", "await-lease", "collect-canary"], (
        no_lease.steps)

    # An absent report sequence is reported as inconclusive and never as a HID
    # proof; only an observed, matching sequence passes.
    unobserved = Surface(capture=("reports-unobserved", "outcome=reports-unobserved\n"))
    quiet = RUNNER["main"](options(), unobserved.environment())
    assert quiet["enumeration"] == "reports-unobserved", quiet
    assert quiet["hid_proof"] == "inconclusive", quiet
    assert RUNNER["hid_proof"]("pass") == "pass"
    assert RUNNER["hid_proof"]("reports-unobserved") == "inconclusive"
    for outcome in ("not-enumerated", "interface-absent", "reports-mismatch",
                    "report-descriptor-mismatch", "rejected"):
        assert RUNNER["hid_proof"](outcome) == "fail", outcome

    # One wrong, missing or inserted report closes the only route to a pass,
    # and the trial says which it was rather than going quiet.
    expected = CAPTURE["expected_reports"]()
    for sequence, name in ((([bytes([1] * 8)] + expected[1:]), "wrong"),
                           (expected[1:], "missing"),
                           (([bytes([1] * 8)] + expected), "inserted")):
        divergent = Surface(sequence=sequence)
        result = RUNNER["main"](options(), divergent.environment())
        assert result["enumeration"] == "reports-mismatch", (name, result)
        assert result["hid_proof"] == "fail", (name, result)
        assert "index=0 " in divergent.evidence["enumeration.txt"].decode(), name

    # A permission refusal, an empty capture and a reader that bound nothing
    # are each their own non-pass, and none of them clears the journal: the
    # confirm is never sent, so the original stays journalled and healable.
    gaps = {}
    for outcome, label in (("permission-denied", "reports-permission-denied"),
                           ("no-reports", "reports-empty"),
                           ("no-matching-device", "reports-device-unbound"),
                           ("several-matching-devices", "reports-device-ambiguous"),
                           ("profile-unavailable", "reports-precondition-missing"),
                           ("seize-refused", "reports-capture-rejected")):
        gap = Surface(reports=outcome)
        gaps[label] = rejected(
            lambda gap=gap: RUNNER["main"](options(), gap.environment()), label)
        assert not [item for item in gap.asked if item.startswith("confirm ")], (
            outcome, gap.asked)
        assert "heal-status" in gap.asked, outcome
        assert RUNNER["reports_gap"](outcome) == label, outcome
    assert len(set(gaps.values())) == len(gaps), gaps
    # Armed before the publication, a reader that bound nothing means the
    # interface never appeared; that is not the same statement as a reader
    # that held the device and saw nothing arrive.
    assert RUNNER["REPORT_GAPS"]["no-matching-device"] != RUNNER["REPORT_GAPS"]["no-reports"]
    assert RUNNER["reports_gap"]("reports-recorded") is None
    assert len(set(RUNNER["REPORT_GAPS"].values())) == len(RUNNER["REPORT_GAPS"])
    assert "reports-recorded" not in RUNNER["REPORT_GAPS"], RUNNER["REPORT_GAPS"]
    # The permission refusal names the grant, where an operator reads it.
    assert "Input Monitoring" in RUNNER["__doc__"], "the runner must name the grant"

    # An observed-report file is accepted only where this trial wrote it, so no
    # operator-supplied file can manufacture a pass - and the file this run's
    # own capture step wrote is accepted through that same check.
    with tempfile.TemporaryDirectory(prefix="u3-hid-reports-") as temporary:
        trial = Path(temporary) / "trial"
        trial.mkdir()
        inside = trial / "reports.txt"
        inside.write_text(observed())
        outside = Path(temporary) / "reports.txt"
        outside.write_text(observed())
        assert RUNNER["checked_reports_path"](None, trial) is None
        assert RUNNER["checked_reports_path"](str(inside), trial) == str(inside.resolve())
        rejected(lambda: RUNNER["checked_reports_path"](str(outside), trial),
                 "evidence directory")
        rejected(lambda: RUNNER["checked_reports_path"](str(trial / "absent.txt"), trial),
                 "evidence directory")
        rejected(lambda: RUNNER["checked_reports_path"](
            str(trial / ".." / "reports.txt"), trial), "evidence directory")
        assert RUNNER["captured_reports_path"]("reports-recorded", trial,
                                               "reports.txt") == str(inside.resolve())
        # Only a recorded sequence yields a path at all.
        for outcome in ("no-reports", "permission-denied", "no-matching-device"):
            assert RUNNER["captured_reports_path"](outcome, trial, "reports.txt") is None
        rejected(lambda: RUNNER["captured_reports_path"]("reports-recorded", trial,
                                                         "absent.txt"), "evidence directory")
        rejected(lambda: RUNNER["captured_reports_path"]("reports-recorded", trial,
                                                         "../reports.txt"), "evidence directory")
    # The labels belong where an operator reads them.
    assert "reports-unobserved" in RUNNER["__doc__"], "the runner must state the limitation"

    # The one rule worth proving: a failing strict check never produces a confirm.
    failing = Surface(strict=(False, b"U2_V7_CURRENT rejected\n"))
    rejected(lambda: RUNNER["main"](options(), failing.environment()), "strict external check")
    assert not [item for item in failing.asked if item.startswith("confirm ")], failing.asked
    assert "heal-status" in failing.asked

    absent_usb = Surface(usb=False)
    rejected(lambda: RUNNER["main"](options(), absent_usb.environment()), "USB did not return")
    assert not [item for item in absent_usb.asked if item.startswith("confirm ")], absent_usb.asked

    messages = {}
    for key, surface, fragment in (
            ("kit", Surface(kit=1), "restore kit"),
            ("journal", Surface(status="OK phase=prepared publication=enabled"), "journal"),
            ("idle", Surface(status="OK phase=absent publication=disabled"), "not idle"),
            ("publishing", Surface(function="present-not-opened"), "already publishing"),
            ("digest", Surface(local={"canary": "c" * 64, "broker": "b" * 64}), "canary binary"),
            ("broker-digest", Surface(local={"canary": "a" * 64, "broker": None}), "broker binary"),
            ("staged", Surface(staged="d" * 64), "staged canary"),
            ("ssh", Surface(reachable=False), "Wi-Fi")):
        messages[key] = rejected(
            lambda surface=surface: RUNNER["main"](options(), surface.environment()), fragment)
        assert not [item for item in surface.asked
                    if item.startswith(("prepare", "publish-hid", "confirm"))], (key, surface.asked)
    assert len(set(messages.values())) == len(messages), messages
    print("PASS HID trial runner refusals and proof-gated confirm")


FULL_STEPS = ["start-canary", "await-lease", "start-reports", "publish-hid",
              "collect-reports", "start-capture", "collect-canary", "collect-capture"]


def gate_modes():
    """The staged gates: the runner selects the canary's mode and judges it right.

    Two of the modes write no reports by design, so a missing observed sequence
    is their expected outcome and not a capture gap - but neither is it a HID
    result, so neither may confirm the journal. The reader is still armed before
    the publication and still collected on every path: one left running holds a
    device seized on this Mac.
    """
    assert RUNNER["MODES"] == ("full", "open-only", "configure-only"), RUNNER["MODES"]
    assert RUNNER["mode_writes_reports"]("full") is True
    for mode in ("open-only", "configure-only"):
        assert RUNNER["mode_writes_reports"](mode) is False, mode

    # A descriptor comparison can still pass in a gate, and reading that as a
    # keyboard proof is the conflation the gates exist to prevent.
    assert RUNNER["mode_hid_proof"]("full", "pass") == "pass"
    for mode in ("open-only", "configure-only"):
        for outcome in ("pass", "reports-unobserved", "reports-mismatch"):
            assert RUNNER["mode_hid_proof"](mode, outcome) == "not-attempted", (mode, outcome)

    # The mode reaches the canary as its own argument, and the full run's
    # command line is byte-for-byte what it was before there were modes.
    assert RUNNER["canary_arguments"](options()) == (
        "--function hidcanary --controller 4294967297")
    for mode in ("open-only", "configure-only"):
        assert RUNNER["canary_arguments"](options(mode=mode)) == (
            "--function hidcanary --controller 4294967297 --mode " + mode), mode

    # Defaulted, so an existing invocation selects the full run by saying nothing.
    argv = ["--broker=v13", "--function=hidcanary", "--controller=4294967297",
            "--canary-path=/var/jb/usr/local/bin/hid-canary",
            "--canary-sha256=" + "a" * 64, "--broker-sha256=" + "b" * 64,
            "--configuration=5", "--stock-interfaces=3"]
    assert RUNNER["parse"](argv)["mode"] == "full", "no mode means the full run"
    for mode in ("open-only", "configure-only"):
        assert RUNNER["parse"](argv + ["--mode=" + mode])["mode"] == mode, mode
    rejected(lambda: RUNNER["parse"](argv + ["--mode=openonly"]), "mode")

    for mode in ("open-only", "configure-only"):
        # Whatever the reader saw - it held the device and nothing arrived, or
        # it bound nothing at all - a mode that writes no reports is reported
        # as that mode's own result, never as one of the report-gap labels.
        for reports in ("no-reports", "no-matching-device", "reports-recorded"):
            gate = Surface(reports=reports)
            message = rejected(
                lambda gate=gate: RUNNER["main"](options(mode=mode), gate.environment()),
                "writes no reports")
            assert mode in message, (mode, reports, message)
            for label in RUNNER["REPORT_GAPS"].values():
                assert label not in message, (mode, reports, label, message)
            # Not a HID result, so the journal stays journalled and healable.
            assert not [item for item in gate.asked if item.startswith("confirm ")], (
                mode, reports, gate.asked)
            assert "heal-status" in gate.asked, (mode, reports)
            # The reader is still armed before the publication and still
            # collected: the step order does not change with the mode.
            assert gate.steps == FULL_STEPS, (mode, reports, gate.steps)
            assert gate.steps.index("start-reports") < gate.steps.index("publish-hid"), (
                mode, reports)

    # The full run is unchanged: it still reaches the proof-gated confirm.
    full = Surface()
    assert RUNNER["main"](options(mode="full"), full.environment())["confirmed"] is True
    assert full.steps == FULL_STEPS, full.steps
    print("PASS HID trial runner gate modes, step order and reportless outcomes")


def compiled(temporary):
    binary = Path(temporary) / "u2-hid-report-reader"
    build = subprocess.run(
        ["/usr/bin/xcrun", "swiftc", str(READER), "-o", str(binary)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600,
        env=dict(os.environ, CLANG_MODULE_CACHE_PATH=str(Path(temporary) / "clang"),
                 SWIFT_MODULE_CACHE_PATH=str(Path(temporary) / "swift")))
    assert build.returncode == 0, build.stderr.decode("utf-8", "replace")
    assert binary.is_file()
    return binary


def reader():
    """The reader compiles, refuses what it cannot seize, and never falls back."""
    source = READER.read_text()
    # The whole point of the tool: reports are seized away from this Mac's HID
    # stack, and there is no passive fallback to fall back to.
    assert "kIOHIDOptionsTypeSeizeDevice" in source
    assert "kIOHIDOptionsTypeNone" in source
    # Nothing that reads an identifier is referenced at all, so none can reach
    # the summary or the saved file; the reader's own output is checked below.
    for forbidden in ("kIOHIDSerialNumberKey", "SerialNumber", "UniqueDeviceID",
                      "kUSBSerialNumberString", "PairRecord"):
        assert forbidden not in source, forbidden
    # Matched by the boot keyboard's usage as well as the learned IDs, so the
    # operator's own keyboard cannot be bound by accident.
    for key in ("kIOHIDPrimaryUsagePageKey", "kIOHIDPrimaryUsageKey",
                "kIOHIDVendorIDKey", "kIOHIDProductIDKey"):
        assert key in source, key
    assert not re.search(r"0x05[aA][cC]", source), "no device-specific identifier may be compiled in"
    # The grant is tied to this binary's bytes, so the refusal says that a
    # changed source needs the grant again rather than leaving it to be found.
    assert "after-source-change=grant-it-again" in source, source[:0]

    with tempfile.TemporaryDirectory(prefix="u3-hid-reader-") as temporary:
        binary = compiled(temporary)
        self_test = subprocess.run([str(binary), "--self-test"], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=120)
        assert self_test.returncode == 0, self_test.stdout + self_test.stderr
        usage = subprocess.run([str(binary)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=60)
        assert usage.returncode == 64, usage.returncode
        # Bound to nothing: no attached device carries this pair, so the reader
        # must say so and stop at its deadline rather than seize anything.
        out = Path(temporary) / "reports.txt"
        bound = subprocess.run([str(binary), "0x%04x" % UNBOUND_VENDOR,
                                "0x%04x" % UNBOUND_PRODUCT, "1", "4", str(out)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        text = bound.stdout.decode("ascii", "replace")
        label = REPORTS["READER_OUTCOMES"].get(bound.returncode)
        # Either outcome is honest with no device: nothing matched, or this Mac
        # has not granted the reader the permission it needs. Never a pass.
        assert label in ("no-matching-device", "permission-denied"), (bound.returncode, text)
        assert "outcome=%s" % label in text, text
        assert "outcome=reports-recorded" not in text, text
        assert not out.exists(), "nothing was seized, so nothing may be written"
        if label == "permission-denied":
            assert "input-monitoring" in text, text
        CAPTURE["assert_identifier_free"](text)
        for secret in (FAKE_SERIAL, FAKE_UDID, "SerialNumber", "UniqueDeviceID"):
            assert secret not in text, secret

    # Each outcome is its own, and none of them shares the success code: a
    # tooling fault read as a hardware result would be a false negative.
    codes = REPORTS["READER_OUTCOMES"]
    assert len(set(codes.values())) == len(codes), codes
    assert codes[0] == "reports-recorded"
    for outcome in ("no-reports", "permission-denied", "no-matching-device",
                    "several-matching-devices", "seize-refused"):
        assert outcome in codes.values(), outcome
    exits = REPORTS["EXIT_CODES"]
    assert len(set(exits.values())) == len(exits), exits
    assert exits["reports-recorded"] == 0
    assert all(code != 0 for name, code in exits.items() if name != "reports-recorded")
    assert set(codes.values()) | {"profile-unavailable"} == set(exits), (codes, exits)
    print("PASS HID report reader compiles, refuses what it cannot seize, one outcome each")


def report_capture():
    """The wrapper takes the IDs from the learned profile and never hangs."""
    assert REPORTS["identifiers"]({"vendor": VENDOR, "product": PRODUCT}) == (VENDOR, PRODUCT)
    calls = []

    def unavailable():
        calls.append("fetch")
        raise ValueError("broker has no learned device profile")

    # No device, so no profile: a missing precondition, reported and not waited on.
    assert REPORTS["identifiers"]({"vendor": None, "product": None},
                                 fetch=unavailable) is None
    assert calls == ["fetch"], calls

    def learned():
        return {"schemaVersion": 3, "usbVendorID": VENDOR, "usbProductID": PRODUCT,
                "functions": ["stock"]}

    assert REPORTS["identifiers"]({"vendor": None, "product": None},
                                 fetch=learned) == (VENDOR, PRODUCT)

    with tempfile.TemporaryDirectory(prefix="u3-hid-capture-") as temporary:
        result = subprocess.run(
            [sys.executable, str(HOST / "capture-u2-hid-reports.py"),
             "--out-dir=%s" % temporary, "--vendor=0x%04x" % UNBOUND_VENDOR,
             "--product=0x%04x" % UNBOUND_PRODUCT, "--deadline=1", "--max-reports=4"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900)
        text = result.stdout.decode("ascii", "replace")
        match = re.search(r"outcome=([a-z-]+)", text)
        assert match, text
        label = match.group(1)
        assert label in ("no-matching-device", "permission-denied"), text
        assert result.returncode == REPORTS["EXIT_CODES"][label], (result.returncode, text)
        assert "outcome=reports-recorded" not in text, text
        assert not list(Path(temporary).iterdir()), "nothing was seized, so no reports file"
        CAPTURE["assert_identifier_free"](text)
        # The binary the operator has to grant lives at a stable path in the
        # ignored build tree, not in a temporary directory that gets reaped,
        # and its name carries the source digest so a changed source is a
        # visibly different artifact.
        built = re.search(r"reader=(\S+)", text)
        assert built, text
        binary = Path(built.group(1))
        assert binary.parent == REPORTS["BUILD"], binary
        assert binary.is_file() and binary.name.startswith("u2-hid-report-reader-"), binary
        digest = hashlib.sha256(READER.read_bytes()).hexdigest()
        assert binary.name.endswith(digest[:16]), (binary, digest[:16])
        assert REPORTS["reader_binary"]() == binary, "a second call reuses the same binary"
    print("PASS HID report capture wrapper outcomes and missing precondition")


if __name__ == "__main__":
    try:
        comparator()
        descriptors()
        reader()
        report_capture()
        runner()
        gate_modes()
    finally:
        for directory in TEMPORARIES:
            shutil.rmtree(directory, ignore_errors=True)
