#!/usr/bin/env python3
"""Prove from this Mac whether the appended gadget function enumerated as a USB boot keyboard.

Effect: read-only. It takes the host's own view of the device - the raw
configuration descriptors from the pinned read-only helper, and the report
descriptor macOS kept after it asked the device for one - and compares both
against the golden boot-keyboard fixtures: interface class 3 / subclass 1 /
protocol 1, exactly one interrupt-IN endpoint of 8 bytes at interval 10, the
9-byte HID descriptor whose trailing length is derived from the report
descriptor actually appended, and that 65-byte report descriptor byte for byte.
An observed report sequence, when one was recorded, is compared against the
press/release sequence the canary types.

Every outcome is separately labelled and only `pass` is a pass. A host that
does not enumerate the device is `not-enumerated`: it is neither a pass nor a
descriptor failure, because reading it as either would turn "we could not see"
into "HID works on this device", which is the one conclusion this tool exists
to establish honestly.

The same argument applies one step earlier, to whether this capture was
positioned to see anything at all. Publishing a changed description takes the
device off bus for a measured 29 to 72 seconds while the broker's lease ceiling
is 30, and the healer's remedy re-publishes the journalled original - so a
capture that reads late is reading a *stock* device and would report its
missing interface as a descriptor failure. It therefore refuses to emit a pass
or any descriptor verdict unless the caller hands it a witness that the
publication was live: what the broker said, when it said it, and the lease that
bounds how long that word can be relied on. The capture stamps its own read
time and compares the two; a read it cannot place inside that window is
`publication-liveness-unestablished`, its own outcome and its own exit code, so
a void observation can never again be read as a negative result.

macOS exposes no control-transfer log, so the recorded HID control requests are
only those whose result survives in the registry; the rest are listed as
expected and not exposed. A bus-level capture on another host is the complete
record and remains the escalation if this evidence proves too thin.

No serial number, unique device ID or UDID is printed or saved: identifier-
bearing registry lines are dropped before parsing and the rendered report is
checked again before it is written.

Usage:
  --configuration N --stock-interfaces N [--vendor 0xNNNN --product 0xNNNN]
  [--raw-configs FILE] [--ioreg FILE] [--reports FILE] [--out FILE]
  [--publication-state TEXT --publication-observed-at EPOCH
   --publication-max-age SECONDS]
Exit: 0 pass, 2 a labelled failure, 3 not-enumerated,
      4 publication liveness unestablished, 1 refused.
"""

import hashlib
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time

HOST = Path(__file__).resolve().parent
RAW = runpy.run_path(str(HOST / "capture-u2-raw-configs.py"))

# USB boot keyboard, and the one endpoint a boot keyboard has.
INTERFACE_TRIPLE = (3, 1, 1)
ENDPOINT_TRANSFER_TYPE = 3   # interrupt
ENDPOINT_MAX_PACKET = 8
ENDPOINT_INTERVAL = 10
# Shortest valid length by descriptor type (interface, endpoint); the checks
# below index into these fields, so a shorter one must be refused up front.
DESCRIPTOR_MINIMUM = {4: 9, 5: 7}
# bLength, HID, bcdHID 1.11, country 0, one descriptor, type 0x22, then the
# report descriptor's length little-endian: 65, not the example's 93.
HID_DESCRIPTOR = bytes.fromhex("092111010001224100")
REPORT_DESCRIPTOR = bytes.fromhex(
    "05010906A101050719E029E7150025017501950881029501750881019503750"
    "1050819012903910295057501910195067508150026FF00050719002AFF0081"
    "00C0")
# The canary's fixed string, character by character with its keycode and
# whether it is typed shifted. Kept beside the canary's own table so a
# divergence is a test failure here rather than a silent mismatch on a device.
KEYSTROKES = (("M", 0x10, True), ("A", 0x04, True), ("C", 0x06, True),
              ("2", 0x1F, False), ("J", 0x0D, True), ("B", 0x05, True))
LEFT_SHIFT = 0x02
REPORT_LENGTH = 8

# A read this capture cannot place inside a live publication. Its own outcome,
# distinct from every other, because it is a statement about the observation
# and not about the device: the descriptors it read may belong to the stock
# description the healer put back.
PUBLICATION_UNESTABLISHED = "publication-liveness-unestablished"
VOID_EXIT = 4
# The fragment of the broker's status line that says an additive publication is
# live. Nothing else is accepted as a witness.
LIVE_PHASE = "phase=published"
# Worst outcome first: the label printed is the first that applies. The void
# observation is first because an unpositioned read cannot support any of the
# others - not even `not-enumerated`, which would claim the host saw nothing
# when in truth this capture does not know what it was looking at.
OUTCOMES = (PUBLICATION_UNESTABLISHED,
            "not-enumerated", "interface-absent", "interface-mismatch", "endpoint-mismatch",
            "hid-descriptor-mismatch", "report-descriptor-missing", "report-descriptor-mismatch",
            "reports-mismatch", "reports-unobserved", "pass")
# Registry keys that carry a device identifier. Their lines never reach the
# parser, so no identifier can reach the output or a saved artifact.
IDENTIFIER_KEYS = ("serial", "udid", "uniquedeviceid", "uniqueid", "unique device id")
IDENTIFIER_SHAPES = (re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}\b"),
                     re.compile(r"\b[0-9A-Fa-f]{40}\b"),
                     re.compile(r"\b[0-9A-Fa-f]{24,25}\b"))
PREFIX = "U2_HID_ENUM"
NODE = re.compile(r"^\s*\+-o ", re.MULTILINE)
PROPERTY = re.compile(r'^\s*"([^"]+)" = (.+)$')


def assert_identifier_free(text):
    lowered = text.lower()
    for key in IDENTIFIER_KEYS:
        if key in lowered:
            raise ValueError("identifier key in capture output")
    for shape in IDENTIFIER_SHAPES:
        if shape.search(text):
            raise ValueError("identifier-shaped token in capture output")


def scrubbed(text):
    """Drop every identifier-bearing registry line before anything parses it."""
    return "\n".join(line for line in text.splitlines()
                     if not any(key in line.lower() for key in IDENTIFIER_KEYS))


def configurations(envelope):
    """Split the helper's validated envelope into {configuration number: raw bytes}."""
    RAW["parse"](envelope)  # shared framing and header validation
    count = envelope[8]
    offset = 9
    result = {}
    for _ in range(count):
        length = int.from_bytes(envelope[offset:offset + 2], "little")
        offset += 2
        raw = envelope[offset:offset + length]
        offset += length
        result[raw[5]] = raw
    return result


def interface_groups(raw):
    """One group per interface descriptor: the interface and what follows it."""
    groups = []
    position = 9
    while position < len(raw):
        size = raw[position]
        # A device-supplied length is untrusted: a header-less or overrunning
        # descriptor is reported with its offset, never indexed past or looped on.
        if size < 2 or position + size > len(raw):
            raise ValueError("malformed-descriptor offset=%d length=%d buffer=%d"
                             % (position, size, len(raw)))
        descriptor = raw[position:position + size]
        minimum = DESCRIPTOR_MINIMUM.get(descriptor[1], 2)
        if size < minimum:
            raise ValueError("malformed-descriptor offset=%d type=%d length=%d minimum=%d"
                             % (position, descriptor[1], size, minimum))
        if descriptor[1] == 4:
            groups.append({"interface": descriptor, "endpoints": [], "class": [], "other": []})
        elif groups:
            key = {5: "endpoints", 0x21: "class"}.get(descriptor[1], "other")
            groups[-1][key].append(descriptor)
        position += size
    return groups


def check_interface(descriptor):
    triple = tuple(descriptor[5:8])
    if triple != INTERFACE_TRIPLE:
        return ["interface class/subclass/protocol=%d/%d/%d expected=%d/%d/%d"
                % (*triple, *INTERFACE_TRIPLE)]
    return []


def check_endpoints(endpoints):
    if len(endpoints) != 1:
        return ["endpoint count=%d expected=1" % len(endpoints)]
    descriptor = endpoints[0]
    failures = []
    if not descriptor[2] & 0x80:
        failures.append("endpoint direction=out expected=in")
    if descriptor[3] & 0x03 != ENDPOINT_TRANSFER_TYPE:
        failures.append("endpoint transfer-type=%d expected=%d"
                        % (descriptor[3] & 0x03, ENDPOINT_TRANSFER_TYPE))
    size = int.from_bytes(descriptor[4:6], "little")
    if size != ENDPOINT_MAX_PACKET:
        failures.append("endpoint max-packet-size=%d expected=%d" % (size, ENDPOINT_MAX_PACKET))
    if descriptor[6] != ENDPOINT_INTERVAL:
        failures.append("endpoint interval=%d expected=%d" % (descriptor[6], ENDPOINT_INTERVAL))
    return failures


def compare_bytes(label, observed, expected):
    if len(observed) != len(expected):
        return ["%s length=%d expected=%d" % (label, len(observed), len(expected))]
    for offset, (left, right) in enumerate(zip(observed, expected)):
        if left != right:
            return ["%s offset=%d observed=0x%02x expected=0x%02x" % (label, offset, left, right)]
    return []


def report_descriptor(text, vendor, product):
    """The report descriptor macOS kept for this device, or None if it has none.

    macOS only holds one because it asked the device for it, so its presence is
    the single piece of direct control-request evidence this host exposes.
    """
    for node in re.split(NODE, scrubbed(text))[1:]:
        fields = {}
        for line in node.splitlines():
            match = PROPERTY.match(line)
            if match:
                fields[match.group(1)] = match.group(2).strip()
        if (fields.get("VendorID") != str(vendor) or fields.get("ProductID") != str(product) or
                fields.get("PrimaryUsagePage") != "1" or fields.get("PrimaryUsage") != "6"):
            continue
        value = fields.get("ReportDescriptor", "")
        digits = re.fullmatch(r"<([0-9A-Fa-f]*)>", value)
        if not digits or len(digits.group(1)) % 2:
            return None
        return bytes.fromhex(digits.group(1))
    return None


def expected_reports():
    """A press and its release for every character the canary types."""
    sequence = []
    for _, keycode, shifted in KEYSTROKES:
        sequence.append(bytes((LEFT_SHIFT if shifted else 0, 0, keycode, 0, 0, 0, 0, 0)))
        sequence.append(bytes(REPORT_LENGTH))
    return sequence


def parse_reports(text):
    reports = []
    for line in text.splitlines():
        stripped = re.sub(r"[\s:]", "", line.split("#", 1)[0])
        if not stripped:
            continue
        if not re.fullmatch(r"[0-9A-Fa-f]{%d}" % (REPORT_LENGTH * 2), stripped):
            raise ValueError("observed report is not %d hex bytes" % REPORT_LENGTH)
        reports.append(bytes.fromhex(stripped))
    return reports


def compare_reports(observed, expected):
    """The first divergence by index, named as a wrong, extra or missing report."""
    for index in range(min(len(observed), len(expected))):
        if observed[index] != expected[index]:
            kind = "wrong"
            if observed[index:index + 1] == expected[index + 1:index + 2]:
                kind = "missing"
            elif observed[index + 1:index + 2] == expected[index:index + 1]:
                kind = "extra"
            return ["report index=%d %s observed=%s expected=%s"
                    % (index, kind, observed[index].hex(), expected[index].hex())]
    if len(observed) > len(expected):
        return ["report index=%d extra observed=%s beyond expected=%d"
                % (len(expected), observed[len(expected)].hex(), len(expected))]
    if len(observed) < len(expected):
        return ["report index=%d missing expected=%s observed=%d"
                % (len(observed), expected[len(observed)].hex(), len(observed))]
    return []


def witness_token(state):
    """The broker's status line as one printable token, with no identifier in it."""
    return re.sub(r"[^A-Za-z0-9=._-]+", "_", state)[:96]


def publication_liveness(state, observed_at, max_age, read_at):
    """Whether this read can be placed inside a live publication.

    The caller knows what the broker said and when; this capture knows when it
    read. Liveness is established only when the broker's word says a
    publication was live, was given before the read, and is no older than the
    lease that bounds it - the lease, not a fixed deadline, because the lease
    is the only thing that keeps the publication from being healed away. Each
    way of failing to be positioned keeps its own reason, so an operator reads
    why rather than guessing.
    """
    answer = {"established": False, "state": state, "observed_at": observed_at,
              "max_age": max_age, "read_at": read_at, "age": None}
    if state is None or observed_at is None or max_age is None:
        answer["reason"] = "no-publication-witness-supplied"
        return answer
    age = read_at - observed_at
    answer["age"] = age
    if LIVE_PHASE not in state:
        answer["reason"] = "witness-state-is-not-a-live-publication"
        return answer
    if age < 0:
        answer["reason"] = "witness-observed-after-the-read"
        return answer
    if age > max_age:
        answer["reason"] = ("witness-older-than-the-lease age=%.1fs lease=%.1fs"
                            % (age, max_age))
        return answer
    answer["established"] = True
    answer["reason"] = "witness-inside-the-lease"
    return answer


def control_requests(enumerated, descriptor_present):
    """What the host must have asked, split into observed and not exposed.

    `enumerated is None` is the void observation: this capture cannot say what
    the host asked of which description, so every entry says so. Reporting
    "not-observed" there would be a claim about the device.
    """
    if enumerated is None:
        return [(name, "not-established") for name, _ in
                control_requests(False, False)]
    observed = "observed" if enumerated else "not-observed"
    return [("get-descriptor configuration", observed),
            ("set-configuration", observed),
            ("get-descriptor hid-report", "observed" if descriptor_present else "not-observed"),
            # macOS keeps no record of these that a host tool can read.
            ("set-idle", "expected-not-exposed"),
            ("set-protocol boot", "expected-not-exposed"),
            ("get-report", "expected-not-exposed")]


def evaluate(envelope, stock_interfaces, ioreg_text, observed, vendor, product,
             configuration, liveness):
    """One labelled outcome plus every failure line, from host-side evidence only."""
    if not liveness["established"]:
        # Refused before anything is compared: these descriptors cannot be
        # attributed to the publication, so neither a pass nor a descriptor
        # failure may be claimed from them. Nothing below runs, so no
        # descriptor label can leak into a void observation's report.
        return {"outcome": PUBLICATION_UNESTABLISHED, "liveness": liveness,
                "failures": ["the publication this capture measured could not be shown "
                             "live when it read (%s)" % liveness["reason"]],
                "control_requests": control_requests(None, None), "interfaces": None,
                "reports": 0 if observed is None else len(observed), "evidence": "void"}
    if envelope is None:
        return {"outcome": "not-enumerated", "failures": ["host enumerates no device"],
                "control_requests": control_requests(False, False), "interfaces": None,
                "reports": 0, "evidence": "none", "liveness": liveness}
    raw = configurations(envelope).get(configuration)
    if raw is None:
        raise ValueError("host-selected configuration absent from the capture")
    groups = interface_groups(raw)
    failures = []
    labels = []
    if len(groups) <= stock_interfaces:
        labels.append("interface-absent")
        failures.append("interfaces=%d expected=%d with one appended"
                        % (len(groups), stock_interfaces + 1))
        descriptor = None
    else:
        # The function is appended last so stock interface numbers do not shift.
        appended = groups[-1]
        for label, lines in (("interface-mismatch", check_interface(appended["interface"])),
                             ("endpoint-mismatch", check_endpoints(appended["endpoints"])),
                             ("hid-descriptor-mismatch", compare_bytes(
                                 "hid descriptor",
                                 appended["class"][0] if appended["class"] else b"",
                                 HID_DESCRIPTOR))):
            if lines:
                labels.append(label)
                failures.extend(lines)
        descriptor = report_descriptor(ioreg_text, vendor, product)
        if descriptor is None:
            labels.append("report-descriptor-missing")
            failures.append("macOS holds no report descriptor for this device")
        else:
            lines = compare_bytes("report descriptor", descriptor, REPORT_DESCRIPTOR)
            if lines:
                labels.append("report-descriptor-mismatch")
                failures.extend(lines)
    if observed is None:
        labels.append("reports-unobserved")
        failures.append("no host-side report sequence was recorded")
    else:
        lines = compare_reports(observed, expected_reports())
        if lines:
            labels.append("reports-mismatch")
            failures.extend(lines)
    outcome = next((label for label in OUTCOMES if label in labels), "pass")
    return {"outcome": outcome, "failures": failures, "liveness": liveness,
            "control_requests": control_requests(True, descriptor is not None),
            "interfaces": len(groups), "reports": 0 if observed is None else len(observed),
            "evidence": hashlib.sha256(envelope).hexdigest()}


def render(result):
    # Stamped with the time of the read and the state this capture believes was
    # live: a verdict that cannot say what it measured, or when, is not
    # evidence - which is precisely how a capture of a healed stock device came
    # to be filed as a descriptor failure.
    live = result["liveness"]
    lines = ["%s outcome=%s interfaces=%s reports=%s" % (
        PREFIX, result["outcome"], result["interfaces"], result["reports"])]
    lines.append("%s read-at=%s read-at-epoch=%d" % (
        PREFIX, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(live["read_at"])),
        int(live["read_at"])))
    lines.append("%s publication-witness live=%s state=%s observed-at-epoch=%s "
                 "age-seconds=%s lease-seconds=%s reason=%s"
                 % (PREFIX, "yes" if live["established"] else "no",
                    "none" if live["state"] is None else witness_token(live["state"]),
                    "none" if live["observed_at"] is None else int(live["observed_at"]),
                    "none" if live["age"] is None else "%.1f" % live["age"],
                    "none" if live["max_age"] is None else "%.1f" % live["max_age"],
                    witness_token(live["reason"])))
    for name, status in result["control_requests"]:
        lines.append("%s control-request %s=%s" % (PREFIX, name, status))
    lines.append("%s control-request-evidence=registry-only "
                 "note=macOS-exposes-no-control-transfer-log" % PREFIX)
    for failure in result["failures"]:
        lines.append("%s failure %s" % (PREFIX, failure))
    lines.append("%s descriptor-evidence-sha256=%s" % (PREFIX, result["evidence"]))
    return "\n".join(lines) + "\n"


def host_registry():
    result = subprocess.run(["/usr/sbin/ioreg", "-r", "-c", "IOHIDDevice", "-l", "-w0"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    if result.returncode or len(result.stdout) > 16 * 1024 * 1024:
        raise ValueError("HID registry query failed")
    return result.stdout.decode("utf-8", "replace")


def live_capture():
    """The raw configuration descriptors, or None when this host enumerates nothing."""
    try:
        return RAW["capture"]()[0]
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def parse(argv):
    options = {"reports": None, "out": None, "raw-configs": None, "ioreg": None,
               "publication-state": None, "publication-observed-at": None,
               "publication-max-age": None}
    for item in argv:
        name, _, value = item.partition("=")
        if not name.startswith("--") or not value:
            raise ValueError("usage: see the module docstring")
        options[name[2:]] = value
    for name in ("configuration", "stock-interfaces"):
        if name not in options:
            raise ValueError("--%s is required" % name)
        options[name] = int(options[name], 0)
    for name in ("vendor", "product"):
        options[name] = int(options[name], 0) if name in options else None
    # The witness is optional on the command line and absent is a refusal, not
    # a default pass: a caller that cannot say the publication was live gets
    # the void outcome rather than a verdict.
    for name in ("publication-observed-at", "publication-max-age"):
        if options[name] is not None:
            options[name] = float(options[name])
            if options[name] <= 0:
                raise ValueError("--%s must be positive" % name)
    return options


def main(argv):
    options = parse(argv)
    envelope = (Path(options["raw-configs"]).read_bytes() if options["raw-configs"]
                else live_capture())
    # Taken the moment the descriptors were read, not when the report is
    # rendered: the read is the thing whose position has to be established.
    read_at = time.time()
    text = (Path(options["ioreg"]).read_text(errors="replace") if options["ioreg"]
            else (host_registry() if envelope is not None else ""))
    vendor, product = options["vendor"], options["product"]
    # Only needed to pick the device's HID node; with nothing enumerated there is
    # no node to pick, and asking the device for its profile would just hang.
    if envelope is not None and (vendor is None or product is None):
        # Device-agnostic: the broker's learned profile, never a compiled-in ID.
        profile = runpy.run_path(str(HOST / "u2_broker_profile.py"))["fetch"]()
        vendor, product = profile["usbVendorID"], profile["usbProductID"]
    observed = (parse_reports(Path(options["reports"]).read_text()) if options["reports"]
                else None)
    liveness = publication_liveness(options["publication-state"],
                                    options["publication-observed-at"],
                                    options["publication-max-age"], read_at)
    result = evaluate(envelope, options["stock-interfaces"], text, observed,
                      vendor, product, options["configuration"], liveness)
    report = render(result)
    assert_identifier_free(report)
    if options["out"]:
        runpy.run_path(str(HOST / "u2_trial_support.py"))["private_file"](
            Path(options["out"]), report.encode("ascii"))
    print(report, end="")
    if result["outcome"] == "pass":
        return 0
    if result["outcome"] == PUBLICATION_UNESTABLISHED:
        return VOID_EXIT
    return 3 if result["outcome"] == "not-enumerated" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        print("%s rejected (%s)" % (PREFIX, error))
        raise SystemExit(1)
