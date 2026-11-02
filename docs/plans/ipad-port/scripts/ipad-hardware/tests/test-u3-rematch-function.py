#!/usr/bin/env python3
"""Mac-only fixtures for the driverless-audio-function inspector and its probe gate.

No device, no network, no IOKit call: every census here is hand-built, and only
the pure parsing, classification and guard functions of the payload and its host
wrapper are exercised. The two rules that matter most are observable without a
device: the payload refuses to probe anything but a single driverless audio nub
on a configured controller, and the host classifier never calls a missing USB
function nub an audio-only difference. The payload digest the wrapper pins is
compared with the payload on disk, so the pin cannot drift unnoticed.
"""

from pathlib import Path
import hashlib
import runpy


ROOT = Path(__file__).resolve().parents[6]
SCRIPTS = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware"
PAYLOAD = SCRIPTS / "device/u3-rematch-driverless-function.py"
DEVICE = runpy.run_path(str(PAYLOAD))
WRAPPER = runpy.run_path(str(SCRIPTS / "host/rematch-u2-driverless-function-wifi.py"))

CONFIGURED = ("configured", "yes", 5)
# The 16 functions of the reference iPad, with the child each one carries when
# healthy; `None` marks a function whose client is host- or daemon-dependent.
HEALTHY = (
    ("PTP", "IOUSBDeviceInterfaceUserClient", "ptpd"),
    ("USBAudioControl", "AppleUSBMike", ""),
    ("USBAudioStreaming", "AppleUSBMike", ""),
    ("IapOverUsbHid", "IOAccessoryPortUSB", ""),
    ("AppleUSBMux", "AppleUSBDeviceMux", ""),
    ("AppleUSBEthernet", "AppleUSBEthernetDevice", ""),
    ("AppleUSBNCMControl", "AppleUSBDeviceNCMControl", ""),
    ("AppleUSBNCMData", "AppleUSBDeviceNCMData", ""),
    ("AppleUSBNCMControlAux", "AppleUSBDeviceNCMControl", ""),
    ("AppleUSBNCMDataAux", "AppleUSBDeviceNCMData", ""),
    ("Valeria", "IOUSBDeviceInterfaceUserClient", "audiomxd"),
    ("USBAudio2Control", "AppleUSBDeviceAudioController", ""),
    ("USBAudio2StreamIN", "AppleUSBDeviceAudioController", ""),
    ("USBAudio2StreamOUT", "AppleUSBDeviceAudioController", ""),
    ("IDAMInterface", "AppleIDAMInterface", ""),
    ("AppleUSBNCMControlDirect", "AppleUSBDeviceNCMControl", ""),
)


def rejected(action, label):
    try:
        action()
    except ValueError:
        return
    raise AssertionError("accepted " + label)


def census(functions, deeper=()):
    """Build a census in the exact shape of device/u2-readonly-xdci-function-census.py."""
    lines = ["U2_XDCI_NODE i=0 parent=-1 depth=0 class=AppleT8112USBXDCI busy=0"]
    index = 1
    children = []
    for function, child, creator in functions:
        lines.append("U2_XDCI_NODE i=%d parent=0 depth=1 class=IOUSBDeviceInterface "
                     "busy=0 function=%s" % (index, function))
        if child:
            children.append((index, child, creator))
        index += 1
    for parent, child, creator in children:
        lines.append("U2_XDCI_NODE i=%d parent=%d depth=2 class=%s busy=0%s" %
                     (index, parent, child, (" creator=" + creator) if creator else ""))
        index += 1
    for depth, cls, creator in deeper:
        lines.append("U2_XDCI_NODE i=%d parent=1 depth=%d class=%s busy=0%s" %
                     (index, depth, cls, (" creator=" + creator) if creator else ""))
        index += 1
    return ("U2_XDCI_FUNCTIONS nodes=%d\n" % len(lines) + "\n".join(lines) +
            "\nU2_XDCI_FUNCTIONS done\n")


def without(functions, name, drop_child_only=False):
    kept = []
    for entry in functions:
        if entry[0] != name:
            kept.append(entry)
        elif drop_child_only:
            kept.append((entry[0], "", ""))
    return tuple(kept)


def nubs_from(functions):
    return [(function, (child,) if child else ()) for function, child, _creator in functions]


def check_payload_guards():
    records = DEVICE["classify"](nubs_from(HEALTHY))
    counts = DEVICE["summary"](records)
    assert counts == {"functions": 16, "audio": 5, "driverless_audio": 0,
                      "served_audio": 5, "other_driverless": 0}, counts
    for name in ("USBAudio2StreamIN", "AppleUSBMux", "PTP", "nosuchfunction", "bad name"):
        rejected(lambda name=name: DEVICE["target"](records, name), "probe of a served nub")

    degraded = nubs_from(without(HEALTHY, "USBAudio2StreamIN", drop_child_only=True))
    records = DEVICE["classify"](degraded)
    counts = DEVICE["summary"](records)
    assert counts["driverless_audio"] == 1 and counts["served_audio"] == 4, counts
    chosen = DEVICE["target"](records, "USBAudio2StreamIN")
    assert chosen["expected"] == "AppleUSBDeviceAudioController" and chosen["eligible"]
    # Only the audio functions may be probed, and only by their exact name.
    for name in ("USBAudio2Control", "Valeria", "PTP", "usbaudio2streamin", ""):
        rejected(lambda name=name: DEVICE["target"](records, name), "ineligible target " + repr(name))
    rejected(lambda: DEVICE["classify"]([("USBAudio2StreamIN", ("not a class",))]),
             "invalid child class")
    rejected(lambda: DEVICE["classify"]([("bad name", ())]), "invalid function name")
    # Two nubs with one name is a registry state nobody should act on blindly.
    doubled = DEVICE["classify"](degraded + [("USBAudio2StreamIN", ())])
    rejected(lambda: DEVICE["target"](doubled, "USBAudio2StreamIN"), "ambiguous function")

    assert DEVICE["require_configured"](CONFIGURED) == CONFIGURED
    for state in (("disconnected", "no", 0), ("configured", "no", 5),
                  ("configured", "yes", 0), ("addressed", "yes", 5)):
        rejected(lambda state=state: DEVICE["require_configured"](state), "state " + str(state))
    assert DEVICE["ioreturn_name"](0) == "success"
    assert DEVICE["ioreturn_name"](0xE00002C7) == "unsupported"
    assert DEVICE["ioreturn_name"](0xE00002C1) == "not-privileged"
    assert DEVICE["ioreturn_name"](0xFFFFFEED) == "mig-bad-id"
    assert DEVICE["ioreturn_name"](0x12345678) == "other"
    return records


def check_payload_output(records):
    """The payload's own lines must satisfy the wrapper's validators."""
    report = DEVICE["render_inspect"](records, CONFIGURED)
    assert report.endswith("U3_REMATCH done\n") and len(report) <= 4096
    names, head = WRAPPER["driverless_audio"](report)
    assert names == ("USBAudio2StreamIN",), names
    assert head[1] == "16" and head[3] == "1" and head[8] == "5", head.groups()
    rejected(lambda: WRAPPER["driverless_audio"](report.replace("driverless-audio=1",
                                                               "driverless-audio=2")),
             "inspect header disagreeing with its own nub lines")
    rejected(lambda: WRAPPER["driverless_audio"]("U3_REMATCH inspect broken\nU3_REMATCH done\n"),
             "malformed inspect header")

    chosen = DEVICE["target"](records, "USBAudio2StreamIN")
    unsupported = DEVICE["render_probe"](chosen, 0xE00002C7, (), CONFIGURED)
    match = WRAPPER["PROBE"].fullmatch(unsupported.splitlines()[0])
    assert match and match[3] == "unsupported" and match[5] == "no", unsupported
    worked = DEVICE["render_probe"](chosen, 0, ("AppleUSBDeviceAudioController",), CONFIGURED)
    match = WRAPPER["PROBE"].fullmatch(worked.splitlines()[0])
    assert match and match[3] == "success" and match[5] == "yes", worked
    # A child of some other class is not a re-match.
    other = DEVICE["render_probe"](chosen, 0, ("IOUSBDeviceInterfaceUserClient",), CONFIGURED)
    assert WRAPPER["PROBE"].fullmatch(other.splitlines()[0])[5] == "no", other


def check_census_classifier():
    reference = census(HEALTHY)
    assert WRAPPER["classify_delta"](reference, reference)["verdict"] == "equal"

    audio = WRAPPER["classify_delta"](
        reference, census(without(HEALTHY, "USBAudio2StreamIN", drop_child_only=True)))
    assert audio["verdict"] == "audio-children-missing", audio
    assert audio["nubs"] == (16, 16) and audio["audio_children"] == (4, 5), audio
    assert audio["nubs_missing"] == () and not audio["extra"], audio

    volatile = WRAPPER["classify_delta"](reference, census(
        without(without(HEALTHY, "USBAudio2StreamIN", drop_child_only=True),
                "PTP", drop_child_only=True)))
    assert volatile["verdict"] == "volatile-clients-missing", volatile
    assert volatile["nubs"] == (16, 16), volatile

    # A missing function nub is the case that must never be called audio-only,
    # with or without the child driver that used to hang off it.
    for dropped in (census(without(HEALTHY, "USBAudio2StreamIN")),
                    census(without(HEALTHY, "AppleUSBMux")),
                    census(without(HEALTHY, "Valeria"))):
        delta = WRAPPER["classify_delta"](reference, dropped)
        assert delta["verdict"] == "nub-missing", delta
        assert delta["nubs"] == (15, 16) and len(delta["nubs_missing"]) == 1, delta

    renamed = census(tuple(("Unexpected" if name == "USBAudio2StreamIN" else name, child, creator)
                           for name, child, creator in HEALTHY))
    assert WRAPPER["classify_delta"](reference, renamed)["verdict"] == "nub-missing"

    # A missing driver that nothing has ever been observed to lose is not
    # waved through, and neither is a node the reference never had.
    assert WRAPPER["classify_delta"](
        reference, census(without(HEALTHY, "AppleUSBEthernet", drop_child_only=True))
    )["verdict"] == "unexpected"
    assert WRAPPER["classify_delta"](
        reference, census(HEALTHY, deeper=((2, "AppleUSBDeviceAudioController", ""),))
    )["verdict"] == "unexpected"
    # The accessory port and its client do come and go with a host.
    assert WRAPPER["classify_delta"](
        reference, census(without(HEALTHY, "IapOverUsbHid", drop_child_only=True))
    )["verdict"] == "volatile-clients-missing"

    rejected(lambda: WRAPPER["census_nodes"]("U2_XDCI_FUNCTIONS nodes=0\n"), "empty census")
    rejected(lambda: WRAPPER["census_nodes"]("U2_XDCI_NODE i=0 parent=-1 depth=0 class=../etc\n"),
             "malformed node line")
    rendered = WRAPPER["render_delta"]("U3_REMATCH_CENSUS", audio)
    assert ("verdict=audio-children-missing nubs=16/16 audio-children=4/5 "
            "missing=AppleUSBDeviceAudioController:1 extra=none nubs-missing=none") in rendered


def check_pin_and_payload_surface():
    source = PAYLOAD.read_bytes()
    assert hashlib.sha256(source).hexdigest() == WRAPPER["PAYLOAD_SHA256"], "payload pin drifted"
    assert 0 < len(source) <= 20480
    text = source.decode("ascii")
    assert text.startswith("#!/var/jb/usr/bin/python3\n")
    # The payload's whole write surface is one call, on one nub. Nothing here
    # may open a user client, set a property, reach the catalogue, call the
    # controller or touch a file.
    assert text.count("io.IOServiceRequestProbe(entry, 0)") == 1, "probe call changed"
    assert text.count("IOServiceRequestProbe") == 4, "probe surface changed"
    for forbidden in ("IOServiceOpen", "IOConnectCall", "IORegistryEntrySetCFProp",
                      "IOCatalogue", "IOServiceAuthorize", "SetDescription",
                      "GoOffAndOnBus", "ForceOffBus", "subprocess", "socket",
                      "open(", "os.remove", "os.unlink"):
        assert forbidden not in text, "payload gained " + forbidden
    # The wrapper has no way to reach the broker: no socket, and it runs no
    # host tool that sends it a command, so no journal can move because of it.
    wrapper = (SCRIPTS / "host/rematch-u2-driverless-function-wifi.py").read_text()
    for forbidden in ("broker.sock", "AF_UNIX", "sendall", "confirm-u2", "run-u2",
                      "recover-u2", "u2-wifi-restore-request", "u2-replace-broker"):
        assert forbidden not in wrapper, "wrapper gained " + forbidden


def main():
    records = check_payload_guards()
    check_payload_output(records)
    check_census_classifier()
    check_pin_and_payload_surface()
    print("PASS U3 rematch probe gate, census classifier and payload pin")


if __name__ == "__main__":
    main()
