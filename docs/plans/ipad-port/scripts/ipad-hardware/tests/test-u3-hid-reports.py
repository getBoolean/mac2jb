#!/usr/bin/env python3
"""Compile and run the Mac-only HID canary model, plan and exit-path tests.

Effect: Mac only. Builds the canary's report model, configuration plan and run
loop with a recording report sink and a fake lease, then builds the whole
canary plus the interface shim for arm64 iOS so the device target is proven to
compile. It also checks structurally that the canary links no publication shim
and never writes a description or the journal. No device, no network, no USB.
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[6]
CANARY = ROOT / "ios/canary"
SHIM = ROOT / "ios/usb/USBDeviceFunctionShim.c"
# The Mac test links the shim-free part of the canary; the entry point is
# excluded because the test executable supplies its own @main.
MAC_SOURCES = [
    CANARY / "HIDKeyboardReport.swift",
    CANARY / "HIDCanaryRun.swift",
    CANARY / "HIDCanaryMode.swift",
    CANARY / "CanaryBrokerLease.swift",
    ROOT / "ios/tests/HIDReportTests.swift",
]
HEADER = ROOT / "ios/usb/USBDeviceFunctionShim.h"
# The reference backend's own names for the two raw returns the wait for host
# enumeration keeps waiting on.
REFERENCE_RETURNS = ROOT / "vendor/libusbd/src/plat/macos/impl.h"
# Publication authority stays in the broker: none of this may appear.
FORBIDDEN = ("MAC2JBUSBRestoreShim", "USBRestoreJournal", "SetDescription",
             "setdescription", "MAC2JBUSBRestore")


def env(temporary):
    return dict(os.environ, CLANG_MODULE_CACHE_PATH=str(temporary / "clang"),
                SWIFT_MODULE_CACHE_PATH=str(temporary / "swift"))


def mac_tests(temporary):
    binary = temporary / "hid-report-tests"
    build = subprocess.run(["/usr/bin/xcrun", "swiftc",
                            *(str(path) for path in MAC_SOURCES), "-o", str(binary)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=180, env=env(temporary))
    if build.returncode != 0:
        raise AssertionError("HID canary tests failed to compile:\n" +
                             build.stdout.decode("utf8", "replace"))
    result = subprocess.run([str(binary)], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=60)
    text = result.stdout.decode("utf8", "replace").strip()
    if result.returncode != 0:
        raise AssertionError("HID canary tests failed:\n" + text)
    print(text)


def device_build(temporary):
    sdk = subprocess.run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
                         stdout=subprocess.PIPE, timeout=60, check=True)
    sdk_path = sdk.stdout.decode("ascii").strip()
    object_file = temporary / "function-shim.o"
    built = subprocess.run(["/usr/bin/xcrun", "--sdk", "iphoneos", "clang",
                            "-target", "arm64-apple-ios15.0", "-isysroot", sdk_path,
                            "-Wall", "-Werror", "-c", str(SHIM), "-o", str(object_file)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=180, env=env(temporary))
    if built.returncode != 0:
        raise AssertionError("interface shim failed to compile for arm64 iOS:\n" +
                             built.stdout.decode("utf8", "replace"))
    built = subprocess.run(["/usr/bin/xcrun", "--sdk", "iphoneos", "swiftc",
                            "-target", "arm64-apple-ios15.0", "-sdk", sdk_path,
                            "-I", str(ROOT / "ios/usb"),
                            *(str(path) for path in sorted(CANARY.glob("*.swift"))),
                            str(object_file), "-framework", "IOKit",
                            "-framework", "CoreFoundation",
                            "-o", str(temporary / "u3-hid-canary")],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=300, env=env(temporary))
    if built.returncode != 0:
        raise AssertionError("canary failed to build for arm64 iOS:\n" +
                             built.stdout.decode("utf8", "replace"))
    print("PASS canary builds for arm64 iOS against the iphoneos SDK")


def canary_publishes_nothing():
    sources = sorted(CANARY.glob("*.swift"))
    if not sources:
        raise AssertionError("no canary sources found")
    for path in sources:
        text = path.read_text()
        for token in FORBIDDEN:
            if token in text:
                raise AssertionError(str(path) + " reaches publication authority: " + token)
    print("PASS canary publishes no description and touches no journal")


def open_outcome_codes_match_the_shim():
    """The gate's two refusal codes are the shim's own, not a drifted copy.

    The Mac test cannot import the shim header, so the stop-after-open gate
    names the two result values it has to tell apart. If the header ever
    renumbers them, an absent interface and a denied open would be reported as
    each other, which is exactly what the gate exists to separate.
    """
    header = HEADER.read_text()
    swift = (CANARY / "HIDCanaryMode.swift").read_text()
    for name, label in (("MAC2JBUSBFunctionServiceAbsent", "serviceAbsentResult"),
                        ("MAC2JBUSBFunctionOpenDenied", "openDeniedResult")):
        found = re.search(name + r"\s*=\s*([0-9]+)", header)
        if not found:
            raise AssertionError("the shim header no longer defines " + name)
        if not re.search(label + r"\s*:\s*Int32\s*=\s*" + found.group(1) + r"\b", swift):
            raise AssertionError("%s must be %s, as the shim header says" %
                                 (label, found.group(1)))
    print("PASS stop-after-open gate reads the shim's own result codes")


def enumeration_wait_returns_match_the_reference():
    """The waitable raw returns are the reference backend's own values.

    Committing the configuration re-presents the device, so a write before the
    host has read the new descriptors returns not-activated, and a write the
    host has not collected times out. Both mean "not yet"; every other raw
    return is a real failure. Reading a real failure as "keep waiting" would
    hide it for the whole budget, so the two values are checked against the
    reference backend that defines them rather than kept as a drifting copy.
    """
    reference = REFERENCE_RETURNS.read_text()
    run_source = (CANARY / "HIDCanaryRun.swift").read_text()
    for name, label in (("LIBUSBD_MACOS_ERR_NOTACTIVATED", "notEnumerated"),
                        ("LIBUSBD_MACOS_ERR_TIMEOUT", "writeTimedOut")):
        found = re.search(r"define\s+" + name + r"\s*\(?(0[xX][0-9a-fA-F]+)", reference)
        if not found:
            raise AssertionError("the reference backend no longer defines " + name)
        expected = int(found.group(1), 16)
        declared = re.search(label + r"\s*=\s*Int32\(bitPattern:\s*(0[xX][0-9a-fA-F]+)\)",
                             run_source)
        if not declared or int(declared.group(1), 16) != expected:
            raise AssertionError("%s must be 0x%08X, as the reference backend says" %
                                 (label, expected))
    print("PASS enumeration wait waits on the reference backend's own raw returns")


def open_gate_attempts_one_open_and_configures_nothing():
    """One open attempt in the whole canary, and the gate stops before configuring.

    A refusal has to be attributable to the open itself, so the stop-after-open
    mode may place no configuration call at all; and the single match-and-open
    call site is what makes "exactly one open attempt" checkable here.
    """
    main_source = (CANARY / "HIDCanaryMain.swift").read_text()
    opens = sum(source.read_text().count("MAC2JBUSBFunctionOpen(")
                for source in sorted(CANARY.glob("*.swift")))
    if opens != 1:
        raise AssertionError("the canary must have exactly one match-and-open call "
                             "site, found %d" % opens)
    gate = main_source.find("configuresInterface")
    configure = main_source.find("configure(session")
    if gate < 0 or configure < 0 or gate > configure:
        raise AssertionError("the stop-after-open gate must exit before the "
                             "configuration sequence is driven")
    print("PASS stop-after-open gate places one open and no configuration call")


def enumeration_wait_cannot_type():
    """The wait for host enumeration must not share its mechanism with typing.

    It used to poll by writing the neutral report, which made every wait a
    write: a wait on a host that is watching types into whatever has focus
    there. The pipe's current maximum packet size answers the same question -
    zero until a host has selected a configuration containing the interface,
    the endpoint's size once it has - and puts nothing on the bus, so the
    structural rule is that the wait reaches the sink nowhere at all.
    """
    source = (CANARY / "HIDCanaryRun.swift").read_text()
    start = source.index("private func waitForHostEnumeration")
    wait = source[start:source.index("private static func stop(", start)]
    for forbidden in ("sink.write", "neutralReport", "HIDReportWrite"):
        if forbidden in wait:
            raise AssertionError("the enumeration wait still reaches the report "
                                 "path: " + forbidden)
    if "visibility.currentMaxPacketSize()" not in wait:
        raise AssertionError("the enumeration wait must poll the pipe's current "
                             "maximum packet size")
    # No default probe, so there is no quiet fallback to the sink to rediscover.
    if re.search(r"visibility\s*:\s*HIDPipeVisibility\s*=", source):
        raise AssertionError("the visibility probe must be injected, not defaulted")
    # The production probe goes through the shim's own entry and selector, and
    # the one pre-existing as-asked query beside create-pipe stays.
    main_source = (CANARY / "HIDCanaryMain.swift").read_text()
    calls = main_source.count("MAC2JBUSBFunctionPipeMaxPacketSize(")
    if calls != 2:
        raise AssertionError("expected the as-asked query and the wait's probe, "
                             "found %d calls" % calls)
    if "MAC2JBUSBFunctionSelectorPipeMaxPacketSize" not in main_source:
        raise AssertionError("the probe must use the shim's own selector")
    if "MAC2JBUSBFunctionPipeMaxPacketSize" not in HEADER.read_text():
        raise AssertionError("the shim header no longer exposes the pipe size entry")
    print("PASS enumeration wait polls the pipe's size and writes no report")


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u3-hid-reports-") as temporary:
        directory = Path(temporary)
        mac_tests(directory)
        device_build(directory)
    canary_publishes_nothing()
    open_outcome_codes_match_the_shim()
    enumeration_wait_returns_match_the_reference()
    enumeration_wait_cannot_type()
    open_gate_attempts_one_open_and_configures_nothing()


if __name__ == "__main__":
    main()
