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


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u3-hid-reports-") as temporary:
        directory = Path(temporary)
        mac_tests(directory)
        device_build(directory)
    canary_publishes_nothing()
    open_outcome_codes_match_the_shim()
    open_gate_attempts_one_open_and_configures_nothing()


if __name__ == "__main__":
    main()
