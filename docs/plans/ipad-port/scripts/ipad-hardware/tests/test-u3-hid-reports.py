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
    CANARY / "CanaryBrokerLease.swift",
    ROOT / "ios/tests/HIDReportTests.swift",
]
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


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u3-hid-reports-") as temporary:
        directory = Path(temporary)
        mac_tests(directory)
        device_build(directory)
    canary_publishes_nothing()


if __name__ == "__main__":
    main()
