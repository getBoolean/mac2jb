#!/usr/bin/env python3
"""Compile and exercise the added-function matcher and operation entries.

Effect: Mac only. Builds and runs the C tests for the matcher, the name
comparison and the attempt ledger; builds the same shim for arm64 iOS so the
device target is proven to compile; imports the header from Swift through the
module map; and drives the pinned host reader's pure classifier over synthetic
device output. No device, no network, no USB.
"""

import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[6]
SHIM = ROOT / "ios/usb/USBDeviceFunctionShim.c"
TESTS = ROOT / "ios/tests/USBDeviceFunctionShimTests.c"
READER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/read-u2-added-function-wifi.py"
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u3-readonly-added-function.py"
MODULE = "MAC2JBUSBDeviceFunctionShim"
# Nothing in the payload may read or print a device identity.
FORBIDDEN = ("serialNumber", "uniqueDeviceID", "IOPlatformSerialNumber",
             "SerialNumber", "UDID", "udid")


def run(command, temporary, timeout=180):
    env = dict(os.environ, CLANG_MODULE_CACHE_PATH=str(temporary / "clang"),
               SWIFT_MODULE_CACHE_PATH=str(temporary / "swift"))
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout, env=env)


def mac_tests(temporary):
    binary = temporary / "function-shim-tests"
    build = run(["/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Werror",
                 str(TESTS), "-framework", "IOKit",  # the test includes the shim source,
         # so that it can build a session and record what each entry marshals;
         # linking the shim as well would duplicate every symbol.
                 "-framework", "CoreFoundation", "-o", str(binary)], temporary)
    if build.returncode != 0:
        raise AssertionError("Mac shim tests failed to compile:\n" +
                             build.stdout.decode("utf8", "replace"))
    result = subprocess.run([str(binary)], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=60)
    text = result.stdout.decode("utf8", "replace").strip()
    if result.returncode != 0:
        raise AssertionError("Mac shim tests failed:\n" + text)
    print(text)


def device_build(temporary):
    sdk = subprocess.run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
                         stdout=subprocess.PIPE, timeout=60, check=True)
    sdk_path = sdk.stdout.decode("ascii").strip()
    built = run(["/usr/bin/xcrun", "--sdk", "iphoneos", "clang",
                 "-target", "arm64-apple-ios15.0", "-isysroot", sdk_path,
                 "-Wall", "-Werror", "-c", str(SHIM),
                 "-o", str(temporary / "function-shim.o")], temporary)
    if built.returncode != 0:
        raise AssertionError("shim failed to compile for arm64 iOS:\n" +
                             built.stdout.decode("utf8", "replace"))
    print("PASS added-function shim compiles for arm64 iOS")


def module_map(temporary):
    source = temporary / "import-check.swift"
    source.write_text("import " + MODULE + "\n"
                      "_ = MAC2JBUSBFunctionSelectorCommit\n"
                      "_ = MAC2JBUSBFunctionServiceAbsent\n")
    built = run(["/usr/bin/xcrun", "swiftc", "-typecheck",
                 "-I", str(ROOT / "ios/usb"), str(source)], temporary)
    if built.returncode != 0:
        raise AssertionError("module map does not expose " + MODULE + ":\n" +
                             built.stdout.decode("utf8", "replace"))
    print("PASS module map exposes " + MODULE + " to Swift")


def reader_classifier():
    reader = runpy.run_path(str(READER))
    classify = reader["classify"]
    summarize = reader["summarize"]
    name = "hidcanary"

    def line(**fields):
        ordered = ("name", "state", "controller", "clients", "open")
        return ("U2_ADDED_FUNCTION " +
                " ".join(key + "=" + str(fields[key]) for key in ordered) + "\n")

    absent = line(name=name, state="absent", controller="unknown", clients=0,
                  open="not-attempted")
    denied = line(name=name, state="present", controller="same", clients=1,
                  open="denied")
    granted = line(name=name, state="present", controller="same", clients=1,
                   open="granted")
    unclaimed = line(name=name, state="present", controller="same", clients=0,
                     open="not-attempted")
    other = line(name=name, state="present", controller="other", clients=0,
                 open="not-attempted")

    labels = {text: classify(text) for text in
              (absent, denied, granted, unclaimed, other)}
    assert labels[absent] == "absent-service", labels[absent]
    assert labels[denied] == "open-denied", labels[denied]
    # Absent and denied must never collapse, and neither is a pass.
    assert len(set(labels.values())) == 5, labels
    assert labels[absent] != labels[denied]
    assert labels[granted] == "open-granted"
    assert labels[unclaimed] == "present-not-opened"
    assert labels[other] == "wrong-controller"
    for text, label in labels.items():
        assert "pass" not in label.lower(), (text, label)

    done = "U2_ADDED_FUNCTION done\n"
    reported = summarize((absent + done).encode("ascii"))
    assert reported == "U2_ADDED_FUNCTION name=hidcanary outcome=absent-service", reported
    reported = summarize((denied + done).encode("ascii"))
    assert reported == "U2_ADDED_FUNCTION name=hidcanary outcome=open-denied", reported

    def rejects(data):
        try:
            summarize(data)
        except (ValueError, UnicodeError):
            return
        raise AssertionError("malformed device output accepted: " + repr(data))

    rejects(b"")
    rejects(absent.encode("ascii"))                       # No terminator.
    rejects((absent + absent + done).encode("ascii"))     # More than one answer.
    rejects(done.encode("ascii"))                         # No answer at all.
    rejects((absent + done).encode("ascii") * 400)
    rejects(line(name="has space", state="absent", controller="unknown",
                 clients=0, open="not-attempted").encode("ascii") + done.encode("ascii"))
    rejects(line(name=name, state="elsewhere", controller="same", clients=0,
                 open="not-attempted").encode("ascii") + done.encode("ascii"))
    rejects(line(name=name, state="present", controller="same", clients=0,
                 open="maybe").encode("ascii") + done.encode("ascii"))
    print("PASS host reader reports absent-service and open-denied distinctly")


def payload_is_read_only():
    source = PAYLOAD.read_text()
    for token in FORBIDDEN:
        if token in source:
            raise AssertionError("device payload mentions a device identity: " + token)
    for token in ("IOServiceOpen", "IOConnectCall", "IORegistryEntrySetCFProperty",
                  "SetDescription", "open(", "subprocess"):
        if token in source:
            raise AssertionError("device payload is not read-only: " + token)
    if not re.search(r"open=not-attempted", source):
        raise AssertionError("device payload must report open as not attempted")
    print("PASS device payload opens nothing and reports no device identity")


def main():
    with tempfile.TemporaryDirectory(prefix="mac2jb-u3-function-shim-") as temporary:
        directory = Path(temporary)
        mac_tests(directory)
        device_build(directory)
        module_map(directory)
    reader_classifier()
    payload_is_read_only()


if __name__ == "__main__":
    main()
