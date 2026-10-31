#!/usr/bin/env python3
"""Build the separate signed HID canary binary on the Mac only.

The canary is the least-privileged half of the HID path: it configures an
already-published gadget function into a USB boot keyboard and writes reports,
and it has no way to publish a description. This script compiles only the
interface shim (never the publication shim), signs exactly
platform-application plus the IOUSBDeviceInterfaceUserClient exception, with no
set-description entitlement, verifies the signature, re-reads the signed
entitlements and exclusively saves one ignored Mac-built binary. It never
installs to or contacts the iPad and never touches USB.
"""

import hashlib
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[5]
BUILD = ROOT / "build/ipad-hardware"
OUTPUT = BUILD / "u3-hid-canary-v1"
# Resolve the installed iPhoneOS SDK instead of pinning an Xcode point release.
SDK = subprocess.run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                     text=True).stdout.strip()
ENTITLEMENTS = ROOT / "ios/entitlements/canary-interface.plist"
SWIFT = sorted((ROOT / "ios/canary").glob("*.swift"))
# Only the interface shim. The publication shim stays out of this binary, so
# the canary structurally cannot write a description.
C = ROOT / "ios/usb/USBDeviceFunctionShim.c"
EXPECTED_ENTITLEMENTS = {
    "platform-application": True,
    "com.apple.security.exception.iokit-user-client-class": [
        "IOUSBDeviceInterfaceUserClient",
    ],
}
# Publication authority and the journal belong to the broker alone.
FORBIDDEN = ("MAC2JBUSBRestoreShim", "USBRestoreJournal", "SetDescription",
             "setdescription", "MAC2JBUSBRestore")


def run(command, env=None, timeout=300):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=env)
    if result.returncode != 0:
        raise ValueError("offline canary build/sign/verify failed")
    return result.stdout


def main():
    if OUTPUT.exists() or not BUILD.is_dir() or not Path(SDK).is_dir():
        raise ValueError("unsafe output or missing SDK")
    if plistlib.loads(ENTITLEMENTS.read_bytes()) != EXPECTED_ENTITLEMENTS:
        raise ValueError("entitlements changed")
    if not SWIFT:
        raise ValueError("no canary sources")
    sources = [C, ROOT / "ios/usb/USBDeviceFunctionShim.h", *SWIFT]
    if any(not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 128 * 1024
           for path in sources):
        raise ValueError("unsafe source")
    for path in SWIFT:
        text = path.read_text()
        if any(token in text for token in FORBIDDEN):
            raise ValueError("canary source reaches publication authority")
    source_digest = hashlib.sha256(
        b"".join(path.name.encode("ascii") + b"\0" + path.read_bytes()
                 for path in sources)).hexdigest()
    with tempfile.TemporaryDirectory(prefix="u3-canary-build-", dir=BUILD) as temporary:
        stage = Path(temporary)
        object_file = stage / "function-shim.o"
        binary = stage / "u3-hid-canary"
        env = dict(os.environ,
                   CLANG_MODULE_CACHE_PATH=str(stage / "clang-cache"),
                   SWIFT_MODULE_CACHE_PATH=str(stage / "swift-cache"))
        run(["/usr/bin/xcrun", "--sdk", "iphoneos", "clang",
             "-target", "arm64-apple-ios15.0", "-isysroot", SDK,
             "-Wall", "-Werror", "-c", str(C), "-o", str(object_file)], env=env)
        run(["/usr/bin/xcrun", "--sdk", "iphoneos", "swiftc",
             "-target", "arm64-apple-ios15.0", "-sdk", SDK,
             "-I", str(ROOT / "ios/usb"), *(str(path) for path in SWIFT),
             str(object_file), "-framework", "IOKit",
             "-framework", "CoreFoundation", "-o", str(binary)], env=env)
        run(["/usr/bin/codesign", "--force", "--sign", "-",
             "--entitlements", str(ENTITLEMENTS), str(binary)])
        run(["/usr/bin/codesign", "--verify", "--strict", str(binary)])
        actual = plistlib.loads(run(
            ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(binary)]))
        if actual != EXPECTED_ENTITLEMENTS:
            raise ValueError("signed entitlements differ")
        data = binary.read_bytes()
        if len(data) > 4 * 1024 * 1024:
            raise ValueError("oversize canary binary")
        fd = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        try:
            if os.write(fd, data) != len(data):
                raise ValueError("short binary write")
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(BUILD, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    print("U3_HID_CANARY_BINARY built=offline signed=platform-interface-class "
          "publication=absent journal=absent")
    print("U3_HID_CANARY_BINARY source-sha256=" + source_digest)
    print("U3_HID_CANARY_BINARY sha256=" + hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException,
            subprocess.TimeoutExpired):
        print("U3_HID_CANARY_BINARY rejected")
        raise SystemExit(1)
