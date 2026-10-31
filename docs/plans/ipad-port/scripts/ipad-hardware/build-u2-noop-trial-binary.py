#!/usr/bin/env python3
"""Build a separate signed native U2 no-op-trial binary on the Mac only.

This compiles the C restore shim and Swift watchdog with the opt-in
MAC2JB_ENABLE_U2_NOOP_TRIAL flag, signs exactly platform-application and
set-description entitlements, verifies the signature, and exclusively saves
one ignored Mac binary. It never installs or runs on the iPad and does not
contact USB. The normal installed `--serve` entry stays publication-disabled;
only this distinct binary's `--serve-noop-trial` can prepare/publish the
captured original description through the journaled watchdog.
"""

import hashlib
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[5]
BUILD = ROOT / "build/ipad-hardware"
OUTPUT = BUILD / "u2-native-noop-trial"
OUTPUT_V2 = BUILD / "u2-native-noop-trial-v2"
OUTPUT_V3 = BUILD / "u2-native-noop-trial-v3-buscycle"
OUTPUT_V4 = BUILD / "u2-native-noop-trial-v4-clone"
OUTPUT_V5 = BUILD / "u2-native-noop-trial-v5-postclone"
OUTPUT_V6 = BUILD / "u2-native-noop-trial-v6-settled"
OUTPUT_V7 = BUILD / "u2-native-noop-trial-v7-ready-gated"
OUTPUT_V8 = BUILD / "u2-native-noop-trial-v8-wifi-restore"
OUTPUT_V9 = BUILD / "u2-native-noop-trial-v9-auto-heal"
OUTPUT_V10 = BUILD / "u2-native-noop-trial-v10-auto-heal-5"
OUTPUT_V11 = BUILD / "u2-native-noop-trial-v11-auto-heal-restart"
OUTPUT_NO_INITIAL_CYCLE = BUILD / "u2-native-noop-trial-clone-no-initial-cycle"
# Resolve the installed iPhoneOS SDK instead of pinning an Xcode point release.
SDK = subprocess.run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
ENTITLEMENTS = ROOT / "ios/entitlements/probe-platform-setdescription.plist"
SWIFT = [
    ROOT / "ios/usb/USBRestoreJournal.swift",
    ROOT / "ios/watchdog/USBRestoreCoordinator.swift",
    ROOT / "ios/watchdog/TargetUSBRestoreSnapshot.swift",
    ROOT / "ios/watchdog/TargetUSBRestoreController.swift",
    ROOT / "ios/watchdog/USBFunctionRegistrationHealer.swift",
    ROOT / "ios/watchdog/USBFunctionOwnerRestarter.swift",
    ROOT / "ios/watchdog/NativeUSBWatchdogService.swift",
    ROOT / "ios/watchdog/USBWatchdogMain.swift",
]
C = ROOT / "ios/usb/USBRestoreControllerShim.c"
EXPECTED_ENTITLEMENTS = {
    "platform-application": True,
    "com.apple.private.usbdevice.setdescription": True,
}


def run(command, env=None, timeout=60):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=env)
    if result.returncode != 0:
        raise ValueError("offline native build/sign/verify failed")
    return result.stdout


def main():
    global OUTPUT
    explicit_cycle = False
    controller_clone = False
    post_clone = False
    settled_recovery = False
    ready_gated = False
    no_initial_cycle = False
    if len(sys.argv) == 2 and sys.argv[1] == "--v2":
        OUTPUT = OUTPUT_V2
    elif len(sys.argv) == 2 and sys.argv[1] == "--v3-buscycle":
        OUTPUT = OUTPUT_V3
        explicit_cycle = True
    elif len(sys.argv) == 2 and sys.argv[1] == "--v4-clone":
        OUTPUT = OUTPUT_V4
        explicit_cycle = True
        controller_clone = True
    elif len(sys.argv) == 2 and sys.argv[1] == "--v5-postclone":
        OUTPUT = OUTPUT_V5
        explicit_cycle = True
        controller_clone = True
        post_clone = True
    elif len(sys.argv) == 2 and sys.argv[1] == "--v6-settled":
        OUTPUT = OUTPUT_V6
        explicit_cycle = True
        controller_clone = True
        post_clone = True
        settled_recovery = True
    elif len(sys.argv) == 2 and sys.argv[1] == "--v7-ready-gated":
        OUTPUT = OUTPUT_V7
        explicit_cycle = True
        controller_clone = True
        post_clone = True
        ready_gated = True
    elif len(sys.argv) == 2 and sys.argv[1] == "--v8-wifi-restore":
        # v7 flags unchanged; the source adds `restore-after-failure`.
        OUTPUT = OUTPUT_V8
        explicit_cycle = True
        controller_clone = True
        post_clone = True
        ready_gated = True
    elif len(sys.argv) == 2 and sys.argv[1] == "--v9-auto-heal":
        # v8 flags; the source adds automatic function-registration healing.
        OUTPUT = OUTPUT_V9
        explicit_cycle = True
        controller_clone = True
        post_clone = True
        ready_gated = True
    elif len(sys.argv) == 2 and sys.argv[1] == "--v10-auto-heal":
        # v9 flags; the healer now allows 5 republications.
        OUTPUT = OUTPUT_V10
        explicit_cycle = True
        controller_clone = True
        post_clone = True
        ready_gated = True
    elif len(sys.argv) == 2 and sys.argv[1] == "--v11-auto-heal":
        # v10 plus healing on watchdog restart and lease expiry.
        OUTPUT = OUTPUT_V11
        explicit_cycle = True
        controller_clone = True
        post_clone = True
        ready_gated = True
    elif len(sys.argv) == 2 and sys.argv[1] == "--clone-no-initial-cycle":
        OUTPUT = OUTPUT_NO_INITIAL_CYCLE
        controller_clone = True
        no_initial_cycle = True
    elif len(sys.argv) != 1:
        raise ValueError("invalid build revision")
    if OUTPUT.exists() or not BUILD.is_dir() or not Path(SDK).is_dir():
        raise ValueError("unsafe output or missing SDK")
    if plistlib.loads(ENTITLEMENTS.read_bytes()) != EXPECTED_ENTITLEMENTS:
        raise ValueError("entitlements changed")
    sources = [C, *SWIFT, ROOT / "ios/usb/USBRestoreControllerShim.h"]
    if any(not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 128 * 1024
           for path in sources):
        raise ValueError("unsafe source")
    source_digest = hashlib.sha256(
        (b"MAC2JB_U2_NO_INITIAL_CYCLE=1\0" if no_initial_cycle else b"") +
        (b"MAC2JB_U2_READY_GATE=1\0" if ready_gated else b"") +
        (b"MAC2JB_U2_SETTLED_RECOVERY=1\0" if settled_recovery else b"") +
        (b"MAC2JB_U2_POST_CLONE=1\0" if post_clone else b"") +
        (b"MAC2JB_U2_CONTROLLER_CLONE=1\0" if controller_clone else b"") +
        (b"MAC2JB_U2_EXPLICIT_BUS_CYCLE=1\0" if explicit_cycle else b"") +
        b"".join(path.name.encode("ascii") + b"\0" + path.read_bytes()
                 for path in sources)).hexdigest()
    with tempfile.TemporaryDirectory(prefix="u2-noop-build-", dir=BUILD) as temporary:
        stage = Path(temporary)
        object_file = stage / "restore.o"
        binary = stage / "u2-native-noop-trial"
        env = dict(os.environ,
                   CLANG_MODULE_CACHE_PATH=str(stage / "clang-cache"),
                   SWIFT_MODULE_CACHE_PATH=str(stage / "swift-cache"))
        run(["/usr/bin/xcrun", "--sdk", "iphoneos", "clang",
             "-target", "arm64-apple-ios15.0", "-isysroot", SDK,
             "-c", str(C), "-o", str(object_file)], env=env)
        defines = ["-D", "MAC2JB_U2_EXPLICIT_BUS_CYCLE"] if explicit_cycle else []
        if controller_clone:
            defines += ["-D", "MAC2JB_U2_CONTROLLER_CLONE"]
        if no_initial_cycle:
            defines += ["-D", "MAC2JB_U2_NO_INITIAL_CYCLE"]
        if post_clone:
            defines += ["-D", "MAC2JB_U2_POST_CLONE"]
        if settled_recovery:
            defines += ["-D", "MAC2JB_U2_SETTLED_RECOVERY"]
        run(["/usr/bin/xcrun", "--sdk", "iphoneos", "swiftc",
             "-target", "arm64-apple-ios15.0", "-sdk", SDK,
             "-D", "MAC2JB_ENABLE_U2_NOOP_TRIAL",
             *defines,
             "-I", str(ROOT / "ios/usb"), *(str(path) for path in SWIFT),
             str(object_file), "-framework", "IOKit", "-o", str(binary)], env=env)
        run(["/usr/bin/codesign", "--force", "--sign", "-",
             "--entitlements", str(ENTITLEMENTS), str(binary)])
        run(["/usr/bin/codesign", "--verify", "--strict", str(binary)])
        actual = plistlib.loads(run(
            ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(binary)]))
        if actual != EXPECTED_ENTITLEMENTS:
            raise ValueError("signed entitlements differ")
        data = binary.read_bytes()
        if len(data) > 4 * 1024 * 1024:
            raise ValueError("oversize trial binary")
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
    print("U2_NOOP_TRIAL_BINARY built=offline signed=platform-setdescription "
          "bus-cycle=" + ("enabled" if explicit_cycle else "disabled") +
          " controller-clone=" + ("enabled" if controller_clone else "disabled"))
    if post_clone:
        print("U2_NOOP_TRIAL_BINARY post-clone-normalization=enabled")
    if settled_recovery:
        print("U2_NOOP_TRIAL_BINARY settled-recovery=enabled")
    if ready_gated:
        print("U2_NOOP_TRIAL_BINARY readiness-gate=enabled")
    if no_initial_cycle:
        print("U2_NOOP_TRIAL_BINARY first-publication-cycle=disabled recovery-cycle=enabled")
    print("U2_NOOP_TRIAL_BINARY source-sha256=" + source_digest)
    print("U2_NOOP_TRIAL_BINARY sha256=" + hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException,
            subprocess.TimeoutExpired):
        print("U2_NOOP_TRIAL_BINARY rejected")
        raise SystemExit(1)
