#!/usr/bin/env python3
"""Build the publication-disabled native U2 watchdog package on the Mac.

The builder verifies the exact signed arm64 iOS executable and its two
entitlements, then stages only the rootless binary, a launchd plist whose
argument is --serve, and an empty mode-0700 journal directory. It creates an
ignored .deb on the Mac. It does not install or run code on the iPad. This
binary's main entry hard-disables publication, so a separate guarded build
is still required before any no-op controller trial.
"""

import hashlib
from pathlib import Path
import plistlib
import stat
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[5]
BUILD = ROOT / "build/ipad-hardware"
BINARY = BUILD / "u2-native-watchdog"
BINARY_SHA256 = "1c7530d5796c27ce50efb4dacd522302ffbd96bbb800513808a929d061baad14"
OUTPUT = BUILD / "mac2jb-u2-native-watchdog_0.1.0_iphoneos-arm64.deb"
LABEL = "dev.mac2jb.u2.watchdog"
INSTALLED = "/var/jb/usr/libexec/mac2jb-u2-native-watchdog"


def main():
    info = BINARY.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024 * 1024 or
            info.st_nlink != 1 or OUTPUT.exists()):
        raise ValueError("unsafe source or existing package")
    executable = BINARY.read_bytes()
    if hashlib.sha256(executable).hexdigest() != BINARY_SHA256:
        raise ValueError("native binary changed")
    verified = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(BINARY)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
    entitlements = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(BINARY)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
    if (verified.returncode != 0 or entitlements.returncode != 0 or
            plistlib.loads(entitlements.stdout) != {
                "platform-application": True,
                "com.apple.private.usbdevice.setdescription": True}):
        raise ValueError("native signature or entitlements changed")
    with tempfile.TemporaryDirectory(prefix="u2-native-package-", dir=BUILD) as temporary:
        stage = Path(temporary)
        stage.chmod(0o755)
        code = stage / "var/jb/usr/libexec"
        daemon = stage / "var/jb/Library/LaunchDaemons"
        state = stage / "var/jb/var/lib/mac2jb-u2-native"
        control = stage / "DEBIAN"
        for directory in (code, daemon, state, control):
            directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        state.chmod(0o700)
        target = code / "mac2jb-u2-native-watchdog"
        target.write_bytes(executable)
        target.chmod(0o755)
        plist = daemon / (LABEL + ".plist")
        plist.write_bytes(plistlib.dumps({
            "Label": LABEL,
            "ProgramArguments": [INSTALLED, "--serve"],
            "RunAtLoad": True,
            "KeepAlive": True,
            "ThrottleInterval": 2,
            "UserName": "root",
        }, fmt=plistlib.FMT_XML))
        plist.chmod(0o644)
        metadata = control / "control"
        metadata.write_text(
            "Package: mac2jb-u2-native-watchdog\n"
            "Version: 0.1.0\n"
            "Architecture: iphoneos-arm64\n"
            "Maintainer: mac2jb local development\n"
            "Description: Publication-disabled native iPad USB restore watchdog\n"
        )
        metadata.chmod(0o644)
        checksums = control / "md5sums"
        checksums.write_text(
            hashlib.md5(executable).hexdigest() +
            "  var/jb/usr/libexec/mac2jb-u2-native-watchdog\n" +
            hashlib.md5(plist.read_bytes()).hexdigest() +
            "  var/jb/Library/LaunchDaemons/" + LABEL + ".plist\n"
        )
        checksums.chmod(0o644)
        result = subprocess.run(
            ["/opt/homebrew/bin/dpkg-deb", "--build", "--root-owner-group",
             str(stage), str(OUTPUT)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode != 0:
            raise ValueError("native package build failed")
    package = OUTPUT.read_bytes()
    print("U2_NATIVE_PACKAGE built=offline publication=disabled")
    print("U2_NATIVE_PACKAGE sha256=" + hashlib.sha256(package).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, plistlib.InvalidFileException,
            subprocess.TimeoutExpired):
        print("U2_NATIVE_PACKAGE rejected")
        raise SystemExit(1)
