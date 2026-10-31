#!/usr/bin/env python3
"""Build an inert-by-default rootless U2 watchdog package on the Mac.

The package copies the five reviewed Python modules into a root-owned
rootless libexec directory, creates a private journal directory, and installs
a launchd plist that starts the watchdog without publication enabled. Building
does not install or start anything on the iPad. The package's broker cannot
prepare or publish until a separately validated trial changes its explicit
launch argument. The package does not replace system USB or SSH files.
"""

import hashlib
from pathlib import Path
import plistlib
import stat
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[5]
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
BUILD = ROOT / "build/ipad-hardware"
OUTPUT = BUILD / "mac2jb-u2-watchdog_0.1.0_all.deb"
MODULES = (
    "u2_restore_journal.py", "u2_target_snapshot.py",
    "u2_usb_controller.py", "u2_watchdog_core.py",
    "u2_watchdog_service.py",
)
LABEL = "dev.mac2jb.u2.watchdog"


def main():
    if OUTPUT.exists():
        raise ValueError("package already exists")
    BUILD.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="u2-package-", dir=BUILD) as temporary:
        stage = Path(temporary)
        # dpkg records the archive root mode. Never propagate TemporaryDirectory's
        # private 0700 mode to the target filesystem root during installation.
        stage.chmod(0o755)
        code = stage / "var/jb/usr/libexec/mac2jb-u2"
        daemon = stage / "var/jb/Library/LaunchDaemons"
        state = stage / "var/jb/var/lib/mac2jb-u2"
        control = stage / "DEBIAN"
        for directory in (code, daemon, state, control):
            directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        state.chmod(0o700)
        source_hashes = {}
        for name in MODULES:
            source = DEVICE / name
            info = source.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 or
                    info.st_nlink != 1):
                raise ValueError("unsafe module source")
            data = source.read_bytes()
            target = code / name
            target.write_bytes(data)
            target.chmod(0o644)
            source_hashes[name] = hashlib.sha256(data).hexdigest()
        launch = {
            "Label": LABEL,
            "ProgramArguments": [
                "/var/jb/usr/bin/python3", "-I", "-S", "-B",
                "/var/jb/usr/libexec/mac2jb-u2/u2_watchdog_service.py",
            ],
            "RunAtLoad": True,
            "KeepAlive": True,
            "ThrottleInterval": 2,
            "UserName": "root",
        }
        plist = daemon / (LABEL + ".plist")
        plist.write_bytes(plistlib.dumps(launch, fmt=plistlib.FMT_XML))
        plist.chmod(0o644)
        metadata = control / "control"
        metadata.write_text(
            "Package: mac2jb-u2-watchdog\n"
            "Version: 0.1.0\n"
            "Architecture: all\n"
            "Maintainer: mac2jb local development\n"
            "Depends: python3\n"
            "Description: Inert-by-default iPad USB restore watchdog prototype\n"
        )
        metadata.chmod(0o644)
        result = subprocess.run(
            ["/opt/homebrew/bin/dpkg-deb", "--build", "--root-owner-group",
             str(stage), str(OUTPUT)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode != 0:
            raise ValueError("package build failed")
    package = OUTPUT.read_bytes()
    print("U2_PACKAGE built=offline publication=disabled files=" + str(len(MODULES)))
    print("U2_PACKAGE sha256=" + hashlib.sha256(package).hexdigest())
    for name, digest in sorted(source_hashes.items()):
        print("U2_PACKAGE source=" + name + " sha256=" + digest)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_PACKAGE rejected")
        raise SystemExit(1)
