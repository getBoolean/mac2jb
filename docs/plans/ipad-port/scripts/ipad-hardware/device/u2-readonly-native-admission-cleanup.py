#!/var/jb/usr/bin/python3
"""Confirm both exact one-shot U2 native test jobs and files are absent.

This read-only probe checks seven fixed paths and asks launchctl whether either
one-shot job is still registered. It never deletes a file or changes a job.
"""

import os
import subprocess


PATHS = (
    "/var/mobile/Media/.mac2jb-u2-native-admission-459d1e3f4f0f",
    "/var/jb/usr/libexec/.mac2jb-u2-native-admission-459d1e3f4f0f",
    "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.nativeadmission.plist",
    "/var/mobile/Media/.mac2jb-u2-native-launch-output-459d1e3f4f0f",
    "/var/jb/usr/libexec/.mac2jb-u2-native-snapshot-de7c2f408120",
    "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.nativesnapshot.plist",
    "/var/mobile/Media/.mac2jb-u2-native-launch-output-de7c2f408120",
)
LABELS = (
    "system/dev.mac2jb.u2.nativeadmission",
    "system/dev.mac2jb.u2.nativesnapshot",
)


def main():
    count = sum(os.path.lexists(path) for path in PATHS)
    loaded = any(subprocess.run(
        ["/var/jb/bin/launchctl", "print", label],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
    ).returncode == 0 for label in LABELS)
    print("U2_NATIVE_CLEANUP paths=" + ("absent" if count == 0 else "present") +
          " job=" + ("present" if loaded else "absent"))
    if count != 0 or loaded:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.TimeoutExpired):
        print("U2_NATIVE_CLEANUP rejected")
        raise SystemExit(1)
