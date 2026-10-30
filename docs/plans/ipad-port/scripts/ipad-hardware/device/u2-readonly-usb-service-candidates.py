#!/var/jb/usr/bin/python3
"""List bounded USB-related launchd labels and processes without changing them.

Calls only `launchctl print system` and `ps` for read-only inventory. Prints
filtered service/process names, never arguments, environment, PIDs, paths,
or raw launchd output. It does not start, stop, or signal any process.
"""

import os
import re
import subprocess


INTEREST = re.compile(r"usb|lockdown|accessory|gadget|deviceconfig|mobiledevice", re.I)
SAFE = re.compile(r"[A-Za-z0-9_.-]{1,110}\Z")


def collect(command, limit):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=10)
    if result.returncode or len(result.stdout) > limit:
        raise ValueError("inventory unavailable")
    return result.stdout.decode("utf-8", "replace")


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    listing = collect(["/var/jb/bin/launchctl", "print", "system"], 8 * 1024 * 1024)
    labels = set()
    for line in listing.splitlines():
        for token in re.findall(r"[A-Za-z0-9_.-]+", line):
            if SAFE.fullmatch(token) and "." in token and INTEREST.search(token):
                labels.add(token)
    if len(labels) > 80:
        raise ValueError("too many labels")
    print("U2_USB_SERVICES count=" + str(len(labels)))
    for label in sorted(labels):
        print("U2_USB_SERVICE " + label)
    candidates = set()
    for directory in ("/System/Library/LaunchDaemons",
                      "/System/Library/LaunchAgents",
                      "/var/jb/Library/LaunchDaemons"):
        if not os.path.isdir(directory):
            continue
        with os.scandir(directory) as entries:
            for entry in entries:
                if (entry.is_file(follow_symlinks=False) and
                        entry.name.endswith(".plist") and
                        SAFE.fullmatch(entry.name) and
                        INTEREST.search(entry.name)):
                    candidates.add(entry.name)
    if len(candidates) > 80:
        raise ValueError("too many plist candidates")
    print("U2_USB_PLISTS count=" + str(len(candidates)))
    for name in sorted(candidates):
        print("U2_USB_PLIST " + name)
    for path in ("/var/jb/usr/bin/ps", "/bin/ps", "/usr/bin/ps"):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            try:
                processes = collect([path, "-A", "-o", "comm="], 1024 * 1024)
            except ValueError:
                continue
            names = set()
            for raw in processes.splitlines():
                name = os.path.basename(raw.strip())
                if SAFE.fullmatch(name) and INTEREST.search(name):
                    names.add(name)
            if len(names) > 80:
                raise ValueError("too many processes")
            print("U2_USB_PROCESSES count=" + str(len(names)))
            for name in sorted(names):
                print("U2_USB_PROCESS " + name)
            break


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_USB_SERVICES rejected")
        raise SystemExit(1)
