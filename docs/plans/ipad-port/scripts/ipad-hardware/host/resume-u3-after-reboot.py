#!/usr/bin/env python3
"""Put the device back into a trial-ready state after an owner reboot.

A reboot restores USB, and it also leaves three things that must be dealt with
in order before any trial can start. Doing them by hand is where mistakes go:
the journal looks resolvable but is not, the strict check silently compares
against another boot's baseline, and a fresh broker starts with a 6 MB jetsam
limit that kills it during a publication.

So this runs them in order and stops at the first failure, reporting what it
did and what is left:

1. Pinned Wi-Fi SSH, Mac USB and a configured controller - refuses if the
   reboot did not in fact restore USB.
2. Retire the previous boot's journal. Its recipe is bound to the boot session
   it was written in and every broker path validates that, so after a reboot it
   can be neither confirmed nor restored while still blocking `prepare`. The
   archive tool refuses a journal from the *running* boot, so this cannot
   quietly discard a resolvable one.
3. Capture a fresh trial baseline, because the old one is bound to the old
   boot, and print the manifest digest to pin. **Pinning is left to a human or
   an agent**, deliberately: the digest is what makes the strict external check
   mean anything, so this prints the one-line edit rather than making it.
4. Raise the fresh broker's jetsam limit, which does not survive a restart.
5. Report the staged canary digest so the trial's argument can be filled in.

Nothing here publishes a description, changes a plist or touches the USB
controller. Usage: no arguments.
"""

import hashlib
import json
from pathlib import Path
import re
import runpy
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
BUILD = ROOT / "build/ipad-hardware"
JOURNAL_PATH = "/var/jb/var/lib/mac2jb-u2-native/restore-journal.json"
TAG = "U3_RESUME "
BROKER_LABEL = re.compile(r"dev\.mac2jb\.u2\.[a-z0-9]{1,24}\Z")


def step(name, command, accept=0):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=900)
    text = result.stdout.decode("utf-8", "replace").strip()
    if result.returncode != accept:
        print(TAG + "stopped at %s" % name, flush=True)
        print(text, flush=True)
        raise SystemExit(1)
    return text


def ssh_command():
    return runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()


def retained_journal():
    """The digest and boot session of whatever journal is on the device now.

    Read from the newest restore kit rather than the device, so the archive
    tool's own precondition - that a kit holds the exact bytes - is the same
    fact this relies on.
    """
    kits = sorted((BUILD / "u2-wifi-restore-kit").iterdir())
    if not kits:
        return None
    copy = kits[-1] / "device" / JOURNAL_PATH.lstrip("/")
    if not copy.is_file():
        return None
    return hashlib.sha256(copy.read_bytes()).hexdigest()


def main():
    print(step("pinned Wi-Fi SSH", [sys.executable, str(HOST / "check-pinned-wireless-ssh.py")]),
          flush=True)
    usb = step("Mac USB", [sys.executable, str(HOST / "diagnose-usb-recognition.py")])
    if "USBMUX query=ok count=1" not in usb:
        print(TAG + "stopped: the reboot did not restore Mac USB", flush=True)
        print(usb, flush=True)
        raise SystemExit(1)

    # A kit first, so the journal exists off the device before anything retires it.
    print(step("restore kit", [sys.executable, str(HOST / "backup-u2-wifi-restore-kit.py")]),
          flush=True)
    digest = retained_journal()
    if digest is None:
        print(TAG + "journal=absent nothing-to-retire", flush=True)
    else:
        archive = HOST / "archive-u2-old-boot-journal-wifi.py"
        print(step("inspect old-boot journal", [sys.executable, str(archive), "--inspect", digest]),
              flush=True)
        print(step("archive old-boot journal", [sys.executable, str(archive), "--archive", digest]),
              flush=True)
        print(step("verify archive", [sys.executable, str(archive), "--verify", digest]), flush=True)

    # The old baseline belongs to the old boot; keep it as evidence, never delete.
    old = BUILD / "u2-v9-trial-baseline"
    if old.is_dir():
        retired = BUILD / ("u2-v9-trial-baseline.oldboot-%s" % hashlib.sha256(
            (old / "manifest.json").read_bytes()).hexdigest()[:8])
        if retired.exists():
            print(TAG + "stopped: a retired baseline under that name already exists", flush=True)
            raise SystemExit(1)
        old.rename(retired)
        print(TAG + "retired-old-baseline=%s" % retired.name, flush=True)
    baseline = step("capture baseline", [sys.executable, str(HOST / "capture-u2-trial-baseline.py")])
    print(baseline, flush=True)
    found = re.search(r"manifest-sha256=([0-9a-f]{64})", baseline)
    if not found:
        print(TAG + "stopped: the baseline printed no manifest digest", flush=True)
        raise SystemExit(1)

    print(step("strict check against the new baseline, journal absent",
               [sys.executable, str(HOST / "check-u2-trial-current.py"),
                "--expect-journal=absent"], accept=1), flush=True)

    print(TAG + "PIN THIS: set MANIFEST_SHA256 in host/check-u2-trial-current.py to "
          + found.group(1), flush=True)
    print(TAG + "the strict check above is expected to fail until that pin is updated",
          flush=True)

    # The limit belongs to the process and a reboot gave us a new one.
    label = None
    listing = subprocess.run(ssh_command() + ["/var/jb/bin/launchctl list 2>/dev/null"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    for line in listing.stdout.decode("utf-8", "replace").splitlines():
        candidate = line.split("\t")[-1].strip()
        if BROKER_LABEL.match(candidate):
            label = candidate
    if label is None:
        print(TAG + "stopped: no mac2jb broker job is loaded", flush=True)
        raise SystemExit(1)
    payload = (DEVICE / "u3-set-broker-memory-limit.py").read_text()
    print(step("raise the broker's jetsam limit",
               ssh_command() + ["/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(payload) +
                                " --raise " + shlex.quote(label)]), flush=True)

    staged = sorted(BUILD.glob("u3-hid-canary-v1"))
    if staged:
        print(TAG + "mac-canary-sha256=" + hashlib.sha256(staged[0].read_bytes()).hexdigest(),
              flush=True)
    print(TAG + "ready broker=%s - pin the baseline digest, then run the trial" % label, flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(TAG + "rejected (%s)" % error, flush=True)
        raise SystemExit(1)
