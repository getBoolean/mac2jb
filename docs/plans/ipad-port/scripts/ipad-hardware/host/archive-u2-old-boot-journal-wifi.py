#!/usr/bin/env python3
"""Retire a restore journal left over from a previous boot, over pinned Wi-Fi SSH.

A journal's recipe is bound to the boot session it was written in and every
broker path validates that, so after a reboot it can be neither confirmed nor
restored, and it blocks the next trial, which requires no journal. The reboot
has already made its restore target moot: a USB description does not survive
one. So the exact bytes are archived on the device under a fixed name and the
active name is unlinked - nothing is deleted and no controller call is made.

Preconditions, checked here before and after: healthy Mac USB, a configured
controller, a Wi-Fi restore kit holding the exact journal bytes, and the
device-side guards (digest, recorded boot session, and a refusal if the journal
belongs to the running boot - that one is resolvable the ordinary way).

The broker is deliberately left running. Its lease check skips any phase that
is not `prepared` or `published`, and every other path validates the recipe
identity and refuses a foreign boot, so it does not touch this file; booting it
out would add a way to leave the device without a broker for no gain.

Usage: --inspect | --archive | --verify  SHA256
"""

import hashlib
import json
from pathlib import Path
import runpy
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
BUILD = ROOT / "build/ipad-hardware"
PAYLOAD = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u3-archive-old-boot-journal.py"
PAYLOAD_SHA256 = "d06439b64a7c4b91ae2e500a25c0024e8c6c219e305ccdbe6e76e08ce74d1f07"
JOURNAL_PATH = "/var/jb/var/lib/mac2jb-u2-native/restore-journal.json"
TAG = "U3_OLD_JOURNAL "
MODES = ("--inspect", "--archive", "--verify")


def payload_source():
    data = PAYLOAD.read_bytes()
    if hashlib.sha256(data).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("device payload changed; repin its digest")
    return data.decode("utf-8")


def kit_holds(expected):
    """The newest Wi-Fi restore kit holds exactly these journal bytes.

    Archival is reversible only while a copy exists off the device, so this
    refuses unless one provably does.
    """
    kits = sorted((BUILD / "u2-wifi-restore-kit").iterdir())
    if not kits:
        raise ValueError("no Wi-Fi restore kit")
    manifest = json.loads((kits[-1] / "manifest.json").read_bytes())
    entries = [item for item in manifest["device"]
               if item.get("path") == JOURNAL_PATH and item.get("sha256") == expected]
    if len(entries) != 1:
        raise ValueError("newest restore kit lacks the exact journal")
    copy = kits[-1] / "device" / JOURNAL_PATH.lstrip("/")
    if hashlib.sha256(copy.read_bytes()).hexdigest() != expected:
        raise ValueError("restore kit copy does not match")
    return kits[-1].name


def recorded_boot_session(expected):
    """The journal's own boot session, read from the Mac's kit copy."""
    import base64
    kits = sorted((BUILD / "u2-wifi-restore-kit").iterdir())
    copy = kits[-1] / "device" / JOURNAL_PATH.lstrip("/")
    envelope = json.loads(copy.read_bytes())
    inner = json.loads(base64.b64decode(envelope["payload"], validate=True))
    session = inner["recipe"]["bootSession"]
    if not session:
        raise ValueError("journal records no boot session")
    return session


def external(stage):
    usb = subprocess.run([sys.executable, str(HOST / "diagnose-usb-recognition.py")],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if (usb.returncode or b"USBMUX query=ok count=1\n" not in usb.stdout or
            b"raw-ipad=yes current-configuration=5" not in usb.stdout):
        raise ValueError("Mac USB not healthy %s" % stage)
    census = subprocess.run([sys.executable, str(HOST / "read-u2-xdci-child-census-wifi.py")],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    if (census.returncode or
            b"DeviceState=configured OnBus=yes SelectedConfiguration=5" not in census.stdout):
        raise ValueError("controller not configured %s" % stage)


def remote(mode, expected, session):
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    result = subprocess.run(
        [*ssh, "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(payload_source()) +
         " " + shlex.quote(mode) + " " + shlex.quote(expected) + " " + shlex.quote(session)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=180)
    return result.returncode, result.stdout.decode("ascii", "replace").strip()


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in MODES or len(sys.argv[2]) != 64:
        raise ValueError("usage: --inspect|--archive|--verify SHA256")
    mode, expected = sys.argv[1], sys.argv[2]
    kit = kit_holds(expected)
    session = recorded_boot_session(expected)
    external("before")
    code, out = remote(mode, expected, session)
    print(out, flush=True)
    if code:
        raise ValueError("device refused")
    external("after")
    print(TAG + "mode=%s kit=%s usb=healthy-before-and-after" % (mode[2:], kit), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(TAG + "rejected (%s)" % error, flush=True)
        raise SystemExit(1)
