#!/usr/bin/env python3
"""Capture a private current-boot U2 baseline after partial reboot recovery.

This reads the iPad snapshot over pinned Wi-Fi SSH, Mac USB descriptors and
interface state, power and USB network binding. The Mac helper sends only
bounded standard IN GET_DESCRIPTOR(STRING) requests without USBDeviceOpen.
It requires a new boot, byte-equal original 16-field live description, the
unchanged old journal, nonrunning old trial service, equal device scalars,
equal interface names and equal raw descriptor bytes outside string indices.
It captures twice and requires the observations to remain equal. Only then
does it create owner-only files under the ignored Mac build directory. It
writes nothing on the iPad and does not certify the first trial's restoration.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
DEST = ROOT / "build/ipad-hardware/u2-recovered-boot-baseline"
CHECK = runpy.run_path(str(HOST / "check-u2-external-current.py"))
SNAPSHOT = runpy.run_path(str(HOST / "capture-u2-private-baseline.py"))
SEMANTIC = runpy.run_path(str(HOST / "diagnose-u2-semantic-descriptors.py"))
PROBE = runpy.run_path(str(HOST / "probe-u2-readonly-string-descriptors.py"))
EXPECTED_JOURNAL = (b"U2_NATIVE_JOURNAL phase=restoring sha256="
                    b"77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39\n")


def command(args, maximum=1024):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=25)
    if result.returncode or len(result.stdout) > maximum:
        raise ValueError("recovery precondition unavailable")
    return result.stdout


def preconditions():
    if DEST.exists() or DEST.is_symlink():
        raise ValueError("recovered baseline already exists")
    journal = command(["/usr/bin/python3", str(
        HOST / "run-u2-readonly-default-description-wifi.py"), "--native-journal"])
    if journal != EXPECTED_JOURNAL:
        raise ValueError("old journal changed")
    trial = command(["/usr/bin/python3", str(
        HOST / "run-u2-readonly-default-description-wifi.py"), "--trial-status"])
    if (b" job=loaded running=no binary=regular plist=regular " not in trial or
            b" phase=unavailable publication=unavailable " not in trial or
            b" original-job=loaded-stopped\n" not in trial):
        raise ValueError("old trial state changed")
    PROBE["pinned"](PROBE["SOURCE"], PROBE["SOURCE_SHA256"], 32 * 1024)
    PROBE["pinned"](PROBE["BINARY"], PROBE["BINARY_SHA256"], 1024 * 1024)
    PROBE["connection"]()
    PROBE["host_usb_ready"]()


def capture():
    old = json.loads(CHECK["private"]("current.json"))
    current = SNAPSHOT["capture"]()
    old_snap = old["snapshot"]
    new_snap = current["snapshot"]
    if (new_snap["identity"]["boot_session"] ==
            old_snap["identity"]["boot_session"] or
            any(new_snap["identity"][key] != old_snap["identity"][key]
                for key in ("product_type", "os_build", "source_sha256")) or
            current["mac"] != old["mac"] or
            current["live_sha256"] != old["live_sha256"] or
            base64.b64decode(new_snap["live_b64"], validate=True) !=
            base64.b64decode(old_snap["live_b64"], validate=True)):
        raise ValueError("new-boot stock identity/live description mismatch")
    raw = runpy.run_path(str(HOST / "capture-u2-raw-configs.py"))["capture"]()[0]
    old_configs = SEMANTIC["configurations"](CHECK["private"]("raw-configs.bin"))
    new_configs = SEMANTIC["configurations"](raw)
    for old_config, new_config in zip(old_configs, new_configs):
        framing, _, other = SEMANTIC["difference"](
            SEMANTIC["descriptors"](old_config),
            SEMANTIC["descriptors"](new_config))
        if framing != "same-framing" or other:
            raise ValueError("raw descriptor structure changed")
    interfaces = runpy.run_path(str(HOST / "capture-u2-host-interfaces.py"))["capture"]()
    old_interfaces = json.loads(CHECK["private"]("host-interfaces.json"))
    if (len(interfaces["interfaces"]) != len(old_interfaces["interfaces"]) or
            any(new["name"] != prior["name"] for prior, new in
                zip(old_interfaces["interfaces"], interfaces["interfaces"]))):
        raise ValueError("host interface names changed")
    scalars = runpy.run_path(str(HOST / "capture-u2-host-usb-scalars.py"))["capture"]()
    if CHECK["canonical"](scalars) != CHECK["private"]("host-usb-scalars.json"):
        raise ValueError("USB device scalars changed")
    power = runpy.run_path(str(HOST / "check-u2-power-wifi.py"))["capture"]()
    if power not in (
            b"POWER_SOURCE query=ok external=yes charging=yes full=no\n",
            b"POWER_SOURCE query=ok external=yes charging=yes full=yes\n",
            b"POWER_SOURCE query=ok external=yes charging=no full=yes\n",
            b"POWER_SOURCE query=ok external=yes charging=no full=no\n"):
        raise ValueError("external power unavailable")
    drivers = runpy.run_path(str(HOST / "check-u2-host-network-function.py"))["capture"]()
    result = subprocess.run([str(PROBE["BINARY"]), "--strings"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=20)
    if result.returncode or len(result.stdout) > 32 * 1024:
        raise ValueError("USB strings unavailable")
    PROBE["strings"](result.stdout)
    PROBE["connection"]()
    PROBE["host_usb_ready"]()
    return {
        "snapshot.json": CHECK["canonical"](current),
        "raw-configs.bin": raw,
        "host-interfaces.json": CHECK["canonical"](interfaces),
        "host-usb-scalars.json": CHECK["canonical"](scalars),
        "strings.bin": result.stdout,
        "power.txt": power,
        "host-network.json": CHECK["canonical"]({"ethernet": drivers[0],
                                                  "ncm_driver": drivers[1]}),
    }


def exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short private baseline write")
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    preconditions()
    first = capture()
    preconditions()
    second = capture()
    if first != second:
        raise ValueError("recovered baseline unstable")
    preconditions()
    manifest = CHECK["canonical"]({
        "version": 1,
        "status": "new-boot-reference-not-old-trial-restore-proof",
        "files": {name: hashlib.sha256(data).hexdigest()
                  for name, data in sorted(first.items())},
        "old_journal_sha256": EXPECTED_JOURNAL.decode("ascii").split("sha256=", 1)[1].strip(),
    })
    os.mkdir(DEST, 0o700)
    if stat.S_IMODE(DEST.stat().st_mode) != 0o700:
        raise ValueError("unsafe private baseline directory")
    for name, data in first.items():
        exclusive(DEST / name, data)
    exclusive(DEST / "manifest.json", manifest)
    directory = os.open(DEST, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print("U2_RECOVERED_BASELINE captured=stable files=8 "
          "old-journal=retained proof=reference-only")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_RECOVERED_BASELINE rejected")
        raise SystemExit(1)
