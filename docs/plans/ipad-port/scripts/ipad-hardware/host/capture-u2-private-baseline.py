#!/usr/bin/env python3
"""Save a private, read-only U2 baseline for the exact connected iPad.

The host checks pinned Wi-Fi SSH, captures the iPad's live USB description,
identity, boot, and stock-source hash in memory, then checks Mac USB/network
discovery and existing pairing. It creates one owner-only file under the
ignored build tree; it writes nothing on the iPad and publishes no descriptor.
The public output contains only status categories and hashes. A pre-existing
baseline is never overwritten. Mac IORegistry properties are useful but do
not by themselves prove the full external USB function set.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2_target_snapshot.py"
SOURCE_SHA256 = "24aa165bc438a6763cf2aca1315d2db4e5dd6143dffef4b31d0ee6aacb54152a"
WIRELESS = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
DESTINATION = ROOT / "build/ipad-hardware/u2-baseline"
TARGET = DESTINATION / "current.json"


def checked(command, timeout=12):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout)
    if result.returncode != 0 or len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("baseline source unavailable")
    return result.stdout


def one_device(args):
    lines = [line.strip() for line in checked(args).splitlines() if line.strip()]
    if len(lines) != 1 or not re.fullmatch(rb"[0-9a-fA-F-]{16,64}", lines[0]):
        raise ValueError("device count or identifier")
    return lines[0]


def trusted_usb():
    usb = one_device(["/opt/homebrew/bin/idevice_id", "-l"])
    network = [line.strip() for line in checked(
        ["/opt/homebrew/bin/idevice_id", "-n"]).splitlines() if line.strip()]
    if (not network or len(set(network)) != len(network) or
            any(not re.fullmatch(rb"[0-9a-fA-F-]{16,64}", item)
                for item in network) or usb not in network):
        raise ValueError("USB target absent or ambiguous on network")
    checked(["/opt/homebrew/bin/idevicepair", "-u", usb.decode("ascii"), "validate"])
    checked(["/opt/homebrew/bin/idevicepair", "-n", "-u",
             usb.decode("ascii"), "validate"])
    return len(network)


def capture():
    source_info = SOURCE.lstat()
    if not stat.S_ISREG(source_info.st_mode) or source_info.st_size > 16 * 1024:
        raise ValueError("unsafe snapshot source")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("snapshot source changed")
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe private address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    payload = (
        "import base64,json\n"
        "m={'__name__':'u2_target_snapshot'}\n"
        "exec(compile(" + repr(source) + ",'u2_target_snapshot.py','exec'),m)\n"
        "identity,live=m['capture']()\n"
        "print(json.dumps({'identity':identity,'live_b64':base64.b64encode(live).decode('ascii')},"
        "sort_keys=True,separators=(',',':')))\n"
    ).encode("ascii")
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    remote = subprocess.run(command, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20)
    if remote.returncode != 0 or len(remote.stdout) > 20 * 1024:
        raise ValueError("target snapshot unavailable")
    captured = json.loads(remote.stdout)
    if set(captured) != {"identity", "live_b64"}:
        raise ValueError("snapshot fields")
    identity = captured["identity"]
    if (set(identity) != {"product_type", "os_build", "controller_id",
                         "boot_session", "source_sha256"} or
            identity["product_type"] != "iPad14,5" or
            identity["os_build"] != "21A329" or
            identity["source_sha256"] !=
            "a0f63c8c2372ebd1ed4e49492344a5c1290c530ae8e5c66d88e9ba481792c5fa"):
        raise ValueError("target identity changed")
    live = base64.b64decode(captured["live_b64"], validate=True)
    if len(live) > 512 * 1024 or not live.startswith(b"bplist00"):
        raise ValueError("live description bytes")
    decoded = plistlib.loads(live)
    if not isinstance(decoded, dict) or len(decoded) != 16:
        raise ValueError("live description shape")
    network_count = trusted_usb()
    report = {
        "version": 1, "snapshot": captured,
        "live_sha256": hashlib.sha256(live).hexdigest(),
        "mac": {"usbmux_count": 1, "network_count": network_count,
                "same_device": True, "usb_pair_valid": True,
                "network_pair_valid": True},
    }
    return report


def main():
    report = capture()
    live_sha256 = report["live_sha256"]
    DESTINATION.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(DESTINATION.stat().st_mode) != 0o700:
        raise ValueError("unsafe baseline directory")
    data = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short baseline write")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(DESTINATION, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print("U2_BASELINE target=expected live=dict:16 usbmux=one trust=valid")
    print("U2_BASELINE live-sha256=" + live_sha256)
    print("U2_BASELINE evidence-sha256=" + hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
        print("U2_BASELINE rejected")
        raise SystemExit(1)
