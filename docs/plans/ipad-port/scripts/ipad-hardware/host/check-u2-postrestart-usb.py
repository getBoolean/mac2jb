#!/usr/bin/env python3
"""Read-only U2 postrestart check over a temporary pinned USB SSH tunnel.

This verifies one Mac USBMux iPad, existing pairing, the durable Mac SSH key
and host pin, then starts the repository's bounded localhost iproxy tunnel.
It sends only digest-pinned snapshot and journal classifiers to root, compares
the boot token and original live description with the private v2 pretrial
reference in Mac memory, prints categories, and closes the tunnel. It makes
no iPad file or USB-controller change and never prints private identifiers.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import runpy
import signal
import stat
import struct
import subprocess
import time


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
DEVICE = ROOT / "scripts/ipad-hardware/device"
TUNNEL = HOST / "start-usb-ssh-tunnel.sh"
REFERENCE = ROOT / "build/ipad-hardware/u2-recovered-boot-baseline/snapshot.json"
SNAPSHOT = DEVICE / "u2_target_snapshot.py"
SNAPSHOT_SHA256 = "b31079908483b290aeb7d23e7b9d7ed96af1b4b550e5e0124a026329ce9723ba"
JOURNAL = DEVICE / "u2-readonly-native-journal-state.py"
JOURNAL_SHA256 = "cb5992879a3f216eb12a51433f33dd73f51735a5ce6263783ed4e014c8ab24a3"
DESCRIPTION = DEVICE / "u1-readonly-controller-description-copy.py"
DESCRIPTION_SHA256 = "b2470a242e1984b746bddf92cd15a1570766bdf6dd6fcbeadc3efb0c3b5f650a"
EXPECTED_JOURNAL = "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0"


def checked(path, digest, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= limit:
        raise ValueError("unsafe source")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("source changed")
    return data


def command(args, *, payload=None, timeout=15, limit=32768):
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout)
    if result.returncode or len(result.stdout) > limit:
        raise ValueError("read-only command unavailable")
    return result.stdout


def tunnel_ready():
    result = subprocess.run(["/usr/sbin/lsof", "-nP", "-iTCP:2222",
                             "-sTCP:LISTEN"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=5)
    return result.returncode == 0


def ssh(helper, payload, limit=32768):
    args = ["/usr/bin/ssh", *helper["ssh_options"](), "-T", "-p", "2222",
            "root@127.0.0.1", "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    return command(args, payload=payload, timeout=20, limit=limit)


def main():
    usb = command(["/opt/homebrew/bin/idevice_id", "-l"], limit=256)
    if len(usb.splitlines()) != 1 or not re.fullmatch(rb"[0-9A-Fa-f-]{16,64}", usb.strip()):
        raise ValueError("USB device count")
    command(["/opt/homebrew/bin/idevicepair", "validate"], limit=512)
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    source = checked(SNAPSHOT, SNAPSHOT_SHA256, 16 * 1024)
    journal_source = checked(JOURNAL, JOURNAL_SHA256, 16 * 1024)
    description_source = checked(DESCRIPTION, DESCRIPTION_SHA256, 16 * 1024)
    reference = json.loads(REFERENCE.read_bytes())["snapshot"]
    if tunnel_ready():
        raise ValueError("USB tunnel port already occupied")
    tunnel = subprocess.Popen(["/bin/sh", str(TUNNEL)], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=True)
    try:
        for _ in range(40):
            if tunnel_ready():
                break
            if tunnel.poll() is not None:
                raise ValueError("USB tunnel failed")
            time.sleep(0.125)
        if not tunnel_ready():
            raise ValueError("USB tunnel unavailable")
        payload = (
            "import hashlib,json\n"
            "m={'__name__':'u2_target_snapshot'}\n"
            "exec(compile(" + repr(source) + ",'u2_target_snapshot.py','exec'),m)\n"
            "identity={'product_type':m['_sysctl'](b'hw.machine').rstrip(b'\\0').decode('ascii'),"
            "'os_build':m['_sysctl'](b'kern.osversion').rstrip(b'\\0').decode('ascii'),"
            "'boot_session':hashlib.sha256(m['_sysctl'](b'kern.boottime')).hexdigest(),"
            "'source_sha256':m['_configuration_digest']()}\n"
            "print(json.dumps({'identity':identity},"
            "sort_keys=True,separators=(',',':')))\n"
        ).encode("ascii")
        captured = json.loads(ssh(helper, payload))
        identity = captured["identity"]
        if (identity["product_type"] != "iPad14,5" or
                identity["os_build"] != "21A329" or
                identity["source_sha256"] != reference["identity"]["source_sha256"]):
            raise ValueError("target identity changed")
        descriptions = ssh(helper, description_source, limit=1024 * 1024)
        magic = b"MAC2JB-U1-DESC\0"
        if not descriptions.startswith(magic) or len(descriptions) < len(magic) + 8:
            raise ValueError("description framing")
        default_len, live_len = struct.unpack_from(">II", descriptions, len(magic))
        offset = len(magic) + 8
        if (not 8 <= default_len <= 512 * 1024 or
                not 8 <= live_len <= 512 * 1024 or
                len(descriptions) != offset + default_len + live_len):
            raise ValueError("description length")
        live = plistlib.loads(descriptions[offset + default_len:])
        original = plistlib.loads(base64.b64decode(reference["live_b64"], validate=True))
        if not isinstance(live, dict) or not isinstance(original, dict):
            raise ValueError("invalid live description")
        extra = set(live) - set(original)
        live_state = "original" if live == original else "changed"
        if extra == {"AllowMultipleCreates"} and live.get("AllowMultipleCreates") is True:
            trimmed = dict(live)
            trimmed.pop("AllowMultipleCreates")
            if trimmed == original:
                live_state = "original-plus-flag"
        journal = ssh(helper, journal_source)
        expected = ("U2_NATIVE_JOURNAL phase=awaitingVerification sha256=" +
                    EXPECTED_JOURNAL + "\n").encode("ascii")
        journal_state = "retained-exact" if journal == expected else "changed"
        print("U2_POSTRESTART_USB boot=" +
              ("same" if identity["boot_session"] == reference["identity"]["boot_session"] else "new") +
              " live=" + live_state + " journal=" + journal_state +
              " usbmux=one pairing=valid ssh=root")
    finally:
        if tunnel.poll() is None:
            os.killpg(tunnel.pid, signal.SIGTERM)
            try:
                tunnel.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(tunnel.pid, signal.SIGKILL)
                tunnel.wait(timeout=3)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired, plistlib.InvalidFileException):
        print("U2_POSTRESTART_USB rejected; no journal change")
        raise SystemExit(1)
