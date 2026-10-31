#!/usr/bin/env python3
"""Classify the current U2 recovery stage without changing the iPad.

This host script sends the already digest-pinned target snapshot source to
Python over pinned root Wi-Fi SSH, but calls only its read-only kern.boottime
sysctl helper. It compares the hashed boot token with the private original
baseline, then runs existing read-only description, USB and journal probes.
Only categorical results leave the process. It writes no file, sends no USB
request, and never starts, stops or confirms the trial service.
"""

import hashlib
import json
from pathlib import Path
import re
import runpy
import stat
import subprocess
import base64


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
GO = ROOT / "build/ipad-hardware/run-readonly-controller-property-keys-wifi"
CHECK = runpy.run_path(str(HOST / "check-u2-external-current.py"))
SNAPSHOT = runpy.run_path(str(HOST / "capture-u2-private-baseline.py"))
WIRELESS = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
HELPER = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
HEX = re.compile(rb"[0-9a-f]{64}\n\Z")


def bounded(command, maximum=512, timeout=20):
    result = subprocess.run(command, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout)
    if result.returncode or len(result.stdout) > maximum:
        raise ValueError("read-only query unavailable")
    return result.stdout


def read_boot_token():
    source_path = SNAPSHOT["SOURCE"]
    info = source_path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024):
        raise ValueError("unsafe snapshot source")
    source = source_path.read_bytes()
    if hashlib.sha256(source).hexdigest() != SNAPSHOT["SOURCE_SHA256"]:
        raise ValueError("snapshot source changed")
    address = WIRELESS["read_address"]()
    if address is None:
        raise ValueError("pinned wireless address unavailable")
    for path, digest in ((HELPER["IDENTITY"], HELPER["IDENTITY_SHA256"]),
                         (HELPER["KNOWN_HOSTS"], HELPER["KNOWN_HOSTS_SHA256"])):
        HELPER["checked_local"](path, digest, 0o600)
    payload = (
        "import hashlib\n"
        "m={'__name__':'u2_target_snapshot'}\n"
        "exec(compile(" + repr(source) + ",'u2_target_snapshot.py','exec'),m)\n"
        "print(hashlib.sha256(m['_sysctl'](b'kern.boottime')).hexdigest())\n"
    ).encode("ascii")
    command = ["/usr/bin/ssh", *HELPER["ssh_options"](),
               "-o", "HostKeyAlias=" + WIRELESS["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode or not HEX.fullmatch(result.stdout):
        raise ValueError("boot token unavailable")
    return result.stdout.decode("ascii").strip()


def boot_category():
    previous = json.loads(CHECK["private"]("current.json"))
    old = previous["snapshot"]["identity"]["boot_session"]
    if not re.fullmatch(r"[0-9a-f]{64}", old):
        raise ValueError("unsafe original boot token")
    return "same" if read_boot_token() == old else "new"


def main():
    boot = boot_category()
    desc = bounded([str(GO), "--descriptions"])
    match = re.fullmatch(
        rb"DESCRIPTION_TYPES query=ok default=dict:[0-9]+ live=dict:([0-9]+)\n", desc)
    if not match:
        raise ValueError("description shape unavailable")
    fields = int(match[1])
    live = str(fields) if fields in (16, 17) else "other"
    usb = bounded(["/usr/bin/python3", str(HOST / "diagnose-usb-recognition.py")])
    mac = "present" if (b"USBMUX query=ok count=1\n" in usb and
                        b"IOREG raw-ipad=yes " in usb) else "absent"
    journal = bounded(["/usr/bin/python3", str(
        HOST / "run-u2-readonly-default-description-wifi.py"), "--native-journal"])
    expected = ("U2_NATIVE_JOURNAL phase=restoring sha256=" +
                "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39\n").encode()
    retained = "yes" if journal == expected else "changed"
    print(f"U2_RECOVERY_STAGE boot={boot} live-fields={live} mac-usb={mac} "
          f"old-journal={retained}")
    if boot != "new" or live != "16" or mac != "present":
        return
    old = json.loads(CHECK["private"]("current.json"))
    current = SNAPSHOT["capture"]()
    source = "equal" if all(
        current["snapshot"]["identity"][key] ==
        old["snapshot"]["identity"][key]
        for key in ("product_type", "os_build", "source_sha256")) else "changed"
    stock = "equal" if (
        current["live_sha256"] == old["live_sha256"] and
        base64.b64decode(current["snapshot"]["live_b64"], validate=True) ==
        base64.b64decode(old["snapshot"]["live_b64"], validate=True)) else "changed"
    trust = "equal" if current["mac"] == old["mac"] else "changed"
    categories = {}
    for name, source_script in CHECK["CAPTURES"].items():
        if name == "current.json":
            continue
        result = runpy.run_path(str(HOST / source_script))["capture"]()
        data = result[0] if name == "raw-configs.bin" else CHECK["canonical"](result)
        categories[name] = "equal" if data == CHECK["private"](name) else "changed"
    print("U2_RECOVERY_COMPARE target=" + source + " live=" + stock +
          " pairing=" + trust + " raw=" + categories["raw-configs.bin"] +
          " interfaces=" + categories["host-interfaces.json"] +
          " scalars=" + categories["host-usb-scalars.json"])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_RECOVERY_STAGE rejected")
        raise SystemExit(1)
