#!/usr/bin/env python3
"""Check U2's exact restore constructor on the iPad without USB mutation.

This Mac runner verifies the pinned SSH key/host and fixed repository sources,
then sends them to the iPad's Python process in memory. The device reads its
identity and live description, constructs an equivalent description, and
exits before SetDescription or an off/on-bus call. It writes no iPad file.
Only a categorical result is returned; private descriptions stay on-device.
"""

import hashlib
from pathlib import Path
import re
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
DEVICE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device"
SOURCES = (
    (DEVICE / "u2_target_snapshot.py", "b31079908483b290aeb7d23e7b9d7ed96af1b4b550e5e0124a026329ce9723ba"),
    (DEVICE / "u2_usb_controller.py", "08d564c58ec4d3466cfdcff03c6d706decb68859a45930a25a664e14980c873e"),
)
WIRELESS = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
RESULT = re.compile(rb"U2_CONSTRUCTOR (?:in-memory-equal|rejected)\n\Z")


def checked_source(path, digest):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 32 * 1024:
        raise ValueError("unsafe source")
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != digest:
        raise ValueError("source digest changed")
    return source


def main():
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe private address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    snapshot, controller = (checked_source(*item) for item in SOURCES)
    payload = (
        "try:\n"
        " s={'__name__':'u2_target_snapshot'}\n"
        " exec(compile(" + repr(snapshot) + ",'u2_target_snapshot.py','exec'),s)\n"
        " c={'__name__':'u2_usb_controller'}\n"
        " exec(compile(" + repr(controller) + ",'u2_usb_controller.py','exec'),c)\n"
        " identity,live=s['capture']()\n"
        " result=c['reconstruct_or_publish'](live,int(identity['controller_id']))\n"
        " print('U2_CONSTRUCTOR '+result)\n"
        "except Exception:\n"
        " print('U2_CONSTRUCTOR rejected')\n"
        " raise SystemExit(1)\n"
    ).encode("ascii")
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode != 0 or not RESULT.fullmatch(result.stdout):
        raise ValueError("constructor probe failed")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_CONSTRUCTOR rejected")
        raise SystemExit(1)
