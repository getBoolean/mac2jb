#!/usr/bin/env python3
"""Hash-pin and validate one read-only XDCI per-node function census over root Wi-Fi SSH.

Effect: runs the pinned device payload once over pinned root SSH; the payload
only reads IORegistry. Prints validated categorical output; writes nothing.
"""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-xdci-function-census.py"
SOURCE_SHA256 = "f4d33dafc4442c166adbfc38fe5bffc75206913cb7f0e518ba721711d9f33674"
HEADER = re.compile(rb"U2_XDCI_FUNCTIONS nodes=([1-9][0-9]{0,2})\n")
NODE = re.compile(
    rb"U2_XDCI_NODE i=([0-9]{1,3}) parent=(-1|[0-9]{1,3}) depth=([0-6]) "
    rb"class=[A-Za-z][A-Za-z0-9_]{0,99} busy=([0-9]{1,2}|unknown)"
    rb"( function=[A-Za-z0-9_+-]{1,64})?( creator=[A-Za-z0-9._-]{1,48})?\n")


def validate(output):
    if len(output) > 16384:
        raise ValueError("oversize census")
    lines = output.splitlines(keepends=True)
    if len(lines) < 3 or lines[-1] != b"U2_XDCI_FUNCTIONS done\n":
        raise ValueError("incomplete census")
    head = HEADER.fullmatch(lines[0])
    if not head or int(head[1]) != len(lines) - 2 or int(head[1]) > 128:
        raise ValueError("invalid census header")
    depths = {}
    for expected, line in enumerate(lines[1:-1]):
        match = NODE.fullmatch(line)
        if not match or int(match[1]) != expected:
            raise ValueError("invalid node line")
        parent, depth = int(match[2]), int(match[3])
        if expected == 0:
            if parent != -1 or depth != 0 or b"class=AppleT8112USBXDCI " not in line:
                raise ValueError("invalid root")
        elif parent not in depths or depths[parent] != depth - 1:
            raise ValueError("invalid parent relation")
        depths[expected] = depth


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 16384:
        raise ValueError("unsafe source")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("source changed")
    wireless = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22", "root@" + address,
               "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii"))]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=25)
    if result.returncode or len(result.stdout) > 16384:
        raise ValueError("device census failed")
    validate(result.stdout)
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_XDCI_FUNCTIONS rejected")
        raise SystemExit(1)
