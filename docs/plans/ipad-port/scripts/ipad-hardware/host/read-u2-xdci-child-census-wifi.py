#!/usr/bin/env python3
"""Hash-pin and validate one read-only XDCI child census over root Wi-Fi SSH."""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-xdci-child-census.py"
SOURCE_SHA256 = "d91cf47e88f1763dc4476b711f03c1afe6a5fc90f01e267cfe11de4dde04f27a"
CLASS = rb"[A-Za-z][A-Za-z0-9_]{0,99}"
EDGE = re.compile(rb"U2_XDCI_EDGE depth=([1-5]) provider=(" + CLASS +
                  rb") client=(" + CLASS + rb") count=([1-9][0-9]{0,1})\n")
HEADER = re.compile(rb"U2_XDCI_CENSUS nodes=([1-9][0-9]?) edges=([0-9]|[1-4][0-9])\n")
DESCRIPTION = re.compile(rb"U2_XDCI_DESCRIPTION BcdUSBVersion=([0-9]{1,5}) MPS0=([0-9]{1,3})\n")
STATE = re.compile(rb"U2_XDCI_STATE DeviceState=(disconnected|attached|powered|default|addressed|configured|suspended|other) OnBus=(yes|no) SelectedConfiguration=([0-9]{1,3})\n")


def validate(output):
    if len(output) > 8192:
        raise ValueError("oversize census")
    lines = output.splitlines(keepends=True)
    if len(lines) < 4 or lines[-1] != b"U2_XDCI_CENSUS done\n":
        raise ValueError("incomplete census")
    head = HEADER.fullmatch(lines[0])
    desc = DESCRIPTION.fullmatch(lines[1])
    state = STATE.fullmatch(lines[2])
    if not head or not desc or not state:
        raise ValueError("invalid census scalar")
    nodes, edge_count = map(int, head.groups())
    if not 1 <= nodes <= 96 or edge_count > 48 or edge_count != len(lines) - 4:
        raise ValueError("invalid census cardinality")
    if int(desc[1]) > 65535 or int(desc[2]) > 255 or int(state[3]) > 255:
        raise ValueError("invalid scalar range")
    # The controller class is device-specific: take it from the first depth-1 edge.
    first = EDGE.fullmatch(lines[3]) if len(lines) > 4 else None
    previous = {0: {first[2]}} if first else {0: set()}
    seen = set()
    ordered = []
    total = 0
    for line in lines[3:-1]:
        match = EDGE.fullmatch(line)
        if not match:
            raise ValueError("invalid child edge")
        depth = int(match[1])
        edge = (depth, match[2], match[3])
        if edge in seen or match[2] not in previous.get(depth - 1, set()):
            raise ValueError("invalid provider relation")
        seen.add(edge)
        ordered.append(edge)
        previous.setdefault(depth, set()).add(match[3])
        total += int(match[4])
    if total != nodes - 1:
        raise ValueError("invalid node total")
    if sorted(ordered) != ordered:
        # The payload sorts edges; enforce a canonical, ID-independent form.
        raise ValueError("noncanonical edge order")


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
                            timeout=20)
    if result.returncode or len(result.stdout) > 8192:
        raise ValueError("device census failed")
    validate(result.stdout)
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_XDCI_CENSUS rejected")
        raise SystemExit(1)
