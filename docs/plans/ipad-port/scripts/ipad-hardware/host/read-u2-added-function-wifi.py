#!/usr/bin/env python3
"""Hash-pin and read one named gadget function's registry state over root Wi-Fi SSH.

Effect: runs the pinned read-only device payload once over pinned root SSH and
prints a single categorical outcome; writes nothing. "No interface with that
name appeared" and "it appeared and the open was refused" are separate
outcomes here and are never merged, and neither is printed as a pass. The
read-only payload never opens a user client, so it always reports the open as
not attempted; an authorized trial payload is what reports granted or denied.

Usage: read-u2-added-function-wifi.py <function-name>
"""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u3-readonly-added-function.py"
SOURCE_SHA256 = "efaf197a34bdce85535a1faa4cb79deafd82d8d1a97ffcd9a09608d4b33ca194"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}\Z")
LINE = re.compile(
    r"U2_ADDED_FUNCTION name=([A-Za-z0-9][A-Za-z0-9_.-]{0,31}) "
    r"state=(absent|present) controller=(same|other|unknown) "
    r"clients=([0-9]) open=(not-attempted|granted|denied)\n")
DONE = "U2_ADDED_FUNCTION done\n"
MAX_OUTPUT = 4096


def classify(line):
    """Map one device answer line to exactly one labelled outcome."""
    match = LINE.fullmatch(line)
    if not match:
        raise ValueError("invalid answer line")
    name, state, controller, clients, opened = match.groups()
    if (state == "absent") != (controller == "unknown"):
        raise ValueError("inconsistent placement")
    if state == "absent" and (clients != "0" or opened != "not-attempted"):
        raise ValueError("absent interface cannot have clients or an open result")
    if state == "absent":
        return "absent-service"
    if controller == "other":
        return "wrong-controller"
    if opened == "denied":
        return "open-denied"
    if opened == "granted":
        return "open-granted"
    return "present-not-opened"


def summarize(output):
    """Validate the whole device transcript and return the one outcome line."""
    if not output or len(output) > MAX_OUTPUT:
        raise ValueError("oversize or empty answer")
    lines = output.decode("ascii").splitlines(keepends=True)
    if len(lines) != 2 or lines[1] != DONE:
        raise ValueError("incomplete answer")
    name = LINE.fullmatch(lines[0])
    if not name:
        raise ValueError("invalid answer line")
    return "U2_ADDED_FUNCTION name=%s outcome=%s" % (name[1], classify(lines[0]))


def main():
    if len(sys.argv) != 2 or not NAME.fullmatch(sys.argv[1]):
        raise ValueError("usage: read-u2-added-function-wifi.py <function-name>")
    wanted = sys.argv[1]
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
               "/var/jb/usr/bin/python3 -I -S -B -c " +
               shlex.quote(source.decode("ascii")) + " " + shlex.quote(wanted)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=25)
    if result.returncode or len(result.stdout) > MAX_OUTPUT:
        raise ValueError("device read failed")
    print(summarize(result.stdout))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.TimeoutExpired):
        print("U2_ADDED_FUNCTION rejected")
        raise SystemExit(1)
