#!/usr/bin/env python3
"""Run the pinned read-only controller CurrentState key classifier over Wi-Fi."""

import hashlib
from pathlib import Path
import re
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-controller-state-keys.py"
SHA = "62ba8b1b4196007406adcc7ee52d5e5592913230175a7842ff1989e85cf34faa"
KEY = re.compile(rb"CONTROLLER_STATE_KEY [A-Za-z0-9_. -]{1,100} type="
                 rb"(?:bool|integer|string|data|dictionary|array|other)\n")


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 8192:
        raise ValueError("unsafe source")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SHA:
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
    if result.returncode or len(result.stdout) > 4096:
        raise ValueError("device probe rejected")
    lines = result.stdout.splitlines(keepends=True)
    if not lines or not re.fullmatch(rb"CONTROLLER_STATE_KEYS count=([1-9]|[1-3][0-9]|4[0-8])\n",
                                     lines[0]):
        raise ValueError("invalid key count")
    count = int(lines[0].split(b"=")[1])
    if len(lines) < count + 7:
        raise ValueError("incomplete keys")
    if not all(KEY.fullmatch(line) for line in lines[1:count + 1]):
        raise ValueError("invalid key line")
    if not re.fullmatch(rb"CONTROLLER_STATE link=[ -~]{1,160}\n", lines[count + 1]):
        raise ValueError("invalid link state")
    for offset, name in enumerate((b"DefaultPreferredConfiguration", b"PreferredConfiguration",
                                   b"SelectedConfiguration"), count + 2):
        if not re.fullmatch(rb"CONTROLLER_STATE " + name + rb"=(?:other|[0-9]{1,3})\n",
                            lines[offset]):
            raise ValueError("invalid configuration state")
    if lines[count + 5] not in (b"CONTROLLER_STATE force-off-symbol=present\n",
                               b"CONTROLLER_STATE force-off-symbol=absent\n"):
        raise ValueError("invalid symbol state")
    parent_lines = lines[count + 6:]
    if (not parent_lines or
            not re.fullmatch(rb"CONTROLLER_PARENTS count=(?:[1-9]|10)\n", parent_lines[0])):
        raise ValueError("invalid parent count")
    parent_count = int(parent_lines[0].split(b"=")[1])
    if len(parent_lines) != parent_count + 1:
        raise ValueError("incomplete parents")
    for depth, line in enumerate(parent_lines[1:]):
        if not re.fullmatch(rb"CONTROLLER_PARENT depth=" + str(depth).encode() +
                            rb" class=[A-Za-z0-9_]{1,100}\n", line):
            raise ValueError("invalid parent class")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
        print("CONTROLLER_STATE_KEYS rejected")
        raise SystemExit(1)
