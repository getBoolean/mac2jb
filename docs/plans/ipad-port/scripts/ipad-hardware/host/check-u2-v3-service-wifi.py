#!/usr/bin/env python3
"""Check the exact idle v3 trial service over pinned root Wi-Fi SSH.

The device payload reads binary/plist/archive metadata and sends only a
status request to the existing root-owned socket. It never asks the broker
to prepare, publish, restore, confirm, or cycle the bus.
"""

import hashlib
from pathlib import Path
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-readonly-trial-v3-status.py"
SOURCE_SHA256 = "eae1473dfd916d715bbc0dc95d9c84f5a8fdb63f94f6b25699f00e94bfce81b6"


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16 * 1024:
        raise ValueError("unsafe status source")
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("status source changed")
    wireless = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    remote = "/var/jb/usr/bin/python3 -I -S -B -c " + shlex.quote(source.decode("ascii")) + " --status"
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, remote]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=12)
    expected = (b"U2_TRIAL_V3 job=loaded running=yes binary=exact plist=exact "
                b"socket=responding phase=absent publication=enabled archives=retained\n")
    if result.returncode or result.stdout != expected:
        raise ValueError("v3 service not exact and idle")
    print(expected.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_TRIAL_V3 rejected")
        raise SystemExit(1)
