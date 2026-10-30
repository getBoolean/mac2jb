#!/usr/bin/env python3
"""Check only in-memory mutation of a cloned stock description.

The pinned root Wi-Fi SSH payload creates the current opaque description,
checks it against live registry fields, changes only the clone in memory, and
rechecks equality. It writes no controller, bus, registry, or device file.
"""

import hashlib
from pathlib import Path
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "scripts/ipad-hardware/host"
SOURCE = ROOT / "scripts/ipad-hardware/device/u2-readonly-clone-mutable.py"
SOURCE_SHA256 = "2380d4725816f2aa3e3068bddfc1015b5bcdd599d517e5e3a9ba0d36af0af50b"


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 16 * 1024:
        raise ValueError("unsafe source")
    payload = SOURCE.read_bytes()
    if hashlib.sha256(payload).hexdigest() != SOURCE_SHA256:
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
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B", "-"]
    result = subprocess.run(command, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=12)
    prefix = b"U2_CLONE_IN_MEMORY stock=equal mutable=yes roundtrip=equal\n"
    if (result.returncode or len(result.stdout) > 256 or
            result.stdout != prefix):
        raise ValueError("clone in-memory check unavailable")
    print(result.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            UnicodeError, subprocess.TimeoutExpired):
        print("U2_CLONE_IN_MEMORY rejected")
        raise SystemExit(1)
