#!/usr/bin/env python3
"""Query installed U1 code-hash trust listing through pinned Wi-Fi SSH.

What this code does: validate the durable Mac key and host pin, read the four
CodeDirectory hashes from the private accepted installed-toolbox attestation,
pin the repository's read-only device payload, and send it to root Python over
Wi-Fi. It accepts only four fixed categorical output lines. It writes no iPad
file, changes no trust cache, and prints no hash, IP address, or cache content.
"""

import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HERE = Path(__file__).resolve().parent
PAYLOAD = ROOT / "scripts/ipad-hardware/device/u1-readonly-toolbox-trust-membership.py"
PAYLOAD_SHA = "bea6ccfcdcf1e5c83dfdd15390f3fe76fcbdee3c55e3e3f447a2b6c66d6a1a28"
MANIFEST = ROOT / "build/ipad-hardware/installed-toolbox-attestation/attestation-manifest.json"
NAMES = ("mac2jb-u1-baseline", "mac2jb-u1-setdescription",
         "mac2jb-u1-controller-client", "mac2jb-u1-interface-client")
LABELS = ("baseline", "setdescription", "controller-client", "interface-client")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def main():
    helper = runpy.run_path(str(HERE / "backup-clienttruth-over-root-ssh.py"))
    wifi = runpy.run_path(str(HERE / "check-pinned-wireless-ssh.py"))
    address = wifi["read_address"]()
    require(address is not None, "private address unavailable")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    source = PAYLOAD.read_bytes()
    require(hashlib.sha256(source).hexdigest() == PAYLOAD_SHA, "payload digest changed")
    data = MANIFEST.read_bytes()
    require(0 < len(data) <= 1024 * 1024, "attestation manifest size")
    manifest = json.loads(data)
    code = manifest["code"]
    by_name = {Path(path).name: value for path, value in code.items()}
    require(set(by_name) == set(NAMES) and len(code) == 4,
            "attestation executable set")
    hashes = []
    for name in NAMES:
        value = by_name[name]["alternateCodeDirectorySha256"]
        require(isinstance(value, str) and HEX64.fullmatch(value) is not None,
                "attestation CodeDirectory hash")
        hashes.append(value[:40])
    remote = "/var/jb/usr/bin/python3 -I -S -B - " + " ".join(hashes)
    command = ["/usr/bin/ssh", *helper["ssh_options"](),
               "-o", "HostKeyAlias=[127.0.0.1]:2222",
               "-o", "AddressFamily=inet", "-T", "-p", "22",
               "root@" + address, remote]
    result = subprocess.run(command, input=source, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=18)
    require(result.returncode == 0 and len(result.stdout) <= 512,
            "bounded trust query failed")
    lines = result.stdout.decode("ascii").splitlines()
    require(len(lines) == 4 and all(
        line in ("TRUST_QUERY " + label + "=listed",
                 "TRUST_QUERY " + label + "=not-listed-in-query")
        for label, line in zip(LABELS, lines)), "trust query output grammar")
    print("\n".join(lines))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError,
            subprocess.TimeoutExpired, UnicodeError) as error:
        print("TRUST_QUERY rejected " + type(error).__name__)
        raise SystemExit(1)
