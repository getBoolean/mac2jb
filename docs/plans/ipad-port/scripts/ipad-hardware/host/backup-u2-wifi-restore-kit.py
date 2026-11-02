#!/usr/bin/env python3
"""Back up everything a later Wi-Fi SSH USB restore needs into one private Mac kit.

Effect: (1) runs the pinned read-only device export once over root Wi-Fi SSH
and saves every U2 state file, journal, broker binary and launchd plist with
SHA-256 verification; (2) copies the Mac-side pinned SSH identity, known-hosts
and address files, the latest private U2 baselines and journal backups, the
healthy-boot reference captures, and a tarball of the repo's iPad scripts and
iOS sources at the current commit. Writes only under a new owner-only
build/ipad-hardware/u2-wifi-restore-kit/<ns>/ directory. Changes nothing on
the iPad. Raw contents may be private: never print or commit them.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shlex
import shutil
import subprocess
import tarfile
import time


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-readonly-restore-kit-export.py"
BUILD = ROOT / "build/ipad-hardware"
KITS = BUILD / "u2-wifi-restore-kit"
SSH_DIR = Path.home() / ".ssh/mac2jb-ipad"
MAC_INPUTS = ("controller-descriptions", "u2-v4-repeat-baseline", "u2-v4-repeat-journal-backup",
              "u2-v7-journal-backup", "u2-v7-baseline", "u2-function-census")
HEAD = re.compile(r"U2_KIT path=(/var/jb/[A-Za-z0-9._/-]+) kind=(file|socket|dir|other) "
                  r"mode=([0-7]+) uid=([0-9]+) links=([0-9]+) size=([0-9]+)"
                  r"(?: sha256=([0-9a-f]{64}) data=([A-Za-z0-9+/=]*))?\Z")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def private_write(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def ssh_command():
    wireless = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    return ["/usr/bin/ssh", *helper["ssh_options"](),
            "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
            "-o", "AddressFamily=inet", "-T", "-p", "22", "root@" + address]


def main():
    KITS.mkdir(mode=0o700, exist_ok=True)
    kit = KITS / str(time.time_ns())
    kit.mkdir(mode=0o700)
    manifest = {"schemaVersion": 1, "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "device": [], "mac": []}
    source = SOURCE.read_bytes()
    manifest["exportSourceSHA256"] = sha(source)
    result = subprocess.run([*ssh_command(), "/var/jb/usr/bin/python3 -I -S -B -c " +
                             shlex.quote(source.decode("ascii"))],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=180)
    lines = result.stdout.decode("ascii").splitlines()
    if result.returncode or not lines or lines[-1] != "U2_KIT done" or not lines[0].startswith("U2_KIT boot-sha256="):
        raise ValueError("device export failed")
    manifest["deviceBootSHA256"] = lines[0].split("=", 1)[1]
    for line in lines[1:-1]:
        if line.endswith(" absent"):
            continue
        match = HEAD.fullmatch(line)
        if not match:
            raise ValueError("invalid export line")
        path, kind, mode, uid, links, size, digest, data = match.groups()
        entry = {"path": path, "kind": kind, "mode": mode, "uid": int(uid),
                 "links": int(links), "size": int(size)}
        if data is not None:
            raw = base64.b64decode(data, validate=True)
            if sha(raw) != digest or len(raw) != int(size):
                raise ValueError("device file digest mismatch")
            private_write(kit / "device" / path.lstrip("/"), raw)
            entry["sha256"] = digest
        manifest["device"].append(entry)
    for item in sorted(SSH_DIR.iterdir()):
        if item.is_file() and not item.is_symlink():
            raw = item.read_bytes()
            private_write(kit / "mac/ssh" / item.name, raw)
            manifest["mac"].append({"path": "~/.ssh/mac2jb-ipad/" + item.name, "sha256": sha(raw)})
    for name in MAC_INPUTS:
        base = BUILD / name
        if not base.exists():
            continue
        for item in sorted(base.rglob("*")):
            if item.is_file() and not item.is_symlink():
                raw = item.read_bytes()
                rel = item.relative_to(BUILD)
                private_write(kit / "mac/build" / rel, raw)
                manifest["mac"].append({"path": "build/ipad-hardware/" + str(rel), "sha256": sha(raw)})
    commit = subprocess.run(["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"],
                            stdout=subprocess.PIPE, timeout=10).stdout.decode().strip()
    manifest["repoCommit"] = commit
    archive = kit / "mac/repo-sources.tar"
    with tarfile.open(archive, "w") as tar:
        for rel in ("docs/plans/ipad-port/scripts/ipad-hardware", "ios", "docs/ipad"):
            tar.add(ROOT / rel, arcname=rel,
                    filter=lambda info: None if "__pycache__" in info.name else info)
    os.chmod(archive, 0o600)
    manifest["mac"].append({"path": "repo-sources.tar", "sha256": sha(archive.read_bytes())})
    private_write(kit / "manifest.json", json.dumps(manifest, indent=1, sort_keys=True).encode())
    files = sum(1 for e in manifest["device"] if "sha256" in e)
    print("U2_KIT saved device-files=%d device-entries=%d mac-files=%d kit=%s" % (
        files, len(manifest["device"]), len(manifest["mac"]), kit.relative_to(ROOT)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError) as error:
        print("U2_KIT rejected: %s" % type(error).__name__)
        raise SystemExit(1)
