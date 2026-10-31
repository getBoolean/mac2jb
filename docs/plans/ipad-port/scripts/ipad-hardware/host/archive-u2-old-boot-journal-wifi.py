#!/usr/bin/env python3
"""Back up and archive the failed U2 journal from a previous iPad boot.

The fixed on-device helper first streams the exact validated old journal to
an exclusive, private Mac backup. Only after that backup is fsynced does its
archive mode boot out the stopped old trial job and relocate the journal to
a fixed root-owned archive name. The original bytes remain both on the Mac
and iPad. Preconditions require the new boot, restored original live USB
description, healthy Mac USB/pairing, a stable private current-boot reference,
and the unchanged old journal. It makes no USB controller call and never
starts a service. Interrupted work stays visible for guarded inspection.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
SOURCE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-archive-old-boot-journal.py"
SOURCE_SHA256 = "b750533d6ac957fc040c50b623495852f158af048d0d16dda702aad7c4e7e852"
EXPECTED_JOURNAL = "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39"
DEST = ROOT / "build/ipad-hardware/u2-oldboot-archive"
REFERENCE = ROOT / "build/ipad-hardware/u2-recovered-boot-baseline"
REFERENCE_MANIFEST = "83200527e1bf318a33fd60a20288c7cd8236d760e00b9b970f578867d082c347"
WIRELESS = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
HELPER = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
RECOVERED = runpy.run_path(str(HOST / "capture-u2-recovered-boot-baseline.py"))


def command(args, maximum=512):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=25)
    if result.returncode or len(result.stdout) > maximum:
        raise ValueError("recovery precondition unavailable")
    return result.stdout


def private_reference():
    directory = REFERENCE.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or
            stat.S_IMODE(directory.st_mode) != 0o700):
        raise ValueError("unsafe new-boot reference directory")
    path = REFERENCE / "manifest.json"
    info = path.lstat()
    data = path.read_bytes()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
            hashlib.sha256(data).hexdigest() != REFERENCE_MANIFEST):
        raise ValueError("new-boot reference changed")
    manifest = json.loads(data)
    if (manifest.get("version") != 1 or len(manifest.get("files", {})) != 7 or
            manifest.get("old_journal_sha256") != EXPECTED_JOURNAL or
            set(path.name for path in REFERENCE.iterdir()) !=
            set(manifest["files"]) | {"manifest.json"}):
        raise ValueError("new-boot reference manifest changed")
    for name, digest in manifest["files"].items():
        if not re.fullmatch(r"[a-z0-9.-]{1,64}", name):
            raise ValueError("invalid reference name")
        file = REFERENCE / name
        info = file.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            raise ValueError("new-boot reference file changed")
    current = RECOVERED["capture"]()
    for name in ("snapshot.json", "raw-configs.bin", "host-interfaces.json",
                 "host-usb-scalars.json", "strings.bin"):
        if current[name] != (REFERENCE / name).read_bytes():
            raise ValueError("new-boot USB reference changed")


def preflight():
    if DEST.exists() or DEST.is_symlink():
        raise ValueError("old-boot backup already exists")
    private_reference()
    stage = command(["/usr/bin/python3", str(HOST / "diagnose-u2-recovery-stage.py")],
                    1024)
    if (b"U2_RECOVERY_STAGE boot=new live-fields=16 mac-usb=present old-journal=yes\n"
            not in stage or
            b"U2_RECOVERY_COMPARE target=equal live=equal pairing=equal "
            not in stage or b" scalars=equal\n" not in stage):
        raise ValueError("new-boot USB recovery changed")
    trial = command(["/usr/bin/python3", str(
        HOST / "run-u2-readonly-default-description-wifi.py"), "--trial-status"])
    if (b" job=loaded running=no binary=regular plist=regular " not in trial or
            b" phase=unavailable publication=unavailable " not in trial or
            b" original-job=loaded-stopped\n" not in trial):
        raise ValueError("old trial job changed")
    journal = command(["/usr/bin/python3", str(
        HOST / "run-u2-readonly-default-description-wifi.py"), "--native-journal"])
    if journal != ("U2_NATIVE_JOURNAL phase=restoring sha256=" +
                   EXPECTED_JOURNAL + "\n").encode("ascii"):
        raise ValueError("old journal changed")


def ssh(mode, payload, maximum):
    address = WIRELESS["read_address"]()
    if address is None:
        raise ValueError("pinned wireless address unavailable")
    for path, digest in ((HELPER["IDENTITY"], HELPER["IDENTITY_SHA256"]),
                         (HELPER["KNOWN_HOSTS"], HELPER["KNOWN_HOSTS_SHA256"])):
        HELPER["checked_local"](path, digest, 0o600)
    args = ["/usr/bin/ssh", *HELPER["ssh_options"](),
            "-o", "HostKeyAlias=" + WIRELESS["HOST_KEY_ALIAS"],
            "-o", "AddressFamily=inet", "-T", "-p", "22",
            "root@" + address, "/var/jb/usr/bin/python3", "-I", "-S", "-B",
            "-", mode]
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=25)
    if result.returncode or not 0 < len(result.stdout) <= maximum:
        raise ValueError("old-boot archive remote step failed")
    return result.stdout


def exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError("short private backup write")
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    info = SOURCE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024:
        raise ValueError("unsafe archive helper")
    payload = SOURCE.read_bytes()
    if hashlib.sha256(payload).hexdigest() != SOURCE_SHA256:
        raise ValueError("archive helper changed")
    preflight()
    journal = ssh("--copy", payload, 2_000_000)
    if hashlib.sha256(journal).hexdigest() != EXPECTED_JOURNAL:
        raise ValueError("old journal backup changed")
    os.mkdir(DEST, 0o700)
    exclusive(DEST / "restore-journal.oldboot.json", journal)
    exclusive(DEST / "backup.json", json.dumps({
        "version": 1, "journal_sha256": EXPECTED_JOURNAL,
        "helper_sha256": SOURCE_SHA256,
        "new_boot_reference_manifest_sha256": REFERENCE_MANIFEST,
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
    directory = os.open(DEST, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    if hashlib.sha256((DEST / "restore-journal.oldboot.json").read_bytes()).hexdigest() != EXPECTED_JOURNAL:
        raise ValueError("old journal backup verification failed")
    # Mutate only after the exact private backup is durable and USB state is rechecked.
    stage = command(["/usr/bin/python3", str(HOST / "diagnose-u2-recovery-stage.py")], 1024)
    if (b"U2_RECOVERY_STAGE boot=new live-fields=16 mac-usb=present old-journal=yes\n"
            not in stage):
        raise ValueError("USB recovery changed before archive")
    result = ssh("--archive", payload, 256)
    if result != b"U2_OLD_JOURNAL archive=retained active=absent trial=booted-out\n":
        raise ValueError("archive result changed")
    if ssh("--verify", payload, 256) != (
            b"U2_OLD_JOURNAL archive=verified active=absent trial=absent\n"):
        raise ValueError("old journal verification failed")
    if command(["/usr/bin/python3", str(
        HOST / "run-u2-readonly-default-description-wifi.py"), "--native-journal"]) != (
            b"U2_NATIVE_JOURNAL phase=absent sha256=none\n"):
        raise ValueError("active journal still present")
    print("U2_OLD_JOURNAL archived=verified mac-backup=durable "
          "trial=booted-out active=absent usb-write=none")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError,
            subprocess.TimeoutExpired):
        print("U2_OLD_JOURNAL rejected; inspect private backup and device state")
        raise SystemExit(1)
