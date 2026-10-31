#!/var/jb/usr/bin/python3
"""Remove U1/U2 leftovers while keeping what is needed to connect and debug.

Effect: `--inspect` is read-only. `--remove` deletes only:
- fixed U1 helper files in /var/mobile/Media (admission smokes, setup/diagnostic
  scripts, a public-key copy; the live keys stay in authorized_keys);
- old U2 broker binaries whose SHA-256 matches the allowlist and whose job is
  not loaded;
- old-boot journal archives whose SHA-256 matches the allowlist (byte copies
  are in the Mac restore kits);
- the publication-disabled `mac2jb-u2-native-watchdog` dpkg package.
It keeps the running v11 broker, its plist and state directory, and every
authorized_keys file, and refuses if v11 is not loaded or a journal is active.
"""

import hashlib
import os
import subprocess
import sys

MEDIA = "/var/mobile/Media/"
MEDIA_FILES = [".mac2jb-u1-admission-platform-control", ".mac2jb-u1-admission-smoke",
               ".mac2jb-u1-auth-diagnostic.py", ".mac2jb-u1-clienttruth-semantics.py",
               ".mac2jb-u1-clienttruth-state.py", ".mac2jb-u1-home-authorize.py",
               ".mac2jb-u1-home-keyfile.py", ".mac2jb-u1-key.pub", ".mac2jb-u1-key.py",
               ".mac2jb-u1-root-authorize.py"]
LIBEXEC = "/var/jb/usr/libexec/.mac2jb-u2-noop-trial-"
OLD_BROKERS = ["cedaa71736aaf0d27f886b5cade552bfd6ee5ff3fde4e9c8eaaac071a8db34c7",
               "87f0b112378b6e38b7d90f770aa20a047f26814170edaa2bd63388aec0b1c380",
               "404f34aa0656222762f7ed228907f7b7940d6462dc2a03db88a5942693b2132c",
               "507b5889012f5f3177cab9443bc1b0c92f50cc79b39aff4012887eedca1733cc",
               "1acbd2495497b0f0b6cb996e1397f2b18bd5b85151536cdc932bd0cd4eefc8e1"]
KEEP_BROKER = "8fdb044ff8840084e27e896432de060deecd6cdc9d27913b9ae3f379077b3736"
STATE = "/var/jb/var/lib/mac2jb-u2-native/"
ARCHIVES = {
    "restore-journal.oldboot-77caed18.json": "77caed18edb899d919eddc6f65229464883b20091b0ae3849bf2af0743abda39",
    "restore-journal.oldboot-v2-f5934b3a.json": "f5934b3ae56c67142d01eaab88443299876d31638c7300fbf0f322c7910e98b0",
    "restore-journal.oldboot-v3-b8e66632.json": "b8e66632f52f59ac13d389f650e71840d90226096bbe0945aeb881562ee7fe3d",
    "restore-journal.oldboot-v4r-639c07c1.json": "639c07c183ebc4e0f8c07b099416d8c66c7ebefb92a5d2227bc19068008d1729",
    "restore-journal.oldboot-v5-2ec38461.json": "2ec384616a51a6375e124ca3643e0bcfd0007783fe50cdab4f544a7bfb748976",
    "restore-journal.oldboot-v7-0f265fd1.json": "0f265fd17847a9db1a1bc6814e39e7da94fd1eaef6e736811e3d618af1bbb02e",
    "restore-journal.oldboot-v8-dbee3a4a.json": "dbee3a4aa6e5f151b3e2897d7b59d2e9be0805be327fa835f5561b75ee38b2cb",
}
LAUNCHCTL = "/var/jb/bin/launchctl"


def sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def loaded(label):
    return subprocess.run([LAUNCHCTL, "print", "system/" + label], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=6).returncode == 0


def main(mode):
    if os.geteuid() != 0 or mode not in ("--inspect", "--remove"):
        raise ValueError("fixed root mode required")
    if not loaded("dev.mac2jb.u2.nooptrialv11") or sha(LIBEXEC + KEEP_BROKER[:8]) != KEEP_BROKER:
        raise ValueError("v11 broker not running")
    if os.path.lexists(STATE + "restore-journal.json"):
        raise ValueError("active journal present")
    plan = []
    for name in MEDIA_FILES:
        if os.path.lexists(MEDIA + name):
            plan.append(MEDIA + name)
    for digest in OLD_BROKERS:
        path = LIBEXEC + digest[:8]
        if os.path.lexists(path):
            if sha(path) != digest:
                raise ValueError("broker binary changed " + digest[:8])
            plan.append(path)
    for name, digest in ARCHIVES.items():
        if os.path.lexists(STATE + name):
            if sha(STATE + name) != digest:
                raise ValueError("archive changed " + name)
            plan.append(STATE + name)
    package = subprocess.run(["/var/jb/usr/bin/dpkg-query", "-W", "-f", "${Status}",
                              "mac2jb-u2-native-watchdog"], capture_output=True, text=True).stdout
    print("U2_CLEANUP plan files=%d package=%s" % (len(plan), "installed" if "installed" in package else "absent"))
    if mode == "--inspect":
        return
    for path in plan:
        os.unlink(path)
    for directory in (MEDIA, STATE, "/var/jb/usr/libexec/"):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    if "installed" in package and loaded("dev.mac2jb.u2.watchdog"):
        raise ValueError("old watchdog job loaded")
    removed_package = "absent"
    if "installed" in package:
        result = subprocess.run(["/var/jb/usr/bin/dpkg", "-r", "mac2jb-u2-native-watchdog"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        removed_package = "removed" if result.returncode == 0 else "dpkg-error"
    print("U2_CLEANUP removed files=%d package=%s v11=%s" % (
        len(plan), removed_package, "running" if loaded("dev.mac2jb.u2.nooptrialv11") else "missing"))


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) == 2 else "")
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("U2_CLEANUP rejected (%s)" % error)
        raise SystemExit(1)
