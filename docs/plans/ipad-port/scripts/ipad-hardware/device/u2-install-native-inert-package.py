#!/var/jb/usr/bin/python3
"""Install and attest only the publication-disabled native watchdog package.

The pinned Mac runner supplies the exact .deb on stdin. This script requires
an empty package/state preflight, stages the bytes exclusively, checks dpkg's
healthy starting state, installs the package with no maintainer scripts,
attests the exact installed signed binary/plist/private directory, and
bootstraps its rootless launchd job. It accepts only a root-only socket status
of publication=disabled, refusal of prepare, and no journal. It then removes
the exact staged .deb. The installed package/service remain for U2 work and
are tracked in the cleanup ledger. No USB publication call is made.
"""

import hashlib
import os
import plistlib
import socket
import stat
import subprocess
import sys
import time


PACKAGE_SHA256 = "6f328b46fcfd683a8b0c29c898663f5640e5ef53b39ccbe185adfd2320b307e3"
BASELINE_AUDIT_SHA256 = "5ba55429f53bb949757a33e53e5f8124b4e869de3dd5ddddeccfb725e0be3794"
BINARY_SHA256 = "1c7530d5796c27ce50efb4dacd522302ffbd96bbb800513808a929d061baad14"
STAGE = "/var/mobile/Media/.mac2jb-u2-native-watchdog-6f328b46.deb"
BINARY = "/var/jb/usr/libexec/mac2jb-u2-native-watchdog"
PLIST = "/var/jb/Library/LaunchDaemons/dev.mac2jb.u2.watchdog.plist"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
LABEL = "dev.mac2jb.u2.watchdog"
DPKG = "/var/jb/usr/bin/dpkg"
LAUNCHCTL = "/var/jb/bin/launchctl"


def checked_run(command, timeout=12):
    result = subprocess.run(command, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout)
    if result.returncode != 0 or len(result.stdout) > 128 * 1024:
        raise OSError("command failed")
    return result.stdout


def status():
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1)
    try:
        client.connect(STATE + "/broker.sock")
        client.sendall(b"status\n")
        first = client.recv(257)
    finally:
        client.close()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1)
    try:
        client.connect(STATE + "/broker.sock")
        client.sendall(b"prepare\n")
        second = client.recv(257)
    finally:
        client.close()
    return first, second


def main():
    if os.geteuid() != 0:
        raise OSError("root required")
    for path in (STAGE, BINARY, PLIST, STATE):
        if os.path.lexists(path):
            raise OSError("package path already exists")
    # This exact target has pre-existing missing-md5sums metadata for 240
    # packages. Refuse a changed audit, but do not treat that known metadata
    # warning as an incomplete install or silently repair other packages.
    audit = checked_run([DPKG, "--audit"])
    if hashlib.sha256(audit).hexdigest() != BASELINE_AUDIT_SHA256:
        raise OSError("dpkg audit changed")
    prior = subprocess.run([DPKG, "-s", "mac2jb-u2-native-watchdog"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=8)
    if prior.returncode == 0:
        raise OSError("package already registered")
    package = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(package) > 1024 * 1024 or hashlib.sha256(package).hexdigest() != PACKAGE_SHA256:
        raise OSError("package bytes changed")
    fd = os.open(STAGE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            if output.write(package) != len(package):
                raise OSError("short package stage")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        os.unlink(STAGE)
        raise
    installed = subprocess.run([DPKG, "-i", STAGE], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=30)
    if installed.returncode != 0:
        print("U2_NATIVE_INSTALL install-failed stage-retained", flush=True)
        raise OSError("dpkg install failed")
    package_status = checked_run([DPKG, "-s", "mac2jb-u2-native-watchdog"])
    if b"Status: install ok installed" not in package_status:
        raise OSError("package status changed")
    binary_info = os.lstat(BINARY)
    plist_info = os.lstat(PLIST)
    state_info = os.lstat(STATE)
    if (not stat.S_ISREG(binary_info.st_mode) or binary_info.st_uid != 0 or
            stat.S_IMODE(binary_info.st_mode) != 0o755 or
            not stat.S_ISREG(plist_info.st_mode) or plist_info.st_uid != 0 or
            stat.S_IMODE(plist_info.st_mode) != 0o644 or
            not stat.S_ISDIR(state_info.st_mode) or state_info.st_uid != 0 or
            stat.S_IMODE(state_info.st_mode) != 0o700):
        raise OSError("installed metadata changed")
    with open(BINARY, "rb") as source:
        if hashlib.sha256(source.read()).hexdigest() != BINARY_SHA256:
            raise OSError("installed binary changed")
    with open(PLIST, "rb") as source:
        config = plistlib.load(source)
    if config != {
            "Label": LABEL, "ProgramArguments": [BINARY, "--serve"],
            "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 2,
            "UserName": "root"}:
        raise OSError("installed plist changed")
    loaded = subprocess.run([LAUNCHCTL, "print", "system/" + LABEL],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=5).returncode == 0
    if not loaded:
        checked_run([LAUNCHCTL, "bootstrap", "system", PLIST])
    first = second = b""
    for _ in range(30):
        try:
            first, second = status()
            if first:
                break
        except (OSError, socket.timeout):
            pass
        time.sleep(0.1)
    if (first != b"OK phase=absent publication=disabled\n" or
            second != b"ERR rejected\n" or
            os.path.lexists(STATE + "/restore-journal.json")):
        raise OSError("installed service check failed")
    stage_info = os.lstat(STAGE)
    if (not stat.S_ISREG(stage_info.st_mode) or stage_info.st_uid != 0 or
            stat.S_IMODE(stage_info.st_mode) != 0o600 or
            hashlib.sha256(open(STAGE, "rb").read()).hexdigest() != PACKAGE_SHA256):
        raise OSError("staged package changed")
    os.unlink(STAGE)
    print("U2_NATIVE_INSTALL package=attested service=ready publication=disabled stage=removed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("U2_NATIVE_INSTALL rejected")
        raise SystemExit(1)
