#!/usr/bin/env python3
"""Stage, run, and remove a harmless signed native U2 admission probe.

This Mac script verifies the exact ad-hoc-signed arm64 iOS binary and pinned
Wi-Fi SSH identity. It creates one exclusive executable under iPad Media,
attempts one root launch with a short timeout, then checks its digest and
removes that exact staged file. The program only writes a fixed stdout line;
it does not call IOKit, alter a USB descriptor, or change SSH/system files.
If cleanup fails, the exact Media path remains in the cleanup ledger.
"""

import hashlib
from pathlib import Path
import plistlib
import runpy
import shlex
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[6]
BINARY = ROOT / "build/ipad-hardware/u2-native-admission-smoke"
DIGEST = "459d1e3f4f0f9c1792920f6dcdd548fecb94753de0d36c1af5e2b6e2b0e2c83c"
STAGE = "/var/mobile/Media/.mac2jb-u2-native-admission-459d1e3f4f0f"
WIRELESS = ROOT / "scripts/ipad-hardware/host/check-pinned-wireless-ssh.py"
HELPER = ROOT / "scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
PYTHON = "/var/jb/usr/bin/python3 -I -S -B -c "


def remote(base, code, input_bytes=b"", timeout=12):
    command = [*base, PYTHON + shlex.quote(code)]
    return subprocess.run(command, input=input_bytes, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=timeout)


def main():
    info = BINARY.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise ValueError("unsafe native binary")
    binary = BINARY.read_bytes()
    if hashlib.sha256(binary).hexdigest() != DIGEST:
        raise ValueError("native binary changed")
    verified = subprocess.run(["/usr/bin/codesign", "--verify", "--strict",
                               str(BINARY)], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=8)
    if verified.returncode != 0:
        raise ValueError("signature invalid")
    entitlement_result = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(BINARY)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
    if entitlement_result.returncode != 0 or plistlib.loads(entitlement_result.stdout) != {
            "platform-application": True,
            "com.apple.private.usbdevice.setdescription": True}:
        raise ValueError("entitlements changed")
    wireless = runpy.run_path(str(WIRELESS))
    helper = runpy.run_path(str(HELPER))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("unsafe private address")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    base = ["/usr/bin/ssh", *helper["ssh_options"](),
            "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
            "-o", "AddressFamily=inet", "-T", "-p", "22", "root@" + address]
    stage_code = (
        "import hashlib,os,stat,sys\n"
        "p=" + repr(STAGE) + "\n"
        "d=sys.stdin.buffer.read(1048577)\n"
        "assert len(d)<=1048576 and hashlib.sha256(d).hexdigest()==" + repr(DIGEST) + "\n"
        "q=os.lstat('/var/mobile/Media')\n"
        "assert stat.S_ISDIR(q.st_mode)\n"
        "f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)\n"
        "try:\n"
        " with os.fdopen(f,'wb') as output:\n"
        "  assert output.write(d)==len(d)\n"
        "  output.flush()\n"
        "  os.fsync(output.fileno())\n"
        "except BaseException:\n"
        " os.unlink(p)\n"
        " raise\n"
        "print('STAGE created')\n"
    )
    cleanup_code = (
        "import hashlib,os,stat;"
        "p=" + repr(STAGE) + ";q=os.lstat(p);"
        "assert stat.S_ISREG(q.st_mode) and q.st_uid==0 and q.st_nlink==1;"
        "assert hashlib.sha256(open(p,'rb').read()).hexdigest()==" + repr(DIGEST) + ";"
        "os.unlink(p);f=os.open('/var/mobile/Media',os.O_RDONLY|os.O_DIRECTORY);"
        "os.fsync(f);os.close(f);assert not os.path.lexists(p);"
        "print('STAGE removed')"
    )
    staged = remote(base, stage_code, binary)
    if staged.returncode != 0 or staged.stdout != b"STAGE created\n":
        raise ValueError("stage failed; inspect cleanup ledger path")
    try:
        launched = subprocess.run([*base, STAGE], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=6)
        category = ("alive" if launched.returncode == 0 and
                    launched.stdout == b"U2_NATIVE_ADMISSION alive\n"
                    else "not-admitted")
        print("U2_NATIVE_ADMISSION " + category)
    finally:
        cleaned = remote(base, cleanup_code)
        if cleaned.returncode != 0 or cleaned.stdout != b"STAGE removed\n":
            print("U2_NATIVE_ADMISSION cleanup-required")
            raise ValueError("staged file cleanup failed")
        print("U2_NATIVE_ADMISSION staged-file=removed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, plistlib.InvalidFileException,
            subprocess.TimeoutExpired):
        print("U2_NATIVE_ADMISSION rejected")
        raise SystemExit(1)
