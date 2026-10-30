#!/usr/bin/env python3
"""Check pinned USB SSH for both iPad accounts while ChatGPT is fully quit.

What this code does: require exactly one USB device in the local usbmux list,
verify the durable Mac identity and host-pin file against their recorded hashes
and modes, then run only `/var/jb/usr/bin/id -u` over the pinned localhost USB
tunnel as mobile and root. It prints categorical results without device IDs,
account numbers, keys, or raw SSH diagnostics. It changes no iPad file or USB
setting; normal SSH authentication/accounting logs may still be written.

Run from Terminal while ChatGPT is quit. Capture stdout under ignored
`build/ipad-hardware/`, then reopen the chat for review. This is a readiness
check, not a U1 probe or permission to bypass a missing USB connection.
"""

from pathlib import Path
import os
import runpy
import signal
import subprocess
import time


ROOT = Path(__file__).resolve().parents[6]
HELPER = ROOT / "scripts/ipad-hardware/host/backup-clienttruth-over-root-ssh.py"
TUNNEL = ROOT / "scripts/ipad-hardware/host/start-usb-ssh-tunnel.sh"


def listener_present():
    result = subprocess.run(["/usr/sbin/lsof", "-nP", "-iTCP:2222",
                             "-sTCP:LISTEN"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=5)
    return result.returncode == 0


def check_accounts(helper):
    for account, expected in (("mobile", b"501"), ("root", b"0")):
        command = ["/usr/bin/ssh", *helper["ssh_options"](), "-T", "-p", "2222",
                   account + "@127.0.0.1", "/var/jb/usr/bin/id -u"]
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=12)
            valid = result.returncode == 0 and result.stdout.strip() == expected
        except (OSError, subprocess.TimeoutExpired):
            valid = False
        print("PINNED_SSH " + account + "=" + ("ok" if valid else "failed"))


def main():
    usb = subprocess.run(["/opt/homebrew/bin/idevice_id", "-l"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         timeout=8)
    if usb.returncode != 0 or len([x for x in usb.stdout.splitlines() if x.strip()]) != 1:
        print("PINNED_SSH usb=unavailable")
        return
    helper = runpy.run_path(str(HELPER))
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    print("PINNED_SSH usb=one")
    if listener_present():
        print("PINNED_SSH tunnel=existing")
        check_accounts(helper)
        return
    tunnel = subprocess.Popen(["/bin/sh", str(TUNNEL)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        for _ in range(40):
            if listener_present():
                break
            if tunnel.poll() is not None:
                break
            time.sleep(0.125)
        if not listener_present():
            print("PINNED_SSH tunnel=failed")
            return
        print("PINNED_SSH tunnel=started")
        check_accounts(helper)
    finally:
        if tunnel.poll() is None:
            os.killpg(tunnel.pid, signal.SIGTERM)
            try:
                tunnel.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(tunnel.pid, signal.SIGKILL)
                tunnel.wait(timeout=3)


if __name__ == "__main__":
    main()
