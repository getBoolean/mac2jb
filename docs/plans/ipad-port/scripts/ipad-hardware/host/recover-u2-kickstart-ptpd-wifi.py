#!/usr/bin/env python3
"""One-shot guarded same-boot USB recovery attempt: start the stock ptpd job.

Effect: (1) read-only precheck over pinned root Wi-Fi SSH that the XDCI is off
bus, its PTP interface has no client, and com.apple.ptpd is not running;
(2) start the passive Mac USB return observer; (3) run exactly one
`launchctl kickstart system/com.apple.ptpd` on the iPad; (4) re-read the
function census and provider listing. It never touches the USB controller,
the restore journal, or the U2 broker. Evidence goes to a new private
build/ipad-hardware/u2-function-census/kickstart-<ns>/ directory.
"""

import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
CENSUS = HOST / "read-u2-xdci-function-census-wifi.py"
PROVIDERS = HOST / "read-u2-usb-function-providers-wifi.py"
OBSERVER = HOST / "u2-usb-return-observer.py"
STATE = HOST / "read-u2-xdci-child-census-wifi.py"
KICKSTART = "/var/jb/usr/bin/launchctl kickstart system/com.apple.ptpd"


def run_reader(path):
    result = subprocess.run([sys.executable, str(path)], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=60)
    if result.returncode:
        raise ValueError("reader failed: " + path.name)
    return result.stdout.decode("ascii")


def ptp_unserved(census):
    lines = census.splitlines()
    root = next((l for l in lines if " i=0 " in l), "")
    ptp = [re.search(r" i=(\d+) ", l)[1] for l in lines if l.endswith("function=PTP")]
    if len(ptp) != 1:
        raise ValueError("PTP interface cardinality")
    served = any((" parent=%s " % ptp[0]) in l for l in lines)
    return not served, root


def main():
    out = ROOT / ("build/ipad-hardware/u2-function-census/kickstart-%d" % time.time_ns())
    out.mkdir(mode=0o700, parents=False)
    census = run_reader(CENSUS)
    providers = run_reader(PROVIDERS)
    (out / "pre-census.txt").write_text(census)
    (out / "pre-providers.txt").write_text(providers)
    unserved, _ = ptp_unserved(census)
    bus = run_reader(STATE)
    (out / "pre-state.txt").write_text(bus)
    if "DeviceState=disconnected OnBus=no SelectedConfiguration=0" not in bus:
        raise ValueError("controller not in the recorded off-bus state; refusing")
    if not unserved:
        raise ValueError("PTP already served; refusing")
    if "label=com.apple.ptpd running=no" not in providers:
        raise ValueError("ptpd not in expected stopped state; refusing")
    observer = subprocess.Popen([sys.executable, str(OBSERVER), "0x05ac", "0x12ab", "20"],
                                stdout=open(out / "observer.ndjson", "w"),
                                stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    if observer.poll() is not None:
        raise ValueError("observer did not start (target present?)")
    wireless = runpy.run_path(str(HOST / "check-pinned-wireless-ssh.py"))
    helper = runpy.run_path(str(HOST / "backup-clienttruth-over-root-ssh.py"))
    address = wireless["read_address"]()
    if address is None:
        raise ValueError("pinned address unavailable")
    for path, digest in ((helper["IDENTITY"], helper["IDENTITY_SHA256"]),
                         (helper["KNOWN_HOSTS"], helper["KNOWN_HOSTS_SHA256"])):
        helper["checked_local"](path, digest, 0o600)
    result = subprocess.run(["/usr/bin/ssh", *helper["ssh_options"](),
                             "-o", "HostKeyAlias=" + wireless["HOST_KEY_ALIAS"],
                             "-o", "AddressFamily=inet", "-T", "-p", "22",
                             "root@" + address, KICKSTART],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    (out / "kickstart.txt").write_text("exit=%d\n" % result.returncode)
    print("U2_KICKSTART exit=%d" % result.returncode, flush=True)
    observer.wait(timeout=40)
    print((out / "observer.ndjson").read_text(), end="")
    time.sleep(2)
    census = run_reader(CENSUS)
    providers = run_reader(PROVIDERS)
    (out / "post-census.txt").write_text(census)
    (out / "post-providers.txt").write_text(providers)
    bus = run_reader(STATE)
    (out / "post-state.txt").write_text(bus)
    unserved, _ = ptp_unserved(census)
    state = next((l for l in bus.splitlines() if l.startswith("U2_XDCI_STATE")), "unknown")
    print("U2_KICKSTART post ptp-served=%s ptpd-running=%s %s" % (
        "no" if unserved else "yes",
        "yes" if "label=com.apple.ptpd running=yes" in providers else "no", state))
    print("U2_KICKSTART evidence=%s" % out.relative_to(ROOT))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("U2_KICKSTART rejected: %s" % error)
        raise SystemExit(1)
