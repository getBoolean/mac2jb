#!/usr/bin/env python3
"""Run device/u2-ptpd-foreground-probe.sh once as mobile over pinned Wi-Fi SSH, then re-read state.

Effect: starts the stock /usr/libexec/ptpd -t usb detached on the iPad (left
running if it stays alive), reports whether it survives 4 s and 12 s, then runs
the read-only function census, child census and Mac USB check. No USB
controller call, journal, or broker access. Output is saved under a new
private build/ipad-hardware/u2-function-census/ptpd-probe-<ns>/ directory.
"""

from pathlib import Path
import runpy
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
PROBE = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/device/u2-ptpd-foreground-probe.sh"


def main():
    out = ROOT / ("build/ipad-hardware/u2-function-census/ptpd-probe-%d" % time.time_ns())
    out.mkdir(mode=0o700)
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
                             "mobile@" + address, "/var/jb/bin/sh -s"],
                            input=PROBE.read_bytes(), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=60)
    (out / "probe.txt").write_bytes(result.stdout[:4096])
    print(result.stdout.decode("ascii", "replace"), end="")
    time.sleep(3)
    for name, script in (("census", "read-u2-xdci-function-census-wifi.py"),
                         ("state", "read-u2-xdci-child-census-wifi.py"),
                         ("usb", "diagnose-usb-recognition.py")):
        data = subprocess.run([sys.executable, str(HOST / script)], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=60).stdout
        (out / (name + ".txt")).write_bytes(data)
        lines = data.decode("ascii", "replace").splitlines()
        keep = [l for l in lines if "creator=ptpd" in l or l.startswith(("U2_XDCI_STATE", "USBMUX", "U2_XDCI_FUNCTIONS"))]
        print("\n".join(keep))
    print("PTPD_PROBE evidence=%s" % out.relative_to(ROOT))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("PTPD_PROBE rejected (%s)" % error)
        raise SystemExit(1)
