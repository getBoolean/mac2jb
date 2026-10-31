#!/usr/bin/env python3
"""Restart the userspace owner of the one unregistered USB function, then observe.

Effect: requires Mac USB absent; streams iPad syslog over the network; runs
exactly one `launchctl kickstart -k system/<job>` for an allowlisted owner
(com.apple.audiomxd owns the Valeria / audio user clients); waits 15 s;
reports newly registered functions, controller state and Mac USB. No
controller call, journal or broker access. Usage: <job-label>
"""

from pathlib import Path
import re
import runpy
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[6]
HOST = ROOT / "docs/plans/ipad-port/scripts/ipad-hardware/host"
RECOVER = runpy.run_path(str(HOST / "recover-u2-over-wifi.py"))
TRIAL = runpy.run_path(str(HOST / "run-u2-native-noop-trial-v8-wifi.py"))
ALLOWED = {"com.apple.audiomxd", "com.apple.accessoryd", "com.apple.ptpd"}


def main(label):
    if label not in ALLOWED:
        raise ValueError("job not allowlisted")
    if TRIAL["usb_present"]():
        raise ValueError("Mac USB present; nothing to restore")
    out = ROOT / ("build/ipad-hardware/u2-trials/owner-restart-%s-%d" % (label.split(".")[-1], time.time_ns()))
    out.mkdir(mode=0o700)
    syslog = RECOVER["start_syslog"](out / "syslog.txt")
    if syslog is None:
        raise ValueError("network syslog unavailable")
    time.sleep(3)
    ssh = runpy.run_path(str(HOST / "backup-u2-wifi-restore-kit.py"))["ssh_command"]()
    code, _ = RECOVER["run"]([*ssh, "/var/jb/usr/bin/launchctl kickstart -k system/" + label], 30)
    time.sleep(15)
    RECOVER["stop_syslog"](syslog)
    text = (out / "syslog.txt").read_text("utf-8", "replace")
    registered = sorted(set(re.findall(r"register function ([A-Za-z0-9]+)", text)))
    _, census = RECOVER["run"]([sys.executable, str(HOST / "read-u2-xdci-child-census-wifi.py")], 60)
    state = [l for l in census.decode().splitlines() if l.startswith("U2_XDCI_STATE")]
    present = TRIAL["usb_present"]()
    print("U2_OWNER_RESTART job=%s kickstart-exit=%d newly-registered=%s %s usb=%s evidence=%s" % (
        label, code, ",".join(registered) or "none", state[0] if state else "state=unknown",
        "present" if present else "absent", out.relative_to(ROOT)))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: <job-label>")
        main(sys.argv[1])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("U2_OWNER_RESTART rejected (%s)" % error)
        raise SystemExit(1)
