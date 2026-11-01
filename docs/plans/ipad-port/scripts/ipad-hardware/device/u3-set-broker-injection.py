#!/var/jb/usr/bin/python3
"""Turn jailbreak tweak injection off (or back on) for one U2/U3 broker job.

The broker runs over its own jetsam ceiling - measured phys_footprint 6.19 MB
against a 6 MB hard limit - and is killed with
JETSAM_REASON_MEMORY_PERPROCESSLIMIT whenever it allocates, which a publication
always does. Its job plist asks for a 96 MB limit through JetsamProperties and
launchd ignores that: iOS takes a daemon's jetsam properties from its own
label-keyed configuration, so the limit cannot be raised from here. What can be
reduced is the footprint, and most of it is the tweak dylibs injected into the
process by the jailbreak's loader.

So this sets _MSSafeMode and _SafeMode in the job's environment, which the
loader honours by not injecting, and restarts the job. It changes nothing
outside this one job: no other process, tweak or system file is touched, and
--revert puts the plist back exactly as it was.

The journal is never read or written, and no USB controller call is made. The
job must be idle with no journal before either change, because restarting the
broker while a publication is live would restore it.

Usage: --inspect | --apply | --revert  LABEL
"""

import ctypes
import json
import os
import plistlib
import re
import subprocess
import sys


DAEMONS = "/var/jb/Library/LaunchDaemons/"
STATE = "/var/jb/var/lib/mac2jb-u2-native"
JOURNAL = STATE + "/restore-journal.json"
LAUNCHCTL = "/var/jb/bin/launchctl"
LABEL = re.compile(r"dev\.mac2jb\.u2\.[a-z0-9]{1,24}\Z")
SAFE_MODE = {"_MSSafeMode": "1", "_SafeMode": "1"}
TAG = "U3_BROKER_INJECTION "


def plist_path(label):
    return DAEMONS + label + ".plist"


def read_plist(label):
    with open(plist_path(label), "rb") as handle:
        return plistlib.loads(handle.read())


def footprint(pid):
    """phys_footprint in bytes - the number jetsam compares to the limit."""
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.proc_pid_rusage.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
    buffer = ctypes.create_string_buffer(1024)
    if libc.proc_pid_rusage(pid, 4, buffer) != 0:
        raise ValueError("footprint unavailable")
    return int.from_bytes(buffer.raw[16 + 8 * 7:24 + 8 * 7], "little")


def job_state(label):
    out = subprocess.run([LAUNCHCTL, "print", "system/" + label], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, timeout=20)
    text = out.stdout.decode("utf-8", "replace")
    if out.returncode:
        raise ValueError("job not loaded")
    pid = re.search(r"^\s*pid = (\d+)", text, re.M)
    runs = re.search(r"^\s*runs = (\d+)", text, re.M)
    limit = re.search(r"jetsam memory limit \(active, soft\) = (\d+) MB", text)
    exits = re.search(r"^\s*last exit reason = (\S+)", text, re.M)
    return {"pid": int(pid.group(1)) if pid else None,
            "runs": int(runs.group(1)) if runs else None,
            "limit_mb": int(limit.group(1)) if limit else None,
            "last_exit": exits.group(1) if exits else "none"}


def report(label, note):
    state = job_state(label)
    size = footprint(state["pid"]) if state["pid"] else 0
    return ("%sinjection=%s footprint=%.2fMB limit=%sMB pid=%s runs=%s last-exit=%s"
            % (TAG, note, size / 1048576, state["limit_mb"], state["pid"],
               state["runs"], state["last_exit"]))


def require_idle():
    """No journal, so restarting the broker cannot interrupt a publication."""
    if os.path.lexists(JOURNAL):
        raise ValueError("a journal is present; resolve it before restarting the broker")


def restart(label, description):
    """Write the plist, reload the job, and put the old one back if that fails."""
    path = plist_path(label)
    previous = open(path, "rb").read()
    body = plistlib.dumps(description, fmt=plistlib.FMT_XML)
    plistlib.loads(body)  # refuse to install anything that will not parse back
    if subprocess.run([LAUNCHCTL, "bootout", "system/" + label],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                      timeout=60).returncode:
        raise ValueError("bootout failed")
    try:
        with open(path, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        if subprocess.run([LAUNCHCTL, "bootstrap", "system", path],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=60).returncode:
            raise ValueError("bootstrap failed")
    except (OSError, ValueError):
        # Never leave the device without a broker: restore the exact previous
        # plist and bring the old job back before reporting the failure.
        with open(path, "wb") as handle:
            handle.write(previous)
            handle.flush()
            os.fsync(handle.fileno())
        subprocess.run([LAUNCHCTL, "bootstrap", "system", path],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        raise


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    if len(sys.argv) != 3 or sys.argv[1] not in ("--inspect", "--apply", "--revert"):
        raise ValueError("usage: --inspect|--apply|--revert LABEL")
    mode, label = sys.argv[1], sys.argv[2]
    if not LABEL.match(label):
        raise ValueError("label not allowlisted")
    description = read_plist(label)
    environment = description.get("EnvironmentVariables") or {}
    present = all(environment.get(key) == value for key, value in SAFE_MODE.items())

    if mode == "--inspect":
        print(report(label, "disabled" if present else "enabled"), flush=True)
        return
    require_idle()
    if mode == "--apply":
        if present:
            print(report(label, "disabled-already"), flush=True)
            return
        description["EnvironmentVariables"] = dict(environment, **SAFE_MODE)
    else:
        if not present:
            print(report(label, "enabled-already"), flush=True)
            return
        remaining = {k: v for k, v in environment.items() if k not in SAFE_MODE}
        if remaining:
            description["EnvironmentVariables"] = remaining
        else:
            description.pop("EnvironmentVariables", None)
    restart(label, description)
    require_idle()
    print(report(label, "disabled" if mode == "--apply" else "enabled"), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            plistlib.InvalidFileException, subprocess.SubprocessError) as error:
        print(TAG + "rejected (%s)" % error, flush=True)
        raise SystemExit(1)
