#!/var/jb/usr/bin/python3
"""Bounded read-only listing of candidate USB function provider jobs and processes.

Effect: runs `launchctl list` and `ps -A -o etime=,comm=` and prints only
entries whose label/process basename matches a fixed allowlist pattern, as
label, running yes/no, last exit status, and process elapsed time. No PIDs,
paths, arguments, IDs, writes, or service control.
"""

import os
import re
import subprocess


PATTERN = re.compile(r"(ptp|mtp|camera|accessor|iap|audio|mediaserver|usb|lockdown|valeria|idam)", re.I)
LABEL = re.compile(r"[A-Za-z0-9._-]{1,96}\Z")
NAME = re.compile(r"[A-Za-z0-9._-]{1,48}\Z")
ETIME = re.compile(r"(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)\Z")


def run(argv):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=8, check=False)
    if result.returncode or len(result.stdout) > 512 * 1024:
        raise ValueError("command failed")
    return result.stdout.decode("utf-8", "replace").splitlines()


def seconds(etime):
    match = ETIME.fullmatch(etime)
    if not match:
        return "unknown"
    days, hours, minutes, secs = (int(part or 0) for part in match.groups())
    return str(((days * 24 + hours) * 60 + minutes) * 60 + secs)


def main():
    if os.geteuid() != 0:
        raise ValueError("root required")
    lines = []
    for row in run(["/var/jb/usr/bin/launchctl", "list"])[1:]:
        parts = row.split("\t")
        if len(parts) != 3 or not LABEL.fullmatch(parts[2]) or not PATTERN.search(parts[2]):
            continue
        status = parts[1] if re.fullmatch(r"-?[0-9]{1,4}", parts[1]) else "other"
        lines.append("U2_PROVIDER_JOB label=%s running=%s status=%s" %
                     (parts[2], "no" if parts[0] == "-" else "yes", status))
    ps = "/var/jb/usr/bin/ps" if os.path.exists("/var/jb/usr/bin/ps") else "/bin/ps"
    for row in run([ps, "-A", "-o", "etime=,comm="]):
        fields = row.strip().split(None, 1)
        if len(fields) != 2:
            continue
        name = os.path.basename(fields[1])
        if NAME.fullmatch(name) and PATTERN.search(name):
            lines.append("U2_PROVIDER_PROC name=%s elapsed=%s" % (name, seconds(fields[0])))
    if len(lines) > 160:
        raise ValueError("output limit")
    print("U2_PROVIDERS count=%d" % len(lines))
    for line in sorted(lines):
        print(line)
    print("U2_PROVIDERS done")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError, TypeError):
        print("U2_PROVIDERS rejected")
        raise SystemExit(1)
