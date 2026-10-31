#!/var/jb/usr/bin/python3
"""Bounded read-only launchd state for the USB function provider jobs.

Effect: runs `launchctl print system/<label>` for com.apple.ptpd, com.apple.iapd
and com.apple.idamd and prints only allowlisted scalar lines (state, runs, last
exit code/reason, spawn type, event stream/trigger names). No PIDs, paths,
arguments, writes, or job control.
"""

import re
import subprocess

LABELS = ("com.apple.ptpd", "com.apple.iapd", "com.apple.idamd")
KEEP = re.compile(r"\s*(state|runs|last exit code|last exit reason|last terminating signal|"
                  r"spawn type|immediate reason|forks|execs|job state|"
                  r"com\.apple\.[A-Za-z0-9._-]+ =>|[A-Za-z0-9._-]+ = \{|event triggers|"
                  r"stream|descriptor|state = )", re.I)
SAFE = re.compile(r"[A-Za-z0-9 ._:=>{}()/,+-]{1,160}\Z")


def main():
    for label in LABELS:
        result = subprocess.run(["/var/jb/usr/bin/launchctl", "print", "system/" + label],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=8, check=False)
        print("U2_JOB label=%s print-exit=%d" % (label, result.returncode))
        for line in result.stdout.decode("utf-8", "replace").splitlines()[:400]:
            if KEEP.match(line) and SAFE.fullmatch(line.strip()) and "pid" not in line.lower():
                print("U2_JOB_LINE label=%s %s" % (label, line.strip()))
    print("U2_JOB done")


if __name__ == "__main__":
    main()
