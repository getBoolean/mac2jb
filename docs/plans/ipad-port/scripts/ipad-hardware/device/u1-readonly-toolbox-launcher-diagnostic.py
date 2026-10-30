#!/var/jb/usr/bin/python3
"""Classify a failed toolbox launcher boundary without running the probe.

What this code does: as mobile, checks fixed tool paths, app/container and
probe file type/owner/mode, and a caller-provided expected SHA-256. It prints
only categories and never a path, bundle UUID, plist, or raw report. It does
not execute the installed probe or change any iPad file or service.
"""

import glob
import hashlib
import os
import stat
import subprocess
import sys


GLOBS = ("/var/containers/Bundle/Application/*/Mac2JBU1-Toolbox.app",
         "/Applications/Mac2JBU1-Toolbox.app",
         "/var/jb/Applications/Mac2JBU1-Toolbox.app")
TOOLS = {
    "env": ("/usr/bin/env", "/bin/env", "/var/jb/usr/bin/env", "/var/jb/bin/env"),
    "timeout": ("/var/jb/usr/bin/timeout", "/var/jb/bin/timeout",
                "/usr/bin/timeout", "/bin/timeout"),
    "sleep": ("/bin/sleep", "/usr/bin/sleep", "/var/jb/bin/sleep", "/var/jb/usr/bin/sleep"),
    "stat": ("/usr/bin/stat", "/bin/stat", "/var/jb/usr/bin/stat", "/var/jb/bin/stat"),
    "sha256sum": ("/var/jb/usr/bin/sha256sum", "/var/jb/bin/sha256sum",
                  "/usr/bin/sha256sum", "/bin/sha256sum"),
}


def metadata(path):
    try:
        info = os.lstat(path)
    except OSError:
        return "inaccessible"
    kind = "directory" if stat.S_ISDIR(info.st_mode) else "regular" if stat.S_ISREG(info.st_mode) else "other"
    return f"{kind}:{info.st_uid}:{info.st_gid}:{stat.S_IMODE(info.st_mode):o}"


def main():
    if len(sys.argv) != 2 or len(sys.argv[1]) != 64:
        raise SystemExit(64)
    expected = sys.argv[1]
    for name, paths in TOOLS.items():
        usable = any(os.path.isfile(p) and not os.path.islink(p)
                     and os.access(p, os.R_OK | os.X_OK) and
                     not os.access(p, os.W_OK) for p in paths)
        print("LAUNCH_DIAG " + name + "=" + ("usable" if usable else "unavailable"))
    candidates = [p for pattern in GLOBS for p in glob.glob(pattern)]
    print("LAUNCH_DIAG bundle-count=" + str(len(candidates)) if len(candidates) <= 2
          else "LAUNCH_DIAG bundle-count=other")
    if len(candidates) != 1:
        return
    app = candidates[0]
    print("LAUNCH_DIAG app=" + metadata(app))
    selected_stat = next((p for p in TOOLS["stat"] if os.path.isfile(p)
                          and not os.path.islink(p) and os.access(p, os.R_OK | os.X_OK)
                          and not os.access(p, os.W_OK)), None)
    if selected_stat:
        try:
            result = subprocess.run([selected_stat, "-f", "%u:%g:%Lp", app],
                                    capture_output=True, timeout=3)
            stat_match = result.returncode == 0 and result.stdout.strip() == b"0:0:755"
        except (OSError, subprocess.TimeoutExpired):
            stat_match = False
        print("LAUNCH_DIAG stat-format=" + ("match" if stat_match else "other"))
    for index, candidate in enumerate(TOOLS["stat"]):
        if not os.path.isfile(candidate) or os.path.islink(candidate):
            continue
        try:
            bsd = subprocess.run([candidate, "-f", "%u:%g:%Lp", app],
                                 capture_output=True, timeout=3)
            gnu = subprocess.run([candidate, "-c", "%u:%g:%a", app],
                                 capture_output=True, timeout=3)
            category = ("bsd" if bsd.returncode == 0 and bsd.stdout.strip() == b"0:0:755"
                        else "gnu" if gnu.returncode == 0 and gnu.stdout.strip() == b"0:0:755"
                        else "other")
        except (OSError, subprocess.TimeoutExpired):
            category = "other"
        print("LAUNCH_DIAG stat-candidate-" + str(index) + "=" + category)
    print("LAUNCH_DIAG container=" + metadata(os.path.dirname(app)))
    for label, relative in (("baseline", "mac2jb-u1-baseline"),
                            ("probes", "Probes"),
                            ("setdescription", "Probes/mac2jb-u1-setdescription")):
        print("LAUNCH_DIAG " + label + "=" + metadata(app + "/" + relative))
    path = app + "/mac2jb-u1-baseline"
    try:
        h = hashlib.sha256()
        with open(path, "rb") as file:
            while True:
                chunk = file.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        digest = h.hexdigest()
        match = digest == expected
    except OSError:
        match = False
    print("LAUNCH_DIAG baseline-hash=" + ("match" if match else "other"))


if __name__ == "__main__":
    main()
