#!/var/jb/usr/bin/python3
"""Classify dpkg's pre-existing audit findings without changing packages.

The U2 installer refused because dpkg --audit was nonempty. This read-only
script runs that command once, bounds its output, and prints only the exit
category, output hash, and affected package tokens. It does not configure,
install, remove, or repair anything.
"""

import hashlib
import re
import subprocess


def main():
    result = subprocess.run(["/var/jb/usr/bin/dpkg", "--audit"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=8)
    if len(result.stdout) > 64 * 1024 or len(result.stderr) > 4096:
        raise ValueError("audit output too large")
    text = result.stdout.decode("utf-8", "strict")
    tokens = []
    for line in text.splitlines():
        if line.startswith(" ") and line.strip():
            candidate = line.strip().split()[0]
            if re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.+-]{0,79}", candidate):
                tokens.append(candidate)
    print("U2_DPKG_AUDIT exit=" + ("zero" if result.returncode == 0 else "other") +
          " output=" + ("empty" if not text else "nonempty") +
          " sha256=" + hashlib.sha256(result.stdout).hexdigest())
    unique = sorted(set(tokens))
    heading = next((line.strip() for line in text.splitlines()
                    if line.strip() and not line.startswith(" ")), "none")
    heading = re.sub(r"[^a-zA-Z0-9 ]", "", heading[:120]).replace(" ", "_")
    print("U2_DPKG_AUDIT affected-count=" + str(len(unique)) +
          " sample=" + (",".join(unique[:4]) if unique else "none"))
    print("U2_DPKG_AUDIT heading=" + heading)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print("U2_DPKG_AUDIT rejected")
        raise SystemExit(1)
