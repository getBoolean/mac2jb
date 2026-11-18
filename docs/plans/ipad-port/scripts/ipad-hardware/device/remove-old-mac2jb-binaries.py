#!/var/jb/usr/bin/python3
"""Remove superseded mac2jb broker and canary binaries from /var/jb/usr/libexec.

Usage: --inspect | --remove   KEEP_PATH [KEEP_PATH ...]

Effect: considers only regular files in /var/jb/usr/libexec named
.mac2jb-u2-noop-trial-XXXXXXXX or .mac2jb-u3-hid-canary-XXXXXXXX (8 hex). A
candidate is removed only if (1) it is not one of the KEEP_PATH arguments,
(2) no plist in /var/jb/Library/LaunchDaemons mentions its path, and (3) its
SHA-256 starts with the 8 hex characters in its own name, so a file that is
not what its name says is left alone and reported. `--inspect` changes nothing.
Prints one line per file with its full SHA-256 for the cleanup ledger. Touches
no other path, no journal, no launchd job and no USB controller state.
"""

import hashlib
import os
import re
import stat
import sys

LIBEXEC = "/var/jb/usr/libexec"
DAEMONS = "/var/jb/Library/LaunchDaemons"
NAME = re.compile(r"\.mac2jb-(u2-noop-trial|u3-hid-canary)-([0-9a-f]{8})\Z")


def referenced_paths():
    found = set()
    for entry in sorted(os.listdir(DAEMONS)):
        if not entry.endswith(".plist"):
            continue
        with open(os.path.join(DAEMONS, entry), "rb") as handle:
            data = handle.read(1024 * 1024)
        for match in re.finditer(rb"/var/jb/usr/libexec/[A-Za-z0-9._/-]+", data):
            found.add(match.group(0).decode("ascii"))
    return found


def main(mode, keep):
    if mode not in ("--inspect", "--remove") or not keep:
        raise ValueError("usage: --inspect|--remove KEEP_PATH [KEEP_PATH ...]")
    keep = set(keep)
    referenced = referenced_paths()
    removed = kept = skipped = 0
    for entry in sorted(os.listdir(LIBEXEC)):
        match = NAME.fullmatch(entry)
        if not match:
            continue
        path = os.path.join(LIBEXEC, entry)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            print("SKIP %s reason=not-a-regular-file" % entry)
            skipped += 1
            continue
        with open(path, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        if path in keep or path in referenced:
            print("KEEP %s sha256=%s reason=%s" % (entry, digest,
                  "keep-list" if path in keep else "launchd-plist"))
            kept += 1
            continue
        if not digest.startswith(match.group(2)):
            print("SKIP %s sha256=%s reason=name-hash-mismatch" % (entry, digest))
            skipped += 1
            continue
        if mode == "--remove":
            os.unlink(path)
        print("%s %s sha256=%s" % ("REMOVED" if mode == "--remove" else "WOULD-REMOVE",
                                   entry, digest))
        removed += 1
    print("SUMMARY mode=%s %s=%d kept=%d skipped=%d"
          % (mode[2:], "removed" if mode == "--remove" else "would-remove", removed, kept, skipped))


if __name__ == "__main__":
    try:
        main(sys.argv[1] if len(sys.argv) > 1 else "", sys.argv[2:])
    except (OSError, ValueError) as error:
        print("REMOVE_OLD rejected (%s)" % error)
        raise SystemExit(1)
