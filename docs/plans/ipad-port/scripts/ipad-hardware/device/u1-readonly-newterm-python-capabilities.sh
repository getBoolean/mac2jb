#!/bin/sh
# What this code does:
# Inspect only metadata for the Python and sudo executable paths and the
# fixed rootless parent directories. It executes neither Python nor sudo,
# opens no SSH file, and writes no device file. It never prints symlink targets.
#
# Exact NewTerm command (one line):
# for p in /var/jb /var/jb/usr /var/jb/usr/bin /var/jb/usr/bin/python3 /var/jb/usr/bin/sudo; do /var/jb/usr/bin/stat -c '%n=%u:%a:%h:%F' "$p" 2>/dev/null || printf '%s=unavailable\n' "$p"; /var/jb/usr/bin/stat -Lc '%n-target=%u:%a:%h:%F' "$p" 2>/dev/null || printf '%s-target=unavailable\n' "$p"; done

for p in /var/jb /var/jb/usr /var/jb/usr/bin /var/jb/usr/bin/python3 /var/jb/usr/bin/sudo; do
  /var/jb/usr/bin/stat -c '%n=%u:%a:%h:%F' "$p" 2>/dev/null || printf '%s=unavailable\n' "$p"
  /var/jb/usr/bin/stat -Lc '%n-target=%u:%a:%h:%F' "$p" 2>/dev/null || printf '%s-target=unavailable\n' "$p"
done
