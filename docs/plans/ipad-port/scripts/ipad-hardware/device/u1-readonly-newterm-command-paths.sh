#!/bin/sh
# What this code does:
# Report only fixed-prefix command paths for id, Python, Perl, sudo, and stat
# after the owner's package installation. It executes none of those commands,
# reads no SSH key or authorized_keys content, and changes no iPad state.
#
# Exact NewTerm command (one line):
# for n in id python3 perl sudo stat; do p=$(command -v "$n" 2>/dev/null); case "$p" in /var/jb/*|/usr/*|/bin/*) printf '%s=%s\n' "$n" "$p";; *) printf '%s=absent-or-other\n' "$n";; esac; done

for n in id python3 perl sudo stat; do
  p=$(command -v "$n" 2>/dev/null)
  case "$p" in
    /var/jb/*|/usr/*|/bin/*) printf '%s=%s\n' "$n" "$p" ;;
    *) printf '%s=absent-or-other\n' "$n" ;;
  esac
done
