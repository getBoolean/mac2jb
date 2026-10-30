#!/bin/sh
# What this code does:
# Classify the NewTerm numeric account without printing it, then report only
# rootless/system Python and Perl command paths. It reads no key or user file,
# executes neither interpreter, and changes no iPad file or service.
#
# Exact NewTerm command (one line):
# u=$(/usr/bin/id -u 2>/dev/null); case "$u" in 501) printf 'account-uid=mobile\n';; 0) printf 'account-uid=root\n';; *) printf 'account-uid=other\n';; esac; for n in python3 perl; do p=$(command -v "$n" 2>/dev/null); case "$p" in /var/jb/usr/bin/*|/var/jb/bin/*|/usr/bin/*|/bin/*) printf '%s=%s\n' "$n" "$p";; *) printf '%s=absent-or-other\n' "$n";; esac; done

u=$(/usr/bin/id -u 2>/dev/null)
case "$u" in
  501) printf 'account-uid=mobile\n' ;;
  0) printf 'account-uid=root\n' ;;
  *) printf 'account-uid=other\n' ;;
esac
for n in python3 perl; do
  p=$(command -v "$n" 2>/dev/null)
  case "$p" in
    /var/jb/usr/bin/*|/var/jb/bin/*|/usr/bin/*|/bin/*)
      printf '%s=%s\n' "$n" "$p" ;;
    *) printf '%s=absent-or-other\n' "$n" ;;
  esac
done
