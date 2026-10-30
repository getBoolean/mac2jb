#!/bin/sh
# What this code does:
# Classify NewTerm as mobile, root, or another account and report only fixed
# executable candidate paths for the owner-installed Python and Perl tools.
# It does not execute either interpreter, read any key, or write a file.
#
# Exact NewTerm command (one line):
# a=$(/usr/bin/id -un 2>/dev/null); if [ "$a" = mobile ]; then printf 'account=mobile\n'; elif [ "$a" = root ]; then printf 'account=root\n'; else printf 'account=other\n'; fi; for p in /var/jb/usr/bin/python3 /var/jb/bin/python3 /usr/bin/python3 /bin/python3; do if [ -x "$p" ] && [ ! -L "$p" ]; then printf 'python=%s\n' "$p"; fi; done; for p in /var/jb/usr/bin/perl /var/jb/bin/perl /usr/bin/perl /bin/perl; do if [ -x "$p" ] && [ ! -L "$p" ]; then printf 'perl=%s\n' "$p"; fi; done

a=$(/usr/bin/id -un 2>/dev/null)
if [ "$a" = mobile ]; then
  printf 'account=mobile\n'
elif [ "$a" = root ]; then
  printf 'account=root\n'
else
  printf 'account=other\n'
fi
for p in /var/jb/usr/bin/python3 /var/jb/bin/python3 /usr/bin/python3 /bin/python3; do
  if [ -x "$p" ] && [ ! -L "$p" ]; then
    printf 'python=%s\n' "$p"
  fi
done
for p in /var/jb/usr/bin/perl /var/jb/bin/perl /usr/bin/perl /bin/perl; do
  if [ -x "$p" ] && [ ! -L "$p" ]; then
    printf 'perl=%s\n' "$p"
  fi
done
