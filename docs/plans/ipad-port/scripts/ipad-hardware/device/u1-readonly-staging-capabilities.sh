#!/bin/sh
# Read-only capability check for a replacement exclusive staging helper.
#
# What this script does:
# - Tests only fixed absolute paths for Perl, Node, tar, and dd.
# - If Perl or Node is present, runs a fixed one-line import/constant check that
#   opens no target. Perl checks exclusive/no-follow open plus SHA-256 support;
#   Node additionally checks same-FD chmod support.
# - If dd is present, reads its help text into shell memory and reports only whether
#   both exclusive-create and no-follow flags are documented. Tar is presence-only.
# - Emits six fixed-label lines. It never lists directories or emits paths, help
#   text, environment data, file content, or device identifiers.
#
# Residual effects: interpreter/help processes and the surrounding SSH login can
# affect transient caches and ordinary authentication/process/accounting logs.
# This payload intentionally makes no persistent device change.

exec 2>&-
set +euxv

perl_path=''
for candidate in /var/jb/usr/bin/perl /var/jb/bin/perl /usr/bin/perl /bin/perl; do
  if [ -x "$candidate" ]; then perl_path=$candidate; break; fi
done
perl_candidate='not observed'
perl_open_hash='not observed'
if [ -n "$perl_path" ]; then
  perl_candidate='present'
  if "$perl_path" -T -MFcntl=O_CREAT,O_EXCL,O_NOFOLLOW,O_RDWR -MDigest::SHA -e 'exit((O_CREAT() && O_EXCL() && O_NOFOLLOW() && O_RDWR()) ? 0 : 1)' </dev/null >/dev/null 2>&1; then
    perl_open_hash='present'
  fi
fi

node_path=''
for candidate in /var/jb/usr/bin/node /var/jb/bin/node /usr/bin/node /bin/node; do
  if [ -x "$candidate" ]; then node_path=$candidate; break; fi
done
node_candidate='not observed'
node_full_stager='not observed'
if [ -n "$node_path" ]; then
  node_candidate='present'
  if "$node_path" -e 'const f=require("fs"),c=f.constants;require("crypto");process.exit(c.O_CREAT&&c.O_EXCL&&c.O_NOFOLLOW&&c.O_RDWR&&typeof f.fchmodSync==="function"?0:1)' </dev/null >/dev/null 2>&1; then
    node_full_stager='present'
  fi
fi

tar_candidate='not observed'
for candidate in /var/jb/usr/bin/bsdtar /var/jb/usr/bin/tar /var/jb/bin/tar /usr/bin/tar /bin/tar; do
  if [ -x "$candidate" ]; then tar_candidate='present'; break; fi
done

dd_exclusive_flags='not observed'
for candidate in /var/jb/usr/bin/dd /var/jb/bin/dd /usr/bin/dd /bin/dd; do
  if [ -x "$candidate" ]; then
    dd_help=$("$candidate" --help </dev/null 2>&1)
    dd_excl='not observed'
    dd_nofollow='not observed'
    case "$dd_help" in *excl*) dd_excl='present' ;; esac
    case "$dd_help" in *nofollow*) dd_nofollow='present' ;; esac
    if [ "$dd_excl" = 'present' ] && [ "$dd_nofollow" = 'present' ]; then dd_exclusive_flags='present'; fi
    break
  fi
done

command printf '%s\n' \
  "perl-candidate: $perl_candidate" \
  "perl-open-hash-primitives: $perl_open_hash" \
  "node-candidate: $node_candidate" \
  "node-full-stager-primitives: $node_full_stager" \
  "tar-candidate: $tar_candidate" \
  "dd-exclusive-flags: $dd_exclusive_flags"
