#!/bin/sh
# What this code does:
# Report whether fixed, locally available interpreters can implement an
# append-only, no-follow update to mobile's existing SSH authorized_keys.
# It does not read or print keys, inspect user files, contact SSH, or write to
# the iPad. Run the exact command below in NewTerm as the mobile account.
#
# Exact NewTerm command (one line):
# for n in python3 python perl ruby; do if command -v "$n" >/dev/null 2>&1; then printf '%s=present\n' "$n"; else printf '%s=absent\n' "$n"; fi; done

for n in python3 python perl ruby; do
  if command -v "$n" >/dev/null 2>&1; then
    printf '%s=present\n' "$n"
  else
    printf '%s=absent\n' "$n"
  fi
done
