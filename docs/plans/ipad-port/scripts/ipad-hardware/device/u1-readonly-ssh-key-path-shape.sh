#!/bin/sh
# What this code does:
# Classify the current NewTerm account and the shape of mobile's SSH directory
# and authorized_keys file. It reads no file contents, emits no key, path,
# ownership, or mode value, and makes no device change.
#
# Exact NewTerm command (one line, run as mobile):
# if [ "$(/usr/bin/id -un 2>/dev/null)" = mobile ]; then printf 'account=mobile\n'; else printf 'account=other\n'; fi; if [ -L /var/mobile/.ssh ]; then printf 'ssh-dir=symlink\n'; elif [ -d /var/mobile/.ssh ]; then printf 'ssh-dir=directory\n'; else printf 'ssh-dir=other\n'; fi; if [ -L /var/mobile/.ssh/authorized_keys ]; then printf 'key-file=symlink\n'; elif [ -f /var/mobile/.ssh/authorized_keys ]; then printf 'key-file=regular\n'; else printf 'key-file=other\n'; fi; if command -v stat >/dev/null 2>&1; then printf 'stat=present\n'; else printf 'stat=absent\n'; fi

if [ "$(/usr/bin/id -un 2>/dev/null)" = mobile ]; then
  printf 'account=mobile\n'
else
  printf 'account=other\n'
fi
if [ -L /var/mobile/.ssh ]; then
  printf 'ssh-dir=symlink\n'
elif [ -d /var/mobile/.ssh ]; then
  printf 'ssh-dir=directory\n'
else
  printf 'ssh-dir=other\n'
fi
if [ -L /var/mobile/.ssh/authorized_keys ]; then
  printf 'key-file=symlink\n'
elif [ -f /var/mobile/.ssh/authorized_keys ]; then
  printf 'key-file=regular\n'
else
  printf 'key-file=other\n'
fi
if command -v stat >/dev/null 2>&1; then
  printf 'stat=present\n'
else
  printf 'stat=absent\n'
fi
