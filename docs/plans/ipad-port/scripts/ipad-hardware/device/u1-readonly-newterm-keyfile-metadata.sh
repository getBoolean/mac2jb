#!/bin/sh
# What this code does:
# Report the current numeric account category, the Python executable's shape,
# and fixed-path SSH directory/key-file metadata. It reads no key contents,
# runs no sudo, and writes nothing. This uses the owner's reported fixed
# rootless id and stat paths after Python/Perl installation.
#
# Exact NewTerm command (one line):
# u=$(/var/jb/usr/bin/id -u 2>/dev/null); case "$u" in 501) printf 'account=mobile\n';; 0) printf 'account=root\n';; *) printf 'account=other\n';; esac; if [ -L /var/jb/usr/bin/python3 ]; then printf 'python=symlink\n'; elif [ -f /var/jb/usr/bin/python3 ] && [ -x /var/jb/usr/bin/python3 ]; then printf 'python=regular-executable\n'; else printf 'python=other\n'; fi; if [ -L /var/mobile/.ssh ] || [ -L /var/mobile/.ssh/authorized_keys ]; then printf 'ssh-path=symlink-stop\n'; else /var/jb/usr/bin/stat -c 'ssh-dir=%u:%a:%h:%F' /var/mobile/.ssh 2>/dev/null || printf 'ssh-dir=unavailable\n'; /var/jb/usr/bin/stat -c 'key-file=%u:%a:%h:%F' /var/mobile/.ssh/authorized_keys 2>/dev/null || printf 'key-file=unavailable\n'; fi

u=$(/var/jb/usr/bin/id -u 2>/dev/null)
case "$u" in
  501) printf 'account=mobile\n' ;;
  0) printf 'account=root\n' ;;
  *) printf 'account=other\n' ;;
esac
if [ -L /var/jb/usr/bin/python3 ]; then
  printf 'python=symlink\n'
elif [ -f /var/jb/usr/bin/python3 ] && [ -x /var/jb/usr/bin/python3 ]; then
  printf 'python=regular-executable\n'
else
  printf 'python=other\n'
fi
if [ -L /var/mobile/.ssh ] || [ -L /var/mobile/.ssh/authorized_keys ]; then
  printf 'ssh-path=symlink-stop\n'
else
  /var/jb/usr/bin/stat -c 'ssh-dir=%u:%a:%h:%F' /var/mobile/.ssh 2>/dev/null || printf 'ssh-dir=unavailable\n'
  /var/jb/usr/bin/stat -c 'key-file=%u:%a:%h:%F' /var/mobile/.ssh/authorized_keys 2>/dev/null || printf 'key-file=unavailable\n'
fi
