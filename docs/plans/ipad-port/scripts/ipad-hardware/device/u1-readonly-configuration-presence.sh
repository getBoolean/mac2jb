#!/bin/sh
# On-device U1 discovery payload. Observational only: never emits the raw value.

# Close diagnostics before executing any path-bearing command.
exec 2>&-
set +euxv

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

if /usr/sbin/ioreg -p IODeviceTree -r -k configuration-string -l 2>&- |
  /var/jb/usr/bin/grep -q -E '^[[:space:]|]*"configuration-string"[[:space:]]*=' 2>&-; then
  command printf '%s\n' 'configuration-string: present'
else
  command printf '%s\n' 'configuration-string: not observed'
fi
