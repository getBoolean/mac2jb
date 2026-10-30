#!/bin/sh
# Read-only quarantine diagnostic for the fixed digest-named staged probe.
#
# What this script does:
# - Uses shell file tests only; it does not open, read, execute, alter, or remove
#   the staged probe and does not enumerate unrelated files.
# - Reports whether the fixed env/Python allowlists contain an executable, whether
#   /var/mobile/Documents is a directory, the fixed target path's broad file type,
#   and whether that path is readable, writable, or executable by `mobile`.
# - Emits only seven fixed-label lines and no raw path, metadata, or file content.
#
# Residual effects: the surrounding SSH login and shell process can create normal
# authentication/process/accounting logs. This payload intentionally makes no
# persistent device change.

exec 2>&-
set +euxv

env_candidate='not observed'
for candidate in /usr/bin/env /bin/env /var/jb/usr/bin/env /var/jb/bin/env; do
  if [ -x "$candidate" ]; then
    env_candidate='present'
    break
  fi
done

python_candidate='not observed'
for candidate in /var/jb/usr/bin/python3 /var/jb/bin/python3 /usr/bin/python3 /bin/python3; do
  if [ -x "$candidate" ]; then
    python_candidate='present'
    break
  fi
done

documents_directory='not observed'
if [ -d /var/mobile/Documents ]; then documents_directory='present'; fi

target='/var/mobile/Documents/mac2jb-ios-probe-baseline-878ab27771fd7a660ba9f3997427b9ef92573bd524cad43bb89aded354d6d118'
if [ -L "$target" ]; then
  target_type='symbolic link'
elif [ -e "$target" ]; then
  if [ -f "$target" ]; then target_type='regular file'; else target_type='other object'; fi
else
  target_type='absent'
fi

target_readable='no'
target_writable='no'
target_executable='no'
if [ -r "$target" ]; then target_readable='yes'; fi
if [ -w "$target" ]; then target_writable='yes'; fi
if [ -x "$target" ]; then target_executable='yes'; fi

command printf '%s\n' \
  "env-candidate: $env_candidate" \
  "python-candidate: $python_candidate" \
  "documents-directory: $documents_directory" \
  "target-type: $target_type" \
  "target-readable: $target_readable" \
  "target-writable: $target_writable" \
  "target-executable: $target_executable"
