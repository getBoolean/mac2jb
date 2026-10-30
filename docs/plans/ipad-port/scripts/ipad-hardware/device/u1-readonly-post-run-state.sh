#!/bin/sh
# Read-only state check after a baseline probe exits without an accepted report.
#
# What this script does:
# - Uses shell file tests on only the fixed staged-probe and fixed final-report paths.
# - Classifies each fixed path without opening, reading, hashing, executing, altering,
#   or deleting it. Access/nonempty tests run only after a non-symlink regular-file
#   classification.
# - Counts, without naming, entries matching only the report writer's fixed
#   `.mac2jb-probe-*.tmp` pattern under /var/mobile/Documents.
# - Emits ten fixed-label lines and no raw path, file content, metadata, or identifier.
#
# Residual effects are limited to path lookup/glob traversal, transient caches, and
# ordinary SSH/authentication/process/accounting logs. No persistent device change
# is intended or reachable from the payload commands.

exec 2>&-
set +euxv

probe='/var/mobile/Documents/mac2jb-ios-probe-baseline-878ab27771fd7a660ba9f3997427b9ef92573bd524cad43bb89aded354d6d118'
report='/var/mobile/Documents/mac2jb-probe-baseline-capture-host-a.json'

probe_type='absent'
probe_readable='no'
probe_writable='no'
probe_executable='no'
if [ -L "$probe" ]; then
  probe_type='symbolic link'
elif [ -e "$probe" ]; then
  if [ -f "$probe" ]; then
    probe_type='regular file'
    if [ -r "$probe" ]; then probe_readable='yes'; fi
    if [ -w "$probe" ]; then probe_writable='yes'; fi
    if [ -x "$probe" ]; then probe_executable='yes'; fi
  else
    probe_type='other object'
  fi
fi

report_type='absent'
report_readable='no'
report_writable='no'
report_executable='no'
report_nonempty='no'
if [ -L "$report" ]; then
  report_type='symbolic link'
elif [ -e "$report" ]; then
  if [ -f "$report" ]; then
    report_type='regular file'
    if [ -r "$report" ]; then report_readable='yes'; fi
    if [ -w "$report" ]; then report_writable='yes'; fi
    if [ -x "$report" ]; then report_executable='yes'; fi
    if [ -s "$report" ]; then report_nonempty='yes'; fi
  else
    report_type='other object'
  fi
fi

report_temp_count=0
for candidate in /var/mobile/Documents/.mac2jb-probe-*.tmp; do
  if [ -e "$candidate" ] || [ -L "$candidate" ]; then
    report_temp_count=$((report_temp_count + 1))
  fi
done

command printf '%s\n' \
  "probe-type: $probe_type" \
  "probe-readable: $probe_readable" \
  "probe-writable: $probe_writable" \
  "probe-executable: $probe_executable" \
  "report-type: $report_type" \
  "report-readable: $report_readable" \
  "report-writable: $report_writable" \
  "report-executable: $report_executable" \
  "report-nonempty: $report_nonempty" \
  "report-temp-count: $report_temp_count"
