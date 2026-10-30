#!/bin/sh
# Read-only option-parser check for the fixed tar staging candidate.
#
# What this script does:
# - Selects only from a fixed absolute tar allowlist and classifies that selection
#   into one of three fixed path categories without emitting the path.
# - Runs only `--version` option-parser checks, always with stdin from /dev/null and
#   stdout/stderr suppressed or captured in shell memory.
# - Reports whether tar identifies as libarchive/bsdtar or GNU tar and whether it
#   accepts keep-old-files, safe-writes, ownership/permission suppression, and
#   extended-metadata suppression options needed by a proposed staging design.
# - Emits exactly seven fixed-label lines and no raw version/help text or metadata.
#
# No archive is opened or extracted, no directory is enumerated, and no target file
# is referenced. SSH and process startup can still create normal accounting logs
# and transient cache activity; no payload-directed persistent write is intended.

exec 2>&-
set +euxv

tar_path=''
tar_candidate='not observed'
for candidate in /var/jb/usr/bin/bsdtar /var/jb/usr/bin/tar /var/jb/bin/tar /usr/bin/tar /bin/tar; do
  if [ -x "$candidate" ]; then
    tar_path=$candidate
    case "$candidate" in
      /var/jb/usr/bin/bsdtar) tar_candidate='rootless bsdtar' ;;
      /var/jb/*) tar_candidate='rootless tar' ;;
      *) tar_candidate='system tar' ;;
    esac
    break
  fi
done

tar_family='not observed'
keep_old='not observed'
safe_writes='not observed'
no_same_owner='not observed'
no_same_permissions='not observed'
no_extended_metadata='not observed'

if [ -n "$tar_path" ]; then
  version_output=$("$tar_path" --version </dev/null 2>&1)
  case "$version_output" in
    *bsdtar*|*libarchive*) tar_family='libarchive' ;;
    *GNU*tar*) tar_family='gnu' ;;
    *) tar_family='other' ;;
  esac
  if "$tar_path" -k --version </dev/null >/dev/null 2>&1; then keep_old='present'; fi
  if "$tar_path" --safe-writes --version </dev/null >/dev/null 2>&1; then safe_writes='present'; fi
  if "$tar_path" --no-same-owner --version </dev/null >/dev/null 2>&1; then no_same_owner='present'; fi
  if "$tar_path" --no-same-permissions --version </dev/null >/dev/null 2>&1; then no_same_permissions='present'; fi
  if "$tar_path" --no-xattrs --no-acls --no-fflags --version </dev/null >/dev/null 2>&1; then no_extended_metadata='present'; fi
fi

command printf '%s\n' \
  "tar-candidate: $tar_candidate" \
  "tar-family: $tar_family" \
  "tar-keep-old-files: $keep_old" \
  "tar-safe-writes: $safe_writes" \
  "tar-no-same-owner: $no_same_owner" \
  "tar-no-same-permissions: $no_same_permissions" \
  "tar-no-extended-metadata: $no_extended_metadata"
