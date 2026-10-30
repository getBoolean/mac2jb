#!/bin/sh
# Read-only classifier for the narrowed app-plist tar stream.
#
# The payload selects the same trusted tar candidate and the same fixed
# Dopamine*/TrollStore* Info.plist candidates as the archive payload. It creates
# test archives only on stdout redirected to `/dev/null`; no remote file is
# created. Every tar process is guarded by a fixed, non-writable device-side
# timeout whose behavior is checked with a one-second sleep canary first. Raw
# paths, tar diagnostics, version text, and plist contents are never emitted.
# Output is eight fixed-label categorical/numeric lines.

exec 2>&-
set +euxv

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

if [ "$#" -ne 0 ]; then exit 64; fi

tar_path=
for candidate in \
  /var/jb/usr/bin/bsdtar \
  /var/jb/usr/bin/tar \
  /var/jb/bin/tar \
  /usr/bin/tar \
  /bin/tar
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    tar_path=$candidate
    break
  fi
done

timeout_path=
for candidate in \
  /var/jb/usr/bin/timeout \
  /var/jb/bin/timeout \
  /usr/bin/timeout \
  /bin/timeout \
  /var/jb/usr/bin/gtimeout \
  /var/jb/bin/gtimeout \
  /usr/bin/gtimeout \
  /bin/gtimeout
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    timeout_path=$candidate
    break
  fi
done

sleep_path=
for candidate in \
  /bin/sleep \
  /usr/bin/sleep \
  /var/jb/bin/sleep \
  /var/jb/usr/bin/sleep
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    sleep_path=$candidate
    break
  fi
done

timeout_guard=not-observed
if [ -n "$timeout_path" ] && [ -n "$sleep_path" ]; then
  "$timeout_path" -k 1 0.1 "$sleep_path" 1 </dev/null >/dev/null 2>&1
  if [ "$?" -eq 124 ]; then
    timeout_guard=canary-passed
  else
    timeout_guard=canary-failed
  fi
fi

tar_family=not-observed
if [ -n "$tar_path" ] && [ "$timeout_guard" = canary-passed ]; then
  version_output=$("$timeout_path" -k 1 3 "$tar_path" --version 2>&1)
  version_status=$?
  case "$version_status" in
    0)
      case "$version_output" in
        *GNU*tar*) tar_family=gnu ;;
        *bsdtar*|*libarchive*) tar_family=libarchive ;;
        *) tar_family=other ;;
      esac
      ;;
    1|2) ;;
    124) exit 71 ;;
    *) exit 70 ;;
  esac
fi

set --
candidate_count=0
success_count=0
failure_count=0
path_length_class=none
for plist in \
  /var/containers/Bundle/Application/*/Dopamine*.app/Info.plist \
  /var/containers/Bundle/Application/*/TrollStore*.app/Info.plist \
  /Applications/Dopamine*.app/Info.plist \
  /Applications/TrollStore*.app/Info.plist \
  /var/jb/Applications/Dopamine*.app/Info.plist \
  /var/jb/Applications/TrollStore*.app/Info.plist
do
  if [ ! -f "$plist" ] || [ -L "$plist" ] || [ ! -r "$plist" ]; then continue; fi
  app_directory=${plist%/Info.plist}
  container_directory=${app_directory%/*}
  if [ -L "$app_directory" ] || [ -L "$container_directory" ]; then continue; fi
  candidate_count=$((candidate_count + 1))
  if [ "$candidate_count" -gt 8 ]; then exit 65; fi
  set -- "$@" "$plist"
  if [ "${#plist}" -gt 100 ]; then
    path_length_class=over-100
  elif [ "$path_length_class" = none ]; then
    path_length_class=at-most-100
  fi
  if [ -z "$tar_path" ] || [ "$timeout_guard" != canary-passed ]; then
    failure_count=$((failure_count + 1))
    continue
  fi
  "$timeout_path" -k 1 3 "$tar_path" \
    --create --file - --format=ustar --no-recursion -- "$plist" >/dev/null
  tar_status=$?
  case "$tar_status" in
    0) success_count=$((success_count + 1)) ;;
    1|2) failure_count=$((failure_count + 1)) ;;
    124) exit 71 ;;
    *) exit 70 ;;
  esac
done

empty_status=127
combined_status=127
if [ -n "$tar_path" ] && [ "$timeout_guard" = canary-passed ]; then
  "$timeout_path" -k 1 3 "$tar_path" \
    --create --file - --format=ustar --files-from /dev/null >/dev/null
  empty_status=$?
  case "$empty_status" in
    0|1|2) ;;
    124) exit 71 ;;
    *) exit 70 ;;
  esac
  if [ "$candidate_count" -eq 0 ]; then
    combined_status=$empty_status
  else
    "$timeout_path" -k 1 3 "$tar_path" \
      --create --file - --format=ustar --no-recursion -- "$@" >/dev/null
    combined_status=$?
    case "$combined_status" in
      0|1|2) ;;
      124) exit 71 ;;
      *) exit 70 ;;
    esac
  fi
fi

command printf '%s\n' \
  "timeout-guard: $timeout_guard" \
  "tar-family: $tar_family" \
  "target-candidate-count: $candidate_count" \
  "target-path-length: $path_length_class" \
  "single-file-success-count: $success_count" \
  "single-file-failure-count: $failure_count" \
  "empty-archive-status: $empty_status" \
  "combined-archive-status: $combined_status"
