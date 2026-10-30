#!/bin/sh
# Read-only classifier for the two app plists that GNU tar rejected by absolute
# pathname. It first discovers at most two fixed Dopamine*/TrollStore* plist
# candidates without invoking a reader. It then compares four bounded reads:
#
# 1. `dd` reads one byte to `/dev/null`, proving whether a normal process can
#    actually open the plist rather than relying only on shell `-r` metadata.
# 2. GNU tar receives a root-relative path with ustar plus `--no-recursion`.
# 3. GNU tar receives the same root-relative path with its default archive
#    format plus `--no-recursion`.
# 4. GNU tar receives the same file with only create/file/change-directory and
#    the option separator, isolating the remaining optional flags.
#
# Every external read is guarded by a fixed, non-writable device-side timeout
# whose status-124 behavior is proved with a one-second sleep canary. Only normal
# tool statuses may continue; a timeout or ambiguous wrapper status aborts before
# any later device access. Archive bytes and direct-read bytes go only to
# `/dev/null`. No path, plist content, version text, or tool diagnostic is output.

exec 2>&-
set +euxv

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

if [ "$#" -ne 0 ]; then exit 64; fi

select_readonly_tool() {
  selected_tool=
  for tool_candidate do
    if [ -f "$tool_candidate" ] && [ ! -L "$tool_candidate" ] &&
      [ -r "$tool_candidate" ] && [ -x "$tool_candidate" ] && [ ! -w "$tool_candidate" ]; then
      selected_tool=$tool_candidate
      break
    fi
  done
}

select_readonly_tool \
  /var/jb/usr/bin/bsdtar /var/jb/usr/bin/tar /var/jb/bin/tar /usr/bin/tar /bin/tar
tar_path=$selected_tool

select_readonly_tool \
  /var/jb/usr/bin/timeout /var/jb/bin/timeout /usr/bin/timeout /bin/timeout \
  /var/jb/usr/bin/gtimeout /var/jb/bin/gtimeout /usr/bin/gtimeout /bin/gtimeout
timeout_path=$selected_tool

select_readonly_tool /bin/sleep /usr/bin/sleep /var/jb/bin/sleep /var/jb/usr/bin/sleep
sleep_path=$selected_tool

select_readonly_tool /bin/dd /usr/bin/dd /var/jb/bin/dd /var/jb/usr/bin/dd
dd_path=$selected_tool

timeout_guard=not-observed
if [ -n "$timeout_path" ] && [ -n "$sleep_path" ]; then
  "$timeout_path" -k 1 0.1 "$sleep_path" 1 </dev/null >/dev/null 2>&1
  canary_status=$?
  case "$canary_status" in
    124) timeout_guard=canary-passed ;;
    125|126|127|137) exit 70 ;;
    *) timeout_guard=canary-failed ;;
  esac
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

dd_candidate=not-observed
if [ -n "$dd_path" ]; then dd_candidate=present; fi

set --
candidate_count=0
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
  if [ "$candidate_count" -gt 2 ]; then exit 65; fi
  set -- "$@" "$plist"
done

direct_success=0
direct_failure=0
ustar_success=0
ustar_failure=0
default_success=0
default_failure=0
minimal_success=0
minimal_failure=0

for plist in "$@"; do
  relative_plist=${plist#/}

  if [ -n "$dd_path" ] && [ "$timeout_guard" = canary-passed ]; then
    "$timeout_path" -k 1 3 "$dd_path" if="$plist" of=/dev/null bs=1 count=1 >/dev/null
    read_status=$?
    case "$read_status" in
      0) direct_success=$((direct_success + 1)) ;;
      1) direct_failure=$((direct_failure + 1)) ;;
      124) exit 71 ;;
      *) exit 70 ;;
    esac
  else
    direct_failure=$((direct_failure + 1))
  fi

  if [ -n "$tar_path" ] && [ "$timeout_guard" = canary-passed ]; then
    "$timeout_path" -k 1 3 "$tar_path" \
      --create --file - --format=ustar --no-recursion -C / -- "$relative_plist" >/dev/null
    ustar_status=$?
    case "$ustar_status" in
      0) ustar_success=$((ustar_success + 1)) ;;
      1|2) ustar_failure=$((ustar_failure + 1)) ;;
      124) exit 71 ;;
      *) exit 70 ;;
    esac

    "$timeout_path" -k 1 3 "$tar_path" \
      --create --file - --no-recursion -C / -- "$relative_plist" >/dev/null
    default_status=$?
    case "$default_status" in
      0) default_success=$((default_success + 1)) ;;
      1|2) default_failure=$((default_failure + 1)) ;;
      124) exit 71 ;;
      *) exit 70 ;;
    esac

    "$timeout_path" -k 1 3 "$tar_path" \
      --create --file - -C / -- "$relative_plist" >/dev/null
    minimal_status=$?
    case "$minimal_status" in
      0) minimal_success=$((minimal_success + 1)) ;;
      1|2) minimal_failure=$((minimal_failure + 1)) ;;
      124) exit 71 ;;
      *) exit 70 ;;
    esac
  else
    ustar_failure=$((ustar_failure + 1))
    default_failure=$((default_failure + 1))
    minimal_failure=$((minimal_failure + 1))
  fi
done

command printf '%s\n' \
  "timeout-guard: $timeout_guard" \
  "tar-family: $tar_family" \
  "dd-candidate: $dd_candidate" \
  "target-candidate-count: $candidate_count" \
  "direct-read-success-count: $direct_success" \
  "direct-read-failure-count: $direct_failure" \
  "relative-ustar-success-count: $ustar_success" \
  "relative-ustar-failure-count: $ustar_failure" \
  "relative-default-success-count: $default_success" \
  "relative-default-failure-count: $default_failure" \
  "relative-minimal-success-count: $minimal_success" \
  "relative-minimal-failure-count: $minimal_failure"
