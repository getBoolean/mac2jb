#!/bin/sh
# Read-only installed-record membership scan for AppSync Unified and appinst.
#
# What this code does:
# 1. Selects fixed non-mobile-writable dpkg-query, timeout, sleep, shell, and
#    process-group kill executables and accepts no arguments.
# 2. Proves ordinary timeout descendant teardown and deliberately kills one
#    timeout group leader to prove the exact negative-PGID cleanup path before
#    the package database can be read.
# 3. Runs one five-second-bounded full dpkg-query record scan. A fixed shell
#    filter reads one line at a time, retains only three fixed package states,
#    and requires the producer's terminal status marker. Raw package records,
#    package names other than the three fixed labels, and diagnostics never
#    reach the SSH stream.
# 4. Emits exactly four lines: the completed producer status and installed,
#    record-not-installed, or not-observed for AppSync Unified, appinst, and
#    ElleKit. It rejects duplicates, incomplete scans, malformed markers, and
#    every nonzero producer/supervisor result without publishing partial data.
# 5. Never invokes appinst, AppSync code, package installation/removal, a
#    daemon, a USB API, or a remote regular-file write. Ordinary logs, access
#    metadata, `/dev/null` writes, and bounded transient processes may occur.
#    Results assume no concurrent root or package-manager mutation.

exec 2>&-
set +euxv
set -f

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

if [ "$#" -ne 0 ]; then
  exit 64
fi

select_readonly_tool() {
  selected_tool=
  for candidate do
    if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
      [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
      selected_tool=$candidate
      break
    fi
  done
}

select_readonly_tool \
  /var/jb/usr/bin/dpkg-query /var/jb/bin/dpkg-query \
  /usr/bin/dpkg-query /bin/dpkg-query
dpkg_query=$selected_tool
select_readonly_tool \
  /var/jb/usr/bin/timeout /var/jb/bin/timeout /usr/bin/timeout /bin/timeout \
  /var/jb/usr/bin/gtimeout /var/jb/bin/gtimeout /usr/bin/gtimeout /bin/gtimeout
timeout_path=$selected_tool
select_readonly_tool /bin/sleep /usr/bin/sleep /var/jb/bin/sleep /var/jb/usr/bin/sleep
sleep_path=$selected_tool
select_readonly_tool \
  /bin/sh /usr/bin/sh /var/jb/bin/dash /var/jb/usr/bin/dash \
  /var/jb/bin/bash /var/jb/usr/bin/bash
shell_path=$selected_tool
select_readonly_tool \
  /var/jb/usr/bin/kill /var/jb/bin/kill /usr/bin/kill /bin/kill
kill_path=$selected_tool
if [ -z "$dpkg_query" ] || [ -z "$timeout_path" ] ||
  [ -z "$sleep_path" ] || [ -z "$shell_path" ] || [ -z "$kill_path" ]; then
  exit 66
fi

timeout_group_exists() {
  "$kill_path" -s 0 -- "-$1" >/dev/null 2>&1
}

remove_timeout_group() {
  group_pid=$1
  if timeout_group_exists "$group_pid"; then
    "$kill_path" -s KILL -- "-$group_pid" >/dev/null 2>&1 || exit 68
  fi
  check_count=0
  while timeout_group_exists "$group_pid"; do
    if [ "$check_count" -ge 10 ]; then
      exit 68
    fi
    "$sleep_path" 0.1 >/dev/null 2>&1 || exit 68
    check_count=$((check_count + 1))
  done
}

canary_output=$("$timeout_path" -k 1 2 "$shell_path" -c '
  inner_output=$("$1" -k 1 0.1 "$2" -c '\''"$1" 10 & wait'\'' mac2jb "$3")
  inner_status=$?
  [ -z "$inner_output" ] || exit 71
  [ "$inner_status" -eq 124 ] || exit 72
  command printf %s passed
' mac2jb "$timeout_path" "$shell_path" "$sleep_path")
if [ "$?" -ne 0 ] || [ "$canary_output" != passed ]; then
  exit 67
fi

"$timeout_path" -k 1 5 "$shell_path" -c '
  "$1" -s KILL "$PPID"
  "$2" 2
' mac2jb "$kill_path" "$sleep_path" >/dev/null &
self_kill_timeout_pid=$!
wait "$self_kill_timeout_pid"
if [ "$?" -ne 137 ]; then
  exit 67
fi
if ! timeout_group_exists "$self_kill_timeout_pid"; then
  exit 67
fi
remove_timeout_group "$self_kill_timeout_pid"

dpkg_format='${Package}|${Status}\n'
membership_and_status=$(
  "$timeout_path" -k 1 5 "$shell_path" -c '
    "$1" -c '\''
      "$1" -W -f="$2"
      producer_status=$?
      command printf "__MAC2JB_DPKG_STATUS__|%s\\n" "$producer_status"
    '\'' mac2jb "$2" "$3" |
    "$1" -c '\''
      appsync=not-observed
      appinst=not-observed
      ellekit=not-observed
      appsync_count=0
      appinst_count=0
      ellekit_count=0
      producer_status=
      marker_count=0
      marker_seen=no
      classify_dpkg_status() {
        raw_status=$1
        saved_status_ifs=$IFS
        IFS=" "
        set -- $raw_status
        IFS=$saved_status_ifs
        [ "$#" -eq 3 ] || exit 78
        case "$1" in
          unknown|install|hold|deinstall|purge) ;;
          *) exit 78 ;;
        esac
        case "$2" in
          ok|reinstreq) ;;
          *) exit 78 ;;
        esac
        case "$3" in
          not-installed|config-files|half-installed|unpacked|half-configured|triggers-awaited|triggers-pending|installed) ;;
          *) exit 78 ;;
        esac
        if [ "$3" = installed ]; then
          if [ "$2" = ok ]; then
            CLASSIFIED_STATUS=installed
          else
            CLASSIFIED_STATUS=installed-error
          fi
        else
          CLASSIFIED_STATUS=record-not-installed
        fi
      }
      while IFS= read -r line; do
        if [ "$marker_seen" = yes ]; then
          exit 75
        fi
        case "$line" in
          "ai.akemi.appsyncunified|"*)
            classify_dpkg_status "${line#"ai.akemi.appsyncunified|"}"
            appsync=$CLASSIFIED_STATUS
            appsync_count=$((appsync_count + 1))
            ;;
          "ai.akemi.appinst|"*)
            classify_dpkg_status "${line#"ai.akemi.appinst|"}"
            appinst=$CLASSIFIED_STATUS
            appinst_count=$((appinst_count + 1))
            ;;
          "ellekit|"*)
            classify_dpkg_status "${line#"ellekit|"}"
            ellekit=$CLASSIFIED_STATUS
            ellekit_count=$((ellekit_count + 1))
            ;;
          "__MAC2JB_DPKG_STATUS__|"*)
            producer_status=${line#"__MAC2JB_DPKG_STATUS__|"}
            marker_count=$((marker_count + 1))
            marker_seen=yes
            ;;
        esac
      done
      [ "$marker_count" -eq 1 ] || exit 76
      case "$producer_status" in
        ""|*[!0-9]*) exit 76 ;;
      esac
      [ "$producer_status" -le 255 ] || exit 76
      [ "$appsync_count" -le 1 ] || exit 77
      [ "$appinst_count" -le 1 ] || exit 77
      [ "$ellekit_count" -le 1 ] || exit 77
      command printf "%s\\n" \
        "dpkg-list-status: $producer_status" \
        "appsync-membership: $appsync" \
        "appinst-membership: $appinst" \
        "ellekit-membership: $ellekit"
    '\''
  ' mac2jb "$shell_path" "$dpkg_query" "$dpkg_format" &
  membership_timeout_pid=$!
  wait "$membership_timeout_pid"
  membership_status=$?
  remove_timeout_group "$membership_timeout_pid"
  command printf '__MAC2JB_SUPERVISOR_STATUS_%s__' "$membership_status"
)
if [ "$?" -ne 0 ]; then
  exit 68
fi

status_suffix=${membership_and_status##*'__MAC2JB_SUPERVISOR_STATUS_'}
case "$status_suffix" in
  *'__') supervisor_status=${status_suffix%'__'} ;;
  *) exit 65 ;;
esac
case "$supervisor_status" in
  ''|*[!0-9]*) exit 65 ;;
esac
if [ "$supervisor_status" -ne 0 ]; then
  exit 68
fi
supervisor_trailer="__MAC2JB_SUPERVISOR_STATUS_${supervisor_status}__"
case "$membership_and_status" in
  *"$supervisor_trailer") membership_output=${membership_and_status%"$supervisor_trailer"} ;;
  *) exit 65 ;;
esac

saved_ifs=$IFS
IFS='
'
set -- $membership_output
IFS=$saved_ifs
if [ "$#" -ne 4 ]; then
  exit 65
fi
case "$1" in
  'dpkg-list-status: '[0-9]|'dpkg-list-status: '[0-9][0-9]|'dpkg-list-status: '[0-9][0-9][0-9]) ;;
  *) exit 65 ;;
esac
producer_status=${1#'dpkg-list-status: '}
if [ "$producer_status" -ne 0 ]; then
  exit 68
fi
case "$2" in
  'appsync-membership: installed'|'appsync-membership: installed-error'|'appsync-membership: record-not-installed'|'appsync-membership: not-observed') ;;
  *) exit 65 ;;
esac
case "$3" in
  'appinst-membership: installed'|'appinst-membership: installed-error'|'appinst-membership: record-not-installed'|'appinst-membership: not-observed') ;;
  *) exit 65 ;;
esac
case "$4" in
  'ellekit-membership: installed'|'ellekit-membership: installed-error'|'ellekit-membership: record-not-installed'|'ellekit-membership: not-observed') ;;
  *) exit 65 ;;
esac

command printf '%s\n' "$1" "$2" "$3" "$4"
