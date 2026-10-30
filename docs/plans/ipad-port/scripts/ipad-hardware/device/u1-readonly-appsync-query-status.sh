#!/bin/sh
# Read-only status classifier for the three fixed AppSync/appinst package reads.
#
# What this code does:
# 1. Accepts no arguments, closes stderr, disables pathname expansion, and
#    selects fixed non-mobile-writable dpkg-query, timeout, sleep, shell, and
#    process-group kill executables.
# 2. Proves with a nested canary that the selected timeout kills a shell and
#    its background sleep. A second canary deliberately kills the timeout
#    supervisor, then proves the parent can remove and recheck its surviving
#    process group before running any package query.
# 3. Runs the exact bounded dpkg-query used by the presence probe for the
#    official AppSync Unified, appinst, and ElleKit package identifiers.
# 4. Sends all query stdout directly to `/dev/null` and emits only the three
#    numeric exit statuses. It never buffers or emits package records,
#    versions, architectures, paths, or diagnostics.
# 5. Never invokes appinst, AppSync code, package installation/removal, a
#    daemon, a USB API, or a remote write. Ordinary SSH/package-read logs,
#    access metadata, and bounded transient process state may still occur.
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

# GNU timeout makes itself the process-group leader before it forks the command.
# Model its documented ambiguous-137 case by killing that leader from the child,
# then require the parent shell to kill and verify disappearance of the surviving
# group. The exact same cleanup runs after every real query before the next one.
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

query_status() {
  label=$1
  package=$2
  "$timeout_path" -k 1 3 \
    "$dpkg_query" -W -f='${Status}|${Version}|${Architecture}' "$package" \
    >/dev/null &
  query_timeout_pid=$!
  wait "$query_timeout_pid"
  status=$?
  remove_timeout_group "$query_timeout_pid"
  case "$status" in
    ''|*[!0-9]*) exit 65 ;;
  esac
  if [ "$status" -gt 255 ]; then
    exit 65
  fi
  QUERY_STATUS_LINE="$label-status: $status"
}

query_status appsync-query ai.akemi.appsyncunified
appsync_status_line=$QUERY_STATUS_LINE
query_status appinst-query ai.akemi.appinst
appinst_status_line=$QUERY_STATUS_LINE
query_status ellekit-query ellekit
ellekit_status_line=$QUERY_STATUS_LINE

command printf '%s\n' \
  "$appsync_status_line" \
  "$appinst_status_line" \
  "$ellekit_status_line"
