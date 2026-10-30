#!/bin/sh
# Read-only AppSync Unified and appinst capability classification.
#
# What this code does:
# 1. Accepts no arguments, closes stderr, disables pathname expansion, and
#    selects fixed non-mobile-writable dpkg-query, timeout, sleep, and shell
#    executables. A nested canary proves that timeout kills a shell and its
#    background sleep before any package query can run.
# 2. Reads only the installed-package database records for the official
#    AppSync Unified, appinst, and ElleKit package identifiers. Every query is
#    device-timeout-bounded. Only an empty status-1 result means not-installed;
#    all partial, fatal, execution, signal, and timeout failures reject.
# 3. Classifies five fixed rootless paths by type and access flags only after
#    their fixed parents are readable, searchable, and not mobile-writable.
#    Otherwise it emits not-observed. Symbolic links are reported without
#    testing or reading their targets.
# 4. Never invokes appinst, AppSync code, a package install/remove operation,
#    launchctl, installd, TrollStore, profiled, a USB API, or a remote write.
#    Package/file reads can still affect access metadata; SSH and dpkg-query can
#    create ordinary logs or transient process state. Results are a point-in-
#    time snapshot and assume no concurrent root or package-manager mutation.

exec 2>&-
set +euxv
set -f

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

if [ "$#" -ne 0 ]; then
  exit 64
fi

dpkg_query=
for candidate in \
  /var/jb/usr/bin/dpkg-query \
  /var/jb/bin/dpkg-query \
  /usr/bin/dpkg-query \
  /bin/dpkg-query
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    dpkg_query=$candidate
    break
  fi
done
if [ -z "$dpkg_query" ]; then
  command printf '%s\n' 'dpkg-query: not-observed'
  exit 66
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
  /var/jb/usr/bin/timeout /var/jb/bin/timeout /usr/bin/timeout /bin/timeout \
  /var/jb/usr/bin/gtimeout /var/jb/bin/gtimeout /usr/bin/gtimeout /bin/gtimeout
timeout_path=$selected_tool
select_readonly_tool /bin/sleep /usr/bin/sleep /var/jb/bin/sleep /var/jb/usr/bin/sleep
sleep_path=$selected_tool
select_readonly_tool \
  /bin/sh /usr/bin/sh /var/jb/bin/dash /var/jb/usr/bin/dash \
  /var/jb/bin/bash /var/jb/usr/bin/bash
shell_path=$selected_tool
if [ -z "$timeout_path" ] || [ -z "$sleep_path" ] || [ -z "$shell_path" ]; then
  exit 67
fi

# The inner shell starts a background sleep whose inherited stdout keeps the
# inner command-substitution pipe open. The outer two-second timeout therefore
# returns 0 with exactly `passed` only when the inner timeout returns 124 and
# terminates both the shell and its background descendant. If the descendant
# survives, the outer guard expires and this payload rejects before dpkg-query.
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

package_line() {
  label=$1
  package=$2
  framed_record=$(
    "$timeout_path" -k 1 3 \
      "$dpkg_query" -W -f='${Status}|${Version}|${Architecture}' "$package"
    query_status=$?
    if [ "$query_status" -eq 0 ]; then
      command printf %s '__MAC2JB_QUERY_STATUS_0__'
    elif [ "$query_status" -eq 1 ]; then
      command printf %s '__MAC2JB_QUERY_STATUS_1__'
    else
      command printf %s '__MAC2JB_QUERY_STATUS_ERROR__'
    fi
  )
  case "$framed_record" in
    *'__MAC2JB_QUERY_STATUS_0__')
      status=0
      record=${framed_record%'__MAC2JB_QUERY_STATUS_0__'}
      ;;
    *'__MAC2JB_QUERY_STATUS_1__')
      status=1
      record=${framed_record%'__MAC2JB_QUERY_STATUS_1__'}
      ;;
    *'__MAC2JB_QUERY_STATUS_ERROR__')
      status=error
      record=${framed_record%'__MAC2JB_QUERY_STATUS_ERROR__'}
      ;;
    *) exit 65 ;;
  esac
  case "$status" in
    0) ;;
    1)
      [ -z "$record" ] || exit 65
      PACKAGE_RESULT="$label: not-installed"
      return 0
      ;;
    *) exit 68 ;;
  esac
  case "$record" in
    *'
'*) exit 65 ;;
  esac
  saved_ifs=$IFS
  IFS='|'
  set -- $record
  IFS=$saved_ifs
  if [ "$#" -ne 3 ]; then
    exit 65
  fi
  package_status=$1
  version=$2
  architecture=$3
  if [ "$package_status" != 'install ok installed' ]; then
    PACKAGE_RESULT="$label: not-installed"
    return 0
  fi
  case "$version" in
    ''|*[!0-9A-Za-z.+:~_-]*) exit 65 ;;
  esac
  case "$architecture" in
    ''|*[!0-9A-Za-z_-]*) exit 65 ;;
  esac
  if [ "${#version}" -gt 64 ] || [ "${#architecture}" -gt 32 ]; then
    exit 65
  fi
  PACKAGE_RESULT="$label: installed version=$version architecture=$architecture"
}

package_line appsync-package ai.akemi.appsyncunified
appsync_package_line=$PACKAGE_RESULT
package_line appinst-package ai.akemi.appinst
appinst_package_line=$PACKAGE_RESULT
package_line ellekit-package ellekit
ellekit_package_line=$PACKAGE_RESULT

appinst_binary_path='/var/jb/usr/bin/appinst'
appinst_binary_parent='/var/jb/usr/bin'
appsync_installd_dylib_path='/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.dylib'
appsync_installd_filter_path='/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.plist'
appsync_frontboard_dylib_path='/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.dylib'
appsync_frontboard_filter_path='/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.plist'
appsync_library_parent='/var/jb/Library/MobileSubstrate/DynamicLibraries'

describe_path() {
  label=$1
  parent=$2
  target=$3
  type=not-observed
  readable=no
  writable=no
  executable=no
  if [ -d "$parent" ] && [ ! -L "$parent" ] &&
    [ -r "$parent" ] && [ -x "$parent" ] && [ ! -w "$parent" ]; then
    type=absent
    if [ -L "$target" ]; then
      type=symbolic-link
    elif [ -f "$target" ]; then
      type=regular-file
      [ -r "$target" ] && readable=yes
      [ -w "$target" ] && writable=yes
      [ -x "$target" ] && executable=yes
    elif [ -e "$target" ]; then
      type=other-object
    fi
  fi
  command printf '%s\n' \
    "$label-type: $type" \
    "$label-readable: $readable" \
    "$label-writable: $writable" \
    "$label-executable: $executable"
}

command printf '%s\n' \
  'dpkg-query: present' \
  "$appsync_package_line" \
  "$appinst_package_line" \
  "$ellekit_package_line"
describe_path appinst-binary "$appinst_binary_parent" "$appinst_binary_path"
describe_path appsync-installd-dylib "$appsync_library_parent" "$appsync_installd_dylib_path"
describe_path appsync-installd-filter "$appsync_library_parent" "$appsync_installd_filter_path"
describe_path appsync-frontboard-dylib "$appsync_library_parent" "$appsync_frontboard_dylib_path"
describe_path appsync-frontboard-filter "$appsync_library_parent" "$appsync_frontboard_filter_path"
