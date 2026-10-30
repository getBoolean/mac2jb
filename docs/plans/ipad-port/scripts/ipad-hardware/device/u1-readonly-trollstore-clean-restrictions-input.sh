#!/bin/sh
# Read-only input capture for TrollStore 2.1.1 cleanRestrictions().
#
# What this code does:
# 1. Accepts no arguments and closes stderr before inspecting one fixed parent
#    directory and one fixed ClientTruth.plist path used by TrollStore commit
#    88424f6. It rejects an unsearchable, unreadable, symlinked, or
#    mobile-writable input instead of treating it as absent.
# 2. Emits only `ABSENT` when the readable fixed parent proves the file does not
#    exist. Otherwise it selects fixed non-mobile-writable tar, timeout, and
#    sleep binaries, verifies timeout behavior with a harmless sleep canary,
#    and emits `ARCHIVE` followed by a timeout-bounded ustar stream containing
#    only the fixed plist.
# 3. Creates no remote archive, temporary, directory, report, or other file. It
#    does not invoke TrollStore, cleanRestrictions, profiled, a registration
#    API, a USB API, or an SSH configuration command. Reads can still affect
#    access metadata; SSH/tar/timeout can create ordinary logs and transient
#    process state.
#
exec 2>&-
set +euxv

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

if [ "$#" -ne 0 ]; then
  exit 64
fi

parent_directory='/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles'
member='private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/ClientTruth.plist'
target="/$member"

if [ ! -d "$parent_directory" ] || [ -L "$parent_directory" ] ||
  [ ! -r "$parent_directory" ] || [ ! -x "$parent_directory" ] ||
  [ -w "$parent_directory" ]; then
  exit 66
fi

if [ ! -e "$target" ] && [ ! -L "$target" ]; then
  command printf '%s\n' 'ABSENT'
  exit 0
fi

if [ ! -f "$target" ] || [ -L "$target" ] || [ ! -r "$target" ] ||
  [ -w "$target" ]; then
  exit 67
fi

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
if [ -z "$tar_path" ]; then
  exit 68
fi

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
for candidate in /bin/sleep /usr/bin/sleep /var/jb/bin/sleep /var/jb/usr/bin/sleep
do
  if [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
    [ -r "$candidate" ] && [ -x "$candidate" ] && [ ! -w "$candidate" ]; then
    sleep_path=$candidate
    break
  fi
done
if [ -z "$timeout_path" ] || [ -z "$sleep_path" ]; then
  exit 69
fi
"$timeout_path" -k 1 0.1 "$sleep_path" 1 </dev/null >/dev/null 2>&1
if [ "$?" -ne 124 ]; then
  exit 69
fi

command printf '%s\n' 'ARCHIVE'
exec "$timeout_path" -k 1 10 "$tar_path" \
  --create --file - --format=ustar -C / -- "$member"
