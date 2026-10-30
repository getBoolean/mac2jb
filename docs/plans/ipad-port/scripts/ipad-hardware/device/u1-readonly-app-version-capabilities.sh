#!/bin/sh
# Read-only classifier for the fixed app-version probe prerequisites.
#
# This code uses only POSIX shell `test` operations on seven fixed paths. It
# never follows or prints a symbolic-link target, reads app metadata, enumerates
# a directory, or invokes the candidate tools. Each result is reduced to fixed
# type/access tokens so no device identifier or filesystem path is released.

exec 2>&-
set +euxv

PATH='/usr/bin:/usr/sbin:/bin:/sbin:/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin'
LC_ALL=C
export PATH LC_ALL

if [ "$#" -ne 0 ]; then
  exit 64
fi

classify_type() {
  candidate=$1
  if [ -L "$candidate" ]; then
    classified_type='symbolic-link'
  elif [ -f "$candidate" ]; then
    classified_type='regular-file'
  elif [ -d "$candidate" ]; then
    classified_type='directory'
  elif [ -e "$candidate" ]; then
    classified_type='other-object'
  else
    classified_type='absent'
  fi
}

yes_no_access() {
  operation=$1
  candidate=$2
  case "$operation" in
    readable) [ -r "$candidate" ] ;;
    writable) [ -w "$candidate" ] ;;
    executable) [ -x "$candidate" ] ;;
    *) return 1 ;;
  esac
  if [ "$?" -eq 0 ]; then
    classified_access=yes
  else
    classified_access=no
  fi
}

emit_tool() {
  label=$1
  candidate=$2
  classify_type "$candidate"
  yes_no_access readable "$candidate"
  readable=$classified_access
  yes_no_access writable "$candidate"
  writable=$classified_access
  yes_no_access executable "$candidate"
  executable=$classified_access
  command printf '%s-type: %s\n' "$label" "$classified_type"
  command printf '%s-readable: %s\n' "$label" "$readable"
  command printf '%s-writable: %s\n' "$label" "$writable"
  command printf '%s-executable: %s\n' "$label" "$executable"
}

emit_root() {
  label=$1
  candidate=$2
  classify_type "$candidate"
  yes_no_access readable "$candidate"
  readable=$classified_access
  yes_no_access executable "$candidate"
  executable=$classified_access
  command printf '%s-type: %s\n' "$label" "$classified_type"
  command printf '%s-readable: %s\n' "$label" "$readable"
  command printf '%s-searchable: %s\n' "$label" "$executable"
}

emit_tool system-plutil /usr/bin/plutil
emit_tool rootless-usr-plutil /var/jb/usr/bin/plutil
emit_tool rootless-bin-plutil /var/jb/bin/plutil
emit_tool rootless-plistutil /var/jb/usr/bin/plistutil
emit_root container-app-root /var/containers/Bundle/Application
emit_root system-app-root /Applications
emit_root rootless-app-root /var/jb/Applications
