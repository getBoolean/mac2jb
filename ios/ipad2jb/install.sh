#!/bin/sh
# Build ipad2jb and install it on a jailbroken iPad (rootless /var/jb) over SSH.
#   ios/ipad2jb/install.sh root@<ipad-address> [extra ssh options...]
# Copies to a temporary name first and renames it into place, so a failed
# transfer never leaves a broken command.
set -eu
[ $# -ge 1 ] || { echo "usage: $0 root@<ipad-address> [ssh options...]" >&2; exit 64; }
target=$1; shift
here=$(cd "$(dirname "$0")" && pwd)
binary="$here/../../build/ipad2jb"
"$here/build.sh" "$binary" >/dev/null
ssh "$@" "$target" 'cat > /var/jb/usr/bin/ipad2jb.incoming &&
    chmod 755 /var/jb/usr/bin/ipad2jb.incoming &&
    mv -f /var/jb/usr/bin/ipad2jb.incoming /var/jb/usr/bin/ipad2jb &&
    echo "installed /var/jb/usr/bin/ipad2jb"' < "$binary"
