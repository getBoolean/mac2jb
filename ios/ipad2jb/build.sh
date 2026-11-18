#!/bin/sh
# Build and ad-hoc sign ipad2jb for arm64 iOS (on a Mac with Xcode).
# Output: build/ipad2jb, or the path given as $1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-"$here/../../build/ipad2jb"}
mkdir -p "$(dirname "$out")"
xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 -std=c11 -O2 -Wall -Wextra -Werror \
    -framework IOKit -framework CoreFoundation \
    "$here/main.c" "$here/core.c" "$here/iokit.c" -o "$out"
codesign --force --sign - --entitlements "$here/ipad2jb.entitlements" "$out"
shasum -a 256 "$out"
