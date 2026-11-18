#!/bin/sh
# Build and ad-hoc sign ipad2jb for arm64 iOS (run on a Mac with Xcode).
# Output: build/ipad-hardware/ipad2jb (or the path given as $1).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-"$here/../../build/ipad-hardware/ipad2jb"}
xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 -O2 -Wall -Wextra \
    -framework IOKit -framework CoreFoundation "$here/ipad2jb.c" -o "$out"
codesign --force --sign - --entitlements "$here/ipad2jb.entitlements" "$out"
shasum -a 256 "$out"
