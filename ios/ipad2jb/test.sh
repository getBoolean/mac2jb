#!/bin/sh
# Build and run ipad2jb's host tests (macOS): core.c against fake devices,
# with address and undefined-behavior sanitizers.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
clang -std=c11 -Wall -Wextra -Werror -g -fsanitize=address,undefined \
    -framework CoreFoundation "$here/core.c" "$here/tests/test_core.c" -o "$out/test_core"
"$out/test_core"
