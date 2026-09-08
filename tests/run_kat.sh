#!/bin/sh
# Build the library and the known-answer tests, then run them.
# Usage: tests/run_kat.sh <build dir> [extra CFLAGS]
# Run from the repository root with the patches applied; the 32-bit CI job
# runs the same script inside a linux/386 container.
set -eu
build=$1
cflags=${2:-}
cmake -B "$build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="$cflags" .
cmake --build "$build" -j
# shellcheck disable=SC2086
gcc -O2 -Wall -Wextra $cflags -o "$build/kat" tests/kat.c \
  -Ilibsodium/src/libsodium/include -Iport_include "$build/libsodium.a"
"$build/kat"
