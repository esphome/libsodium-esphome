#!/bin/sh
# Apply the patches if the tree is still pristine, build the library and the
# known-answer tests, then run them.
# Usage: tests/run_kat.sh <build dir> [extra CFLAGS]
# Run from the repository root; the 32-bit CI job runs the same script inside
# a linux/386 container.
set -eu
build=$1
cflags=${2:-}
marker=libsodium/src/libsodium/include/sodium/sodium_esphome_patched.h
if [ ! -f "$marker" ]; then
  patches/apply.sh
fi
# the marker comes from patch 06 and the table from patch 10; without them
# this would test the pristine library and none of the port
test -f "$marker"
test -f libsodium/src/libsodium/crypto_core/ed25519/ref10/base_packed.h
cmake -B "$build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="$cflags" .
cmake --build "$build" -j
# shellcheck disable=SC2086
gcc -O2 -Wall -Wextra $cflags -o "$build/kat" tests/kat.c \
  -Ilibsodium/src/libsodium/include -Iport_include "$build/libsodium.a"
"$build/kat"
