#!/bin/sh
# Apply the patches if the tree is still pristine, build the library and the
# known-answer tests, then run them.
# Usage: tests/run_kat.sh <build dir> [extra CFLAGS]
# Run from the repository root; the 32-bit CI job runs the same script inside
# a linux/386 container.
set -eu
build=$1
cflags=${2:-}
# A pristine tree has no tracked changes; files the patches add can survive a
# reset --hard, so they are cleaned before applying rather than trusted
if git -C libsodium diff --quiet; then
  git -C libsodium clean -fdq
  patches/apply.sh
fi
if git -C libsodium diff --quiet; then
  echo "libsodium is unpatched; run patches/apply.sh" >&2
  exit 1
fi
test -f libsodium/src/libsodium/crypto_core/ed25519/ref10/base_packed.h
cmake -B "$build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="$cflags" .
cmake --build "$build" -j
# upstream's SHA256 as it is at the pinned tag, for the differential in kat.c
git -C libsodium show HEAD:src/libsodium/crypto_hash/sha256/cp/hash_sha256_cp.c \
  > "$build/upstream_hash_sha256_cp.c"
# shellcheck disable=SC2086
gcc -O2 -Wall -Wextra -DCONFIGURED=1 $cflags -o "$build/kat" tests/kat.c tests/sha256_reference.c \
  -Ilibsodium/src/libsodium/include -Ilibsodium/src/libsodium/include/sodium \
  -Iport_include -I"$build" "$build/libsodium.a"
"$build/kat"
