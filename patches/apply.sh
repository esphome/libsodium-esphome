#!/bin/sh
# Apply every patch to the libsodium submodule, in order, checking each one
# first so a patch that no longer applies stops the run with its name.
# Run from the repository root.
set -eu
for f in patches/*.patch; do
  echo "Applying $f"
  git -C libsodium apply --check "../$f"
  git -C libsodium apply "../$f"
done
