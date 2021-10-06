#!/bin/bash

# Apply patches and pack the package for upload

set -euxo pipefail

# Reset submodule state
git -C libsodium reset --hard HEAD

git submodule update

for f in patches/*; do
    git -C libsodium apply "../${f}"
done

pio package pack -o dist/
