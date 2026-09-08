#!/bin/bash

# Apply patches and pack the package for upload

set -euxo pipefail

# Reset submodule state (clean removes files created by patches)
git -C libsodium reset --hard HEAD
git -C libsodium clean -fd

git submodule update --init

patches/apply.sh

pio package pack -o dist/
