#!/bin/sh
# Stage one built binary as a release asset, named after its target.
#
# Usage: scripts/package.sh <target> <path-to-binary>
#
# Output lands in dist-binaries/, so it never mixes with the build directory.
# The file is published as it is: no archive, no checksum file, nothing to
# unpack — download, `chmod +x`, run.
set -eu

target=$1
binary=$2
staged="dist-binaries/git-time-$target"

mkdir -p dist-binaries
cp "$binary" "$staged"
chmod +x "$staged"
file "$staged"
