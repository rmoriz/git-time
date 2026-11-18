#!/bin/sh
# Package one built binary as a release tarball plus its checksum.
#
# Usage: scripts/package.sh <target> <path-to-binary>
#
# Output lands in dist-binaries/, so it never mixes with the build directory.
set -eu

target=$1
binary=$2
name="git-time-$target"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

mkdir -p "dist-binaries/$name"
cp "$binary" "dist-binaries/$name/"
cp README.md LICENSE "dist-binaries/$name/"
printf '%s\n' "$version" > "dist-binaries/$name/VERSION"

tar -C dist-binaries -czf "dist-binaries/$name.tar.gz" "$name"
# Checksum relative to the artifact directory, so the published SHA256SUMS works
# when verified next to the downloaded tarballs.
if command -v sha256sum >/dev/null 2>&1; then
  ( cd dist-binaries && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256" )
else
  ( cd dist-binaries && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256" )
fi
tar -tzf "dist-binaries/$name.tar.gz" | sort
