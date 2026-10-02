#!/usr/bin/env bash
# Inspects the packed EEIP .nupkg/.snupkg in the given directory: the expected payload is present and
# the shipped assembly carries no InternalsVisibleTo for the test project (it is unsigned, so any
# assembly could claim that name and reach internals).
set -euo pipefail

dir="${1:?usage: verify-package.sh <package-dir>}"
friends=(EEIP.NET.Tests)

shopt -s nullglob
nupkgs=("$dir"/*.nupkg)
snupkgs=("$dir"/*.snupkg)
[ ${#nupkgs[@]} -eq 1 ] || { echo "::error::expected exactly one .nupkg in $dir, found ${#nupkgs[@]}"; exit 1; }
[ ${#snupkgs[@]} -eq 1 ] || { echo "::error::expected exactly one .snupkg in $dir, found ${#snupkgs[@]}"; exit 1; }
nupkg=${nupkgs[0]}
snupkg=${snupkgs[0]}

echo "Inspecting $nupkg / $snupkg"
unzip -Z1 "$nupkg" | grep -qx 'lib/net10.0/EEIP.dll' || { echo "::error::missing from package: lib/net10.0/EEIP.dll"; exit 1; }
unzip -Z1 "$snupkg" | grep -qx 'lib/net10.0/EEIP.pdb' || { echo "::error::missing from symbol package: lib/net10.0/EEIP.pdb"; exit 1; }

dll=$(mktemp)
trap 'rm -f "$dll"' EXIT
unzip -p "$nupkg" lib/net10.0/EEIP.dll > "$dll"
for friend in "${friends[@]}"; do
  if grep -aqF "$friend" "$dll"; then
    echo "::error::InternalsVisibleTo leaked into the shipped assembly: $friend"
    exit 1
  fi
done
echo "Package OK"
