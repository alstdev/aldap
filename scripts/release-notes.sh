#!/usr/bin/env bash
# Prints the CHANGELOG.md section of a release for the GitHub Release body.
#   scripts/release-notes.sh v1.2.0 [CHANGELOG.md]   → section "## [1.2.0]" (or "## [v1.2.0]")
#   scripts/release-notes.sh Unreleased              → section "## [Unreleased]" (dry run)
# Fails when the section is missing or empty: rename [Unreleased] before tagging.
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 VERSION [CHANGELOG]" >&2; exit 2; }
version="${1#v}"
file="${2:-CHANGELOG.md}"

notes="$(awk -v v="$version" '
  /^## \[/ {
    h = $0; sub(/^## \[v?/, "", h); sub(/\].*$/, "", h)
    if (found) exit
    found = (h == v); next
  }
  found { print }
' "$file")"

if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "no CHANGELOG section for ${version} in ${file}" >&2
  exit 1
fi
printf '%s\n' "$notes"
