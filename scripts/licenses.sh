#!/usr/bin/env bash
# Checks dependency licences and prints THIRD_PARTY_LICENSES.md for every
# release platform: some modules are imported on one OS only (go-winio on
# windows, procfs on linux), so the reports of both are merged.
# Usage: scripts/licenses.sh <go-licenses binary> <template> <allowed licences>
set -euo pipefail

bin=$1
tpl=$2
allowed=$3

reports=$(mktemp)
trap 'rm -f "$reports"' EXIT

for os in linux windows; do
	GOOS=$os "$bin" check --allowed_licenses="$allowed" ./...
	GOOS=$os "$bin" report ./... --template "$tpl" >"$reports.$os"
	cat "$reports.$os" >>"$reports"
done

# Header of the template (up to the table rule), then the unique rows.
awk '{print} /^\|---/{exit}' "$reports.linux"
grep '^| ' "$reports" | grep -v '^| Module ' | LC_ALL=C sort -u
rm -f "$reports.linux" "$reports.windows"
echo
