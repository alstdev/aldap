#!/usr/bin/env bash
# Print GitHub Actions ::error annotations for every failed test found in a
# `go test -json` event file, so failures show up in the run summary without
# opening the logs. Run by gotestsum --post-run-command (GOTESTSUM_JSONFILE is
# set) or with the file as the first argument. Never fails the build itself.
set -uo pipefail

file="${1:-${GOTESTSUM_JSONFILE:-}}"
if [[ -z "$file" || ! -r "$file" ]]; then
  echo "ci-annotate: no test event file (${file:-unset})" >&2
  exit 0
fi

# go test -json writes {"Time":…,"Action":"fail","Package":"…","Test":"…",…};
# a failing package without a Test field is a build error, panic or timeout.
grep -E '"Action":"fail"' "$file" | sed -nE \
  -e 's/.*"Package":"([^"]+)","Test":"([^"]+)".*/::error title=Test failed::\1: \2/p' \
  -e '/"Test":/!s/.*"Package":"([^"]+)".*/::error title=Package failed::\1/p' |
  sort -u

grep -E '"Action":"output".*WARNING: DATA RACE' "$file" | sed -nE \
  -e 's/.*"Package":"([^"]+)","Test":"([^"]+)".*/::error title=Data race::\1: \2/p' |
  sort -u

exit 0
