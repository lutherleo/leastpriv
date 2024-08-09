#!/usr/bin/env bash
# Runs the test suite with cross-package coverage over internal/... (the
# library code; cmd/ holds thin main wrappers) and fails below the threshold.
set -euo pipefail
min="${1:-80}"
cd "$(dirname "$0")/.."
go test -count=1 -covermode=atomic -coverpkg=./internal/... -coverprofile=coverage.out ./...
total="$(go tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$3); print $3}')"
echo "coverage (internal/...): ${total}% (threshold ${min}%)"
awk -v t="$total" -v m="$min" 'BEGIN { exit !(t+0 >= m+0) }' || { echo "coverage below threshold"; exit 1; }
