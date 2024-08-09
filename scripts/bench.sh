#!/usr/bin/env bash
# Micro-benchmarks (glob matching, policy evaluation) and the generator
# scaling benchmark. Numbers depend on the machine and its load; the README
# quotes one run and states the hardware.
set -euo pipefail
cd "$(dirname "$0")/.."
go test -run '^$' -bench 'BenchmarkMatch|BenchmarkSubsumes' -benchtime 200000x ./internal/glob
go test -run '^$' -bench 'BenchmarkEvaluate' -benchtime 200000x ./internal/engine
go test -run '^$' -bench 'BenchmarkGenerateScaling' -benchtime 3x -timeout 30m ./internal/generator
