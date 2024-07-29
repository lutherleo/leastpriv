# leastpriv - one command gates everything: `make check`.
SHELL := /bin/bash
GO ?= go
GOLANGCI ?= golangci-lint
COVER_MIN ?= 80
BIN := bin
export GOFLAGS ?= -p=3

.PHONY: all build fmt fmt-check lint typecheck test test-short cover check demo eval bench fixtures golden integration clean

all: check

build: ## build the three commands into ./bin
	$(GO) build -trimpath -o $(BIN)/ ./cmd/...

fmt: ## rewrite Go files with gofmt
	gofmt -w cmd internal

fmt-check: ## fail if any Go file is not gofmt-clean
	@out="$$(gofmt -l cmd internal)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: ## golangci-lint (zero issues allowed)
	$(GOLANGCI) run ./...

typecheck: ## compile everything, including tests, and run go vet
	$(GO) build ./...
	$(GO) vet ./...

test: ## all tests (cover runs the same suite with the coverage gate)
	$(GO) test -count=1 ./...

test-short: ## quick run (smaller property-test budget)
	$(GO) test -short -count=1 ./...

cover: ## tests with cross-package coverage of internal/...; fails below COVER_MIN%
	./scripts/coverage.sh $(COVER_MIN)

check: fmt-check lint typecheck cover ## the full quality gate
	@echo "make check: OK"

demo: build ## offline end-to-end demo against the bundled synthetic fixture
	./scripts/demo.sh

eval: build ## held-out evaluation against synthetic ground truth
	./$(BIN)/lp-eval --data testdata/acme --out out/eval

bench: ## micro-benchmarks and the scaling benchmark used in docs
	./scripts/bench.sh

fixtures: ## regenerate testdata/acme deterministically (must produce no diff)
	$(GO) run ./cmd/lp-synth --out testdata/acme

golden: ## rewrite golden files after an intentional change; review the diff
	$(GO) test ./internal/generator ./internal/report -run Golden -update

integration: ## no Docker/network integration suite exists; every test is offline and runs in 'make test'
	@echo "integration: nothing to run (all tests are offline and run in 'make test')"

clean:
	rm -rf $(BIN) out coverage.out coverage.html
