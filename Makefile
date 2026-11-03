# modbus-shield — minimal build/test automation.
# The project is plain Go: `go build ./...` works without make.
# This file exists for appliance packaging convenience.

BINARY := modbus-shield
GO     ?= go
VERSION ?= 1.0.1
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test fmt-check vet staticcheck govulncheck race verify acceptance security peers interop interop-pymodbus interop-required soak cover release release-all release-assets sbom vulnscan clean

all: build

build:
	$(GO) build -o bin/$(BINARY) ./cmd/modbus-shield

# fmt-check fails when any Go file is not gofmt-formatted. The repo is
# gofmt-clean; without CI this is the gate that keeps it that way.
fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; fi

test: fmt-check
	# -p 1: fixtures probe free UDP/TCP ports before binding them, so
	# packages running in parallel can steal a probed port and turn a
	# green suite into an environment race. Serialising packages keeps
	# the gate deterministic; run a single package for a fast edit loop.
	$(GO) test ./... -p 1 -race -timeout 600s

vet:
	$(GO) vet ./...

staticcheck:
	~/go/bin/staticcheck ./...

govulncheck:
	~/go/bin/govulncheck ./...

race: test

# soak runs the long multi-device steady-state test a green `make test`
# cannot judge: continuous load, flat goroutines and live heap. Ten minutes
# by default; SOAK_DURATION overrides it (e.g. `make soak SOAK_DURATION=90s`).
soak:
	MODBUS_SHIELD_SOAK=1 MODBUS_SHIELD_SOAK_DURATION=$${SOAK_DURATION:-10m} \
		$(GO) test ./internal/proxy -run 'TestSoak' -count=1 -timeout 30m -v

# Shared quality gates across the Shield projects.
verify: build test vet

# Acceptance adds independent Modbus peers (mbpoll and pymodbus) and
# real-binary policy reload/connection-ID smoke tests to the deterministic
# race suite. A missing peer fails the release gate instead of skipping.
acceptance: verify interop-required
	sh scripts/smoke-reload.sh
	sh scripts/smoke-connid.sh

# Release security gate. Requires staticcheck, govulncheck, syft and grype;
# unlike individual optional tooling probes, a missing tool fails this target.
security: verify staticcheck govulncheck vulnscan

# peers provisions the independent Python Modbus stack (pymodbus) in .venv.
# Exit 77 when Python/pip is unavailable.
peers:
	sh scripts/peers-setup.sh

# interop drives the built gateway with the real mbpoll client against a
# fake device (reads, writes, exception pass-through, unit-ID addressing,
# concurrent clients). Exit 77 when mbpoll is missing.
interop: build
	@MBPOLL_BIN="$${MBPOLL_BIN:-mbpoll}" sh scripts/interop-modbus.sh

# interop-pymodbus drives both legs with an independent Python stack:
# pymodbus client -> gateway -> pymodbus device. Exit 77 when the venv is
# missing (run `make peers`).
interop-pymodbus: build
	@sh scripts/interop-pymodbus.sh

# interop-required is the release gate: both independent peers must run,
# not skip.
interop-required: build
	@INTEROP_REQUIRED=1 MBPOLL_BIN="$${MBPOLL_BIN:-mbpoll}" sh scripts/interop-modbus.sh
	@INTEROP_REQUIRED=1 sh scripts/interop-pymodbus.sh

# cover measures statement coverage and enforces the per-package floors in
# coverage.floors. A single overall number hides the package that regressed;
# the floors make a drop in the security boundary visible even when the total
# is flat. This is a regression gate, not a target to game: raise a floor when
# a package improves, and add a test rather than lowering it.
cover:
	@mkdir -p dist
	# -p 1: the fixtures probe free UDP ports (FreeUDPPort is a probe, not a
	# reservation), so packages running in parallel can steal each other's
	# port. Serialising packages keeps this gate deterministic.
	$(GO) test ./... -p 1 -covermode=atomic -coverprofile=dist/cover.out -timeout 600s
	$(GO) run ./scripts/covercheck dist/cover.out coverage.floors

# release builds a stripped static binary for appliance deployment.
release:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/modbus-shield

# release-all cross-builds stripped static binaries for the appliance
# platforms (amd64 + arm64 + armv7) into dist/. The project is pure Go
# with CGO disabled, so cross-compiling is exact — no ports, no ifdef.
release-all:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/modbus-shield
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 ./cmd/modbus-shield
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-armv7 ./cmd/modbus-shield
	@echo "release binaries written to dist/ ($(BINARY)-linux-{amd64,arm64,armv7}) version $(VERSION)"

# release-assets produces exactly what the GitHub release carries: the three
# Linux binaries, a per-binary SPDX + CycloneDX SBOM, and SHA256SUMS.
# Requires syft (https://github.com/anchore/syft); exits 77 when missing.
release-assets: release-all
	@command -v syft >/dev/null 2>&1 || { echo "syft not installed (GOBIN=$$HOME/go/bin go install github.com/anchore/syft/cmd/syft@latest)"; exit 77; }
	@for bin in dist/$(BINARY)-linux-amd64 dist/$(BINARY)-linux-arm64 dist/$(BINARY)-linux-armv7; do \
		syft "$$bin" -o spdx-json="$$bin.spdx.json" -o cyclonedx-json="$$bin.cdx.json"; \
	done
	@cd dist && shasum -a 256 $(BINARY)-linux-amd64 $(BINARY)-linux-amd64.cdx.json $(BINARY)-linux-amd64.spdx.json \
		$(BINARY)-linux-arm64 $(BINARY)-linux-arm64.cdx.json $(BINARY)-linux-arm64.spdx.json \
		$(BINARY)-linux-armv7 $(BINARY)-linux-armv7.cdx.json $(BINARY)-linux-armv7.spdx.json > SHA256SUMS
	@echo "release assets in dist/ (binaries, SBOMs, SHA256SUMS)"

# sbom generates SPDX + CycloneDX SBOMs for the release binary into dist/.
# Requires syft (https://github.com/anchore/syft); exits 77 when missing.
sbom: release
	@command -v syft >/dev/null 2>&1 || { echo "syft not installed (GOBIN=$$HOME/go/bin go install github.com/anchore/syft/cmd/syft@latest)"; exit 77; }
	@mkdir -p dist
	syft bin/$(BINARY) -o spdx-json=dist/$(BINARY).spdx.json -o cyclonedx-json=dist/$(BINARY).cdx.json
	@echo "SBOMs written to dist/$(BINARY).spdx.json + dist/$(BINARY).cdx.json"

# vulnscan matches the SBOM against vulnerability databases (NVD/GHSA/OSV)
# via grype and fails on findings at severity HIGH or above.
# Requires grype (https://github.com/anchore/grype); exits 77 when missing.
vulnscan: sbom
	@command -v grype >/dev/null 2>&1 || { echo "grype not installed (GOBIN=$$HOME/go/bin go install github.com/anchore/grype/cmd/grype@latest)"; exit 77; }
	grype db update
	grype dist/$(BINARY).spdx.json --fail-on high

clean:
	rm -f bin/$(BINARY)
	rm -rf dist/
