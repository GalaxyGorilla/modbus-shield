# modbus-shield — minimal build/test automation.
# The project is plain Go: `go build ./...` works without make.
# This file exists for appliance packaging convenience.

BINARY := modbus-shield
GO     ?= go

.PHONY: all build test fmt-check vet staticcheck govulncheck race interop release release-all sbom vulnscan clean

all: build

build:
	$(GO) build -o bin/$(BINARY) ./cmd/modbus-shield

# fmt-check fails when any Go file is not gofmt-formatted. The repo is
# gofmt-clean; without CI this is the gate that keeps it that way.
fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; fi

test: fmt-check
	$(GO) test ./... -race -timeout 180s

vet:
	$(GO) vet ./...

staticcheck:
	~/go/bin/staticcheck ./...

govulncheck:
	~/go/bin/govulncheck ./...

race: test

# interop drives the built gateway with the real mbpoll client against a
# fake device (reads, writes, exception pass-through, unit-ID addressing,
# concurrent clients). Exit 77 when mbpoll is missing.
interop: build
	@MBPOLL_BIN="$${MBPOLL_BIN:-mbpoll}" sh scripts/interop-modbus.sh

# release builds a stripped static binary for appliance deployment.
release:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/$(BINARY) ./cmd/modbus-shield

# release-all cross-builds stripped static binaries for the appliance
# platforms (amd64 + arm64 + armv7) into dist/. The project is pure Go
# with CGO disabled, so cross-compiling is exact — no ports, no ifdef.
release-all:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o dist/$(BINARY)-linux-amd64 ./cmd/modbus-shield
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w" -o dist/$(BINARY)-linux-arm64 ./cmd/modbus-shield
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags "-s -w" -o dist/$(BINARY)-linux-armv7 ./cmd/modbus-shield
	@echo "release binaries written to dist/ ($(BINARY)-linux-{amd64,arm64,armv7})"

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
