#!/usr/bin/env bash
# Build the release binary, generate SPDX and CycloneDX SBOMs, and optionally
# scan them against vulnerability databases with grype.
#
#   scripts/sbom.sh               build + SBOM + HIGH-or-worse scan
#   scripts/sbom.sh --sbom-only   build + SBOM, without grype
#
# Exit 77 means a required external tool is unavailable.
set -euo pipefail

cd "$(dirname "$0")/.."

sbom_only=0
[ "${1:-}" = "--sbom-only" ] && sbom_only=1

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "skip: required tool not installed: $1" >&2
        exit 77
    }
}

need syft
make release >/dev/null
mkdir -p dist
syft bin/modbus-shield \
    -o spdx-json=dist/modbus-shield.spdx.json \
    -o cyclonedx-json=dist/modbus-shield.cdx.json
echo "SBOMs written to dist/modbus-shield.spdx.json + dist/modbus-shield.cdx.json"

[ "$sbom_only" = "1" ] && exit 0

need grype
grype db update
grype dist/modbus-shield.spdx.json --fail-on high
echo "vulnscan: no findings at severity >= high"
