#!/usr/bin/env bash
set -euo pipefail

mkdir -p dist
if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
  echo "cargo-cyclonedx is required: cargo install cargo-cyclonedx --locked" >&2
  exit 1
fi
cargo cyclonedx --format json --override-filename gargoyle.cdx
mv gargoyle.cdx.json dist/gargoyle.cdx.json
