#!/usr/bin/env bash
set -euo pipefail

binary=${1:-./target/release/gargoyle}
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

"$binary" print-default-config > "$tmpdir/gargoyle.toml"
"$binary" validate --config "$tmpdir/gargoyle.toml"
"$binary" print-event-schema | python3 -m json.tool >/dev/null

grep -q 'queue_capacity = 4096' "$tmpdir/gargoyle.toml"
echo "GARGOYLE smoke test passed"
