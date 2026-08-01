#!/usr/bin/env bash
set -euo pipefail

binary=${1:-./target/release/gargoyle}
duration=${GARGOYLE_BENCHMARK_SECONDS:-60}
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

"$binary" print-default-config > "$tmpdir/gargoyle.toml"
python3 - "$tmpdir/gargoyle.toml" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
text = text.replace('stdout = true', 'stdout = false', 1)
text = text.replace('flush_each_event = true', 'file = "' + str(path.parent / 'events.jsonl') + '"\nflush_each_event = false', 1)
path.write_text(text)
PY

set +e
/usr/bin/time -v timeout --signal=INT --kill-after=10 "${duration}s" \
    "$binary" run --config "$tmpdir/gargoyle.toml" \
    >"$tmpdir/stdout.log" 2>"$tmpdir/time.log"
status=$?
set -e
if [[ $status -ne 0 && $status -ne 124 && $status -ne 130 ]]; then
    cat "$tmpdir/time.log" >&2
    exit "$status"
fi

cat "$tmpdir/time.log"
printf 'events_bytes=%s\n' "$(stat -c %s "$tmpdir/events.jsonl" 2>/dev/null || echo 0)"
