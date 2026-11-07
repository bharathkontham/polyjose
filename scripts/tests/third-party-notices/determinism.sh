#!/usr/bin/env bash
# scripts/third-party-notices.sh output is deterministic (ADR 0020 §4): two runs, one of them
# from another working directory, give byte-identical files; LF line endings only; no absolute
# path of this machine, no timestamp; crate sections sorted by name, then version.
set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
export LC_ALL=C

a="$scratch/a.txt"; b="$scratch/b.txt"
run_notices "$a" -p polyjose-node --target aarch64-apple-darwin
rc_a=$rc
(cd "$scratch" && run_notices "$b" -p polyjose-node --target aarch64-apple-darwin)
# run_notices ran in a subshell: read its status from the files instead.
if [ "$rc_a" -ne 0 ] || [ ! -s "$a" ] || [ ! -s "$b" ]; then
  fail "both runs succeed"; show_log; finish; exit
fi
pass "both runs succeed"

if cmp -s "$a" "$b"; then pass "two runs are byte-identical"
else fail "two runs differ"; diff "$a" "$b" | head -20 | sed 's/^/    | /'; fi

if LC_ALL=C grep -q "$(printf '\r')" "$a"; then fail "LF line endings only (found CR)"
else pass "LF line endings only"; fi
if [ "$(tail -c 1 "$a" | od -An -c | tr -d ' ')" = '\n' ]; then pass "ends with a newline"
else fail "ends with a newline"; fi

if grep -qF "$repo" "$a" || grep -qF "$HOME" "$a"; then fail "no absolute local path"
else pass "no absolute local path"; fi
# No timestamp: neither today's date nor a clock time (a crate's own license text may hold a
# year, so years alone are not checked).
today=$(date +%Y-%m-%d)
if grep -qF "$today" "$a" || grep -qE '(^|[^0-9])[0-2][0-9]:[0-5][0-9]:[0-5][0-9]([^0-9]|$)' "$a"; then
  fail "no timestamp"; grep -nE "$today|[0-2][0-9]:[0-5][0-9]:[0-5][0-9]" "$a" | head -5 | sed 's/^/    | /'
else pass "no timestamp"; fi

# The section headings, in file order, are sorted by name and then by version (numerically per
# dot-separated part, as SemVer orders them).
awk -v rule="$rule" 'prev == rule && $0 ~ /^[A-Za-z0-9_-]+ [0-9][^ ]*$/ { print } { prev = $0 }' "$a" \
  >"$scratch/order.txt"
python3 -I - "$scratch/order.txt" <<'EOF' && pass "sections sorted by name, then version" || fail "sections sorted by name, then version"
import re, sys
rows = [l.split(" ") for l in open(sys.argv[1]).read().splitlines()]
def key(row):
    core = re.split(r"[-+]", row[1], maxsplit=1)[0]
    return (row[0], [int(x) for x in core.split(".")], row[1])
sys.exit(0 if len(rows) > 1 and rows == sorted(rows, key=key) else 1)
EOF

finish
