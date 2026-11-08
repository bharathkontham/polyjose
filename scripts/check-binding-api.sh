#!/usr/bin/env bash
# Checks each binding's exported names against the canonical API inventory (feature 0013 T13;
# ADR 0030 §2, §4, §8), so a renamed, missing or extra operation, record or field fails before any
# conformance run.
#
#   scripts/check-binding-api.sh [<mode>...]
#
# Modes are the files scripts/check-binding-api.d/<mode>.sh, one per binding (surface, js; the
# binding features add node, wasm, kotlin and swift as their own files, without editing this one).
# With no argument every mode runs. Before any mode, two checks of the inventory itself:
#   1. bindings/api-inventory.txt parses (its format is described in its header): known keywords,
#      well-formed names, no duplicates, no field outside a record;
#   2. its code list equals polyjose::Error::CODES, in order (ADR 0030 §5): the quoted strings of
#      the `pub const CODES: &'static [&'static str] = &[ ... ];` block of
#      crates/polyjose/src/error.rs, read as text (the parse bindings/js/tools/gen-error-codes.ts
#      also uses), so no cargo build is needed.
#
# Each mode derives its binding's names in the inventory's normal form, one per line:
#   op <name> | record <Name> | field <Name>.<name>[?|=false] | code <Code>
# The derived set must equal the inventory's, restricted to the kinds the mode checks; codes are
# also compared in order. A name derived twice fails (the bindings are flat namespaces).
#
# Output and exit status. Per mode: `check-binding-api: <mode>: PASS (...)`, or the differences
# and `check-binding-api: <mode>: FAIL`. A mode whose inputs are missing (no source tree, no node)
# prints `SKIPPED (<mode>: <reason>)`, which never counts as passing (pipeline rule 9): run with one
# mode, that is the last line and the exit status is 0, as scripts/test-all.sh expects of a step;
# run with several, a summary line follows. Exit 1 if the inventory or any mode fails, 2 on a usage
# error (unknown mode).
#
# The mode file contract (sourced in a subshell, with this script's helpers):
#   MODE_KINDS="op record field [code]"   the kinds the mode derives and checks
#   mode_derive <out>                      writes the derived lines to <out>; calls `skip <reason>`
#                                          when an input is missing and `mode_fail <message>` when
#                                          the binding cannot be read (a parse that finds nothing,
#                                          a failed build); a derived line `error <message>` fails
#                                          the mode with that message
#   mode_expect (optional)                 a filter from the inventory's lines (stdin) to what this
#                                          binding must show (stdout), for host idiom such as JS
#                                          optional flags
# Helpers: $repo (the repository root), $mode_scratch (an empty directory of the mode's own),
# skip, mode_fail, and the awk function file $camel_awk (`camel("key_use")` = "keyUse").
#
# Runs on macOS /bin/bash 3.2 and Linux bash 5; needs only awk, sed, sort and comm (a mode may need
# more, and skips without it).
set -uo pipefail
export LC_ALL=C

repo=$(cd "$(dirname "$0")/.." && pwd -P) || exit 2
inventory=$repo/bindings/api-inventory.txt
core_error_rs=$repo/crates/polyjose/src/error.rs
modes_dir=$repo/scripts/check-binding-api.d
me=check-binding-api

scratch=$(mktemp -d "${TMPDIR:-/tmp}/check-binding-api.XXXXXX") || { echo "$me: mktemp failed"; exit 2; }
# Fail closed on a syntax error under bash 3.2 (feature 0013 F10; see scripts/test-all.sh).
completed=""
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "check-binding-api.sh: stopped before its last line (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

# snake_case -> camelCase, the conversion napi-rs, UniFFI and the JS facade apply (ADR 0030 §2):
# each "_x" becomes "X" ("max_pbes2_count" -> "maxPbes2Count", "p2s_len" -> "p2sLen").
camel_awk=$scratch/camel.awk
cat >"$camel_awk" <<'AWK'
function camel(s,    parts, n, i, out) {
  n = split(s, parts, "_")
  out = parts[1]
  for (i = 2; i <= n; i++) out = out toupper(substr(parts[i], 1, 1)) substr(parts[i], 2)
  return out
}
AWK

# --- The inventory ---------------------------------------------------------------------------------

# inventory_lines: the inventory in normal form on stdout, or its format errors on stderr (exit 1).
inventory_lines() {
  awk '
    function bad(msg) { printf "%s:%d: %s\n", FILENAME, FNR, msg > "/dev/stderr"; errors++ }
    function once(key) { if (key in seen) { bad("duplicate entry: " key); return 0 } seen[key] = 1; return 1 }
    { sub(/\r$/, ""); line = $0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line) }
    line == "" || line ~ /^#/ { next }
    {
      kind = line; sub(/[ \t].*/, "", kind)
      rest = substr(line, length(kind) + 1); sub(/^[ \t]+/, "", rest)
    }
    kind == "op" {
      if (rest !~ /^[a-z][A-Za-z0-9]*$/) { bad("op needs a camelCase name: " line); next }
      if (once("op " rest)) print "op " rest
      next
    }
    kind == "record" {
      if (rest !~ /^[A-Z][A-Za-z0-9]*$/) { bad("record needs an UpperCamel name: " line); record = ""; next }
      record = rest
      if (once("record " rest)) print "record " rest
      next
    }
    kind == "field" {
      if (record == "") { bad("field outside a record: " line); next }
      suffix = ""
      if (rest ~ /^[a-z][A-Za-z0-9]*\?$/) { suffix = "?"; sub(/\?$/, "", rest) }
      else if (rest ~ /^[a-z][A-Za-z0-9]*[ \t]*=[ \t]*false$/) { suffix = "=false"; sub(/[ \t]*=.*$/, "", rest) }
      else if (rest !~ /^[a-z][A-Za-z0-9]*$/) { bad("field needs a camelCase name, then ? or = false: " line); next }
      if (once("field " record "." rest)) print "field " record "." rest suffix
      next
    }
    kind == "code" {
      if (rest !~ /^[A-Z][A-Za-z0-9]*$/) { bad("code needs an UpperCamel name: " line); next }
      if (once("code " rest)) print "code " rest
      next
    }
    { bad("unknown entry (op, record, field or code): " line) }
    END { exit errors > 0 }
  ' "$inventory"
}

# core_codes: polyjose::Error::CODES in order, one per line (see the header).
core_codes() {
  awk '
    !inside && /pub const CODES: &.static \[&.static str\] = &\[/ { inside = 1; found = 1; sub(/.*= &\[/, "") }
    inside {
      done = sub(/\];.*/, "")
      while (match($0, /"[^"]*"/)) { print substr($0, RSTART + 1, RLENGTH - 2); n++; $0 = substr($0, RSTART + RLENGTH) }
      if (done) exit
    }
    END { exit !(found && n > 0) }
  ' "$core_error_rs"
}

check_inventory() {
  local ok=1
  if [ ! -f "$inventory" ]; then echo "$me: ${inventory#"$repo"/} missing"; return 1; fi
  if ! inventory_lines >"$scratch/inventory" 2>"$scratch/inventory.err"; then
    echo "$me: ${inventory#"$repo"/} is malformed:"; sed "s|^$repo/|  |" "$scratch/inventory.err"; return 1
  fi
  if [ ! -f "$core_error_rs" ]; then echo "$me: ${core_error_rs#"$repo"/} missing"; return 1; fi
  if ! core_codes >"$scratch/core-codes"; then
    echo "$me: no Error::CODES block (pub const CODES: &'static [&'static str] = &[...];) in ${core_error_rs#"$repo"/}"
    return 1
  fi
  sed -n 's/^code //p' "$scratch/inventory" >"$scratch/inventory-codes"
  if ! cmp -s "$scratch/inventory-codes" "$scratch/core-codes"; then
    echo "$me: the inventory's error codes differ from polyjose::Error::CODES (same codes, same order; ADR 0030 §5)"
    echo "  inventory: $(tr '\n' ' ' <"$scratch/inventory-codes")"
    echo "  core:      $(tr '\n' ' ' <"$scratch/core-codes")"
    ok=0
  fi
  [ "$ok" -eq 1 ]
}

# --- Modes -----------------------------------------------------------------------------------------

# shellcheck disable=SC2329 # called by the mode files
skip() { printf '%s\n' "$*" >"$mode_scratch/skip-reason"; exit 77; }
mode_fail() { echo "$me: $mode: $*"; echo "$me: $mode: FAIL"; exit 1; }

# kinds_filter <kinds>: keeps the lines whose kind is in the space-separated list.
kinds_filter() { awk -v kinds="$1" 'BEGIN { n = split(kinds, k, " "); for (i = 1; i <= n; i++) want[k[i]] = 1 } ($1 in want)'; }

# compare <expected> <derived>: prints the differences; returns 1 if there are any.
compare() {
  local expected=$1 derived=$2 diffs=0 line
  sort "$derived" | uniq -d >"$mode_scratch/dups"
  while IFS= read -r line; do echo "  defined twice in $mode: $line"; diffs=1; done <"$mode_scratch/dups"
  grep -v '^code ' "$expected" | sort -u >"$mode_scratch/expected.sorted"
  grep -v '^code ' "$derived" | sort -u >"$mode_scratch/derived.sorted"
  comm -23 "$mode_scratch/expected.sorted" "$mode_scratch/derived.sorted" >"$mode_scratch/missing"
  comm -13 "$mode_scratch/expected.sorted" "$mode_scratch/derived.sorted" >"$mode_scratch/extra"
  while IFS= read -r line; do echo "  missing from $mode (in the inventory): $line"; diffs=1; done <"$mode_scratch/missing"
  while IFS= read -r line; do echo "  extra in $mode (not in the inventory): $line"; diffs=1; done <"$mode_scratch/extra"
  grep '^code ' "$expected" >"$mode_scratch/expected.codes"
  grep '^code ' "$derived" >"$mode_scratch/derived.codes"
  if ! cmp -s "$mode_scratch/expected.codes" "$mode_scratch/derived.codes"; then
    echo "  error codes of $mode differ from the inventory's (same codes, same order):"
    echo "    inventory: $(sed 's/^code //' "$mode_scratch/expected.codes" | tr '\n' ' ')"
    echo "    $mode: $(sed 's/^code //' "$mode_scratch/derived.codes" | tr '\n' ' ')"
    diffs=1
  fi
  [ "$diffs" -eq 0 ]
}

# run_mode <mode>: 0 pass, 1 fail, 77 skipped (the SKIPPED line is printed).
run_mode() {
  mode=$1
  mode_scratch=$scratch/mode-$mode
  mkdir "$mode_scratch" || { echo "$me: $mode: could not create a scratch directory"; return 1; }
  (
    MODE_KINDS=""
    # shellcheck source=/dev/null # the mode files are found at run time
    . "$modes_dir/$mode.sh" || mode_fail "could not source scripts/check-binding-api.d/$mode.sh"
    [ -n "$MODE_KINDS" ] || mode_fail "scripts/check-binding-api.d/$mode.sh sets no MODE_KINDS"
    declare -F mode_derive >/dev/null || mode_fail "scripts/check-binding-api.d/$mode.sh defines no mode_derive"
    mode_derive "$mode_scratch/derived" || mode_fail "mode_derive failed"
    [ -f "$mode_scratch/derived" ] || mode_fail "mode_derive wrote nothing"
    if grep -q '^error ' "$mode_scratch/derived"; then
      sed -n "s/^error /$me: $mode: /p" "$mode_scratch/derived"; echo "$me: $mode: FAIL"; exit 1
    fi
    bad=$(grep -Ev '^(op [a-z][A-Za-z0-9]*|record [A-Z][A-Za-z0-9]*|field [A-Z][A-Za-z0-9]*\.[a-z][A-Za-z0-9]*(\?|=false)?|code [A-Z][A-Za-z0-9]*)$' "$mode_scratch/derived")
    [ -z "$bad" ] || mode_fail "derived lines not in the normal form: $bad"
    kinds_filter "$MODE_KINDS" <"$scratch/inventory" >"$mode_scratch/inventory"
    if declare -F mode_expect >/dev/null; then
      mode_expect <"$mode_scratch/inventory" >"$mode_scratch/expected" || mode_fail "mode_expect failed"
    else
      cp "$mode_scratch/inventory" "$mode_scratch/expected"
    fi
    kinds_filter "$MODE_KINDS" <"$mode_scratch/derived" >"$mode_scratch/derived.kinds"
    if compare "$mode_scratch/expected" "$mode_scratch/derived.kinds"; then
      counts=$(awk '{ n[$1]++ } END { printf "%d operations, %d records, %d fields", n["op"], n["record"], n["field"]; if (n["code"]) printf ", %d codes", n["code"] }' "$mode_scratch/derived.kinds")
      echo "$me: $mode: PASS ($counts)"
    else
      echo "$me: $mode: FAIL (bindings/api-inventory.txt is the 0.1.0 API; changing it is Gate 2, ADR 0030 §8)"
      exit 1
    fi
  )
  rc=$?
  if [ "$rc" -eq 77 ]; then echo "SKIPPED ($mode: $(cat "$mode_scratch/skip-reason"))"; fi
  return "$rc"
}

# --- Main ------------------------------------------------------------------------------------------

modes=("$@")
if [ ${#modes[@]} -eq 0 ]; then
  for f in "$modes_dir"/*.sh; do
    [ -e "$f" ] || continue # bash 3.2 has no nullglob: an unmatched glob stays literal
    f=${f##*/}; modes+=("${f%.sh}")
  done
  [ ${#modes[@]} -gt 0 ] || { echo "$me: no modes in scripts/check-binding-api.d/"; exit 1; }
fi
for m in "${modes[@]}"; do
  case $m in
    *[!a-z0-9-]* | "" | -*) echo "$me: bad mode name: $m"; exit 2 ;;
  esac
  [ -f "$modes_dir/$m.sh" ] || { echo "$me: unknown mode: $m (modes are scripts/check-binding-api.d/<mode>.sh)"; exit 2; }
done

check_inventory || { echo "$me: inventory: FAIL"; exit 1; }

passed=0 failed=0 skipped=""
for m in "${modes[@]}"; do
  run_mode "$m"; rc=$?
  case $rc in
    0) passed=$((passed + 1)) ;;
    77) skipped="$skipped $m" ;;
    *) failed=$((failed + 1)) ;;
  esac
done
if [ ${#modes[@]} -gt 1 ]; then
  echo "$me: $passed passed, $failed failed, skipped:${skipped:- none}"
fi
status=0; [ "$failed" -eq 0 ] || status=1
completed=1; exit "$status"
