#!/usr/bin/env bash
# Tests of bindings/ffi/tests/generated-names.sh (feature 0013 T12): the check passes on the real
# inventory and fails, naming the entry for both languages, on inventory copies that ask for a
# name or a field form the generated Kotlin and Swift do not have.
#
#   bindings/ffi/tests/generated-names-selftest.sh
#
# Each case writes a mutated copy of bindings/api-inventory.txt into a scratch directory (removed
# on exit) and runs the check on it; the repository's inventory is never changed. Runs on macOS
# /bin/bash 3.2 and bash 5.
set -uo pipefail
export LC_ALL=C

here=$(cd "$(dirname "$0")" && pwd -P) || exit 2
check=$here/generated-names.sh
inventory=$here/../../api-inventory.txt
scratch=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-ffi-generated-names-selftest.XXXXXX") || exit 2
# Fail closed on a syntax error under bash 3.2 (feature 0013 F10, F11; see scripts/test-all.sh): with
# errexit, bash 3.2 runs an EXIT trap with $? = 0 after a parse error. This script runs without
# errexit, where bash 3.2 exits 2, and the sentinel keeps it so if errexit is turned on: an exit
# before the last line, which sets the sentinel, becomes status 2; a non-zero status is kept.
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "generated-names-selftest.sh: stopped before its last line (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT
passed=0
failed=0

# expect <name> <exit status> <text the output must contain>... ; runs the check on $scratch/inv.
expect() {
  local name=$1 status=$2 out rc needle ok=1
  shift 2
  out=$(bash "$check" "$scratch/inv" 2>&1)
  rc=$?
  [ "$rc" -eq "$status" ] || { echo "  $name: exit $rc, expected $status"; ok=0; }
  for needle in "$@"; do
    case $out in *"$needle"*) ;; *) echo "  $name: output lacks: $needle"; ok=0 ;; esac
  done
  if [ "$ok" -eq 1 ]; then
    echo "ok   $name"
    passed=$((passed + 1))
  else
    echo "FAIL $name"
    printf '%s\n' "$out" | sed 's/^/    | /'
    failed=$((failed + 1))
  fi
}

# 1. The real inventory passes.
cp "$inventory" "$scratch/inv"
expect "unchanged inventory passes" 0 "kotlin: all" "swift: all" "generated-names: PASS"

# 2. An operation no binding exports.
{ cat "$inventory"; echo "op jwkBogus"; } >"$scratch/inv"
expect "missing operation fails in both languages" 1 \
  "FAIL: kotlin" "FAIL: swift" "  op jwkBogus" "generated-names: FAIL"

# 3. A required allow-list asked for as optional: the generated field has no default, so the form
#    differs (ADR 0030 §3).
awk '/^record JwsVerifyOptions/ { r = 1 } r && /field allowedAlgs$/ { sub(/allowedAlgs$/, "allowedAlgs?"); r = 0 } { print }' \
  "$inventory" >"$scratch/inv"
expect "required field asked as optional fails" 1 \
  "FAIL: kotlin" "FAIL: swift" "  field JwsVerifyOptions.allowedAlgs?"

# 4. A flag asked for as required: the generated field defaults to false.
awk '/^record JwsSignOptions/ { r = 1 } r && /field detached = false$/ { sub(/ = false$/, ""); r = 0 } { print }' \
  "$inventory" >"$scratch/inv"
expect "flag asked as required fails" 1 "  field JwsSignOptions.detached"

# 5. An error code no variant has.
sed 's/^code NoMatchingKey$/code NoMatchingKeyX/' "$inventory" >"$scratch/inv"
expect "missing error code fails" 1 "  code NoMatchingKeyX"

# 6. A field of a record that does not exist.
{ cat "$inventory"; echo "record JwsBogus"; echo "  field alg"; } >"$scratch/inv"
expect "missing record fails" 1 "  record JwsBogus" "  field JwsBogus.alg"

echo "generated-names-selftest: $passed passed, $failed failed"
completed=1; exit "$((failed > 0))"
