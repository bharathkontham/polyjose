#!/usr/bin/env bash
# The file rules of scripts/conformance-parity.sh (ADR 0034 §2, §4, §5): a missing or malformed
# rust-core.json fails, as does a reference built with features; rust-core-<suffix>.json is
# ignored; <runner>-<suffix>.json is compared like <runner>; a file naming no runner, a runner
# member that disagrees with the file name, a schema-invalid or unparseable file and a repeated
# id fail; and a usage or tool error exits 2.
# Usage: scripts/tests/conformance-parity/parity-files.sh
# Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
export LC_ALL=C
# shellcheck source=scripts/tests/conformance-parity/lib.sh
. "$(dirname "$0")/lib.sh"

# A missing reference fails, with binding files present or none at all, and so does a missing
# directory.
new_case no-reference
put node.json "$(as_runner node)"
expect_fail "no rust-core.json, a binding file present" '^FAIL: rust-core\.json: missing' '^FAIL: rust-core\.json: missing'
new_case empty
expect_fail "an empty directory" '^FAIL: rust-core\.json: missing' '^FAIL: rust-core\.json: missing'
new_case gone
rmdir "$case_dir"
expect_fail "a missing directory" '^FAIL: rust-core\.json: missing' '^FAIL: rust-core\.json: missing'

# The reference must be the default-features build (ADR 0034 §4).
new_case reference-features
put rust-core.json "$(edit "$REFERENCE" '"features":[]' '"features":["deflate"]')"
expect_fail "a reference built with features" '^FAIL: rust-core\.json: built with features \["deflate"\]' \
  '^FAIL: rust-core\.json: built with features'

# A Rust build with features is not the reference, and is ignored even when it differs.
new_case ignored
put rust-core.json "$REFERENCE"
put rust-core-deflate-fixed-rng.json "$(edit "$REFERENCE" '"features":[]' '"features":["deflate","fixed-rng"]' |
  sed 's/"status":"skipped","reason":"feature:[a-z-]*"/"status":"pass","actual":{"ok":true}/g')"
put rust-core-broken.json '{'
expect_pass "rust-core-<suffix>.json is ignored" \
  '^IGNORED: rust-core-deflate-fixed-rng\.json ' '^IGNORED: rust-core-broken\.json '

# A matrix suffix is compared like its runner: a difference fails; the longest runner name wins
# (wasm-pkg-node-..., not node).
new_case suffix-compared
put rust-core.json "$REFERENCE"
put node-x86_64-unknown-linux-musl.json "$(edit "$(as_runner node)" '"error":"InvalidBase64"' '"error":"InvalidKey"')"
expect_fail "<runner>-<suffix>.json is compared" \
  '^FAIL: node-x86_64-unknown-linux-musl\.json: b64url/decode-reject\.json#0: rust-core pass .* \| node pass ' \
  '^FAIL: node-x86_64-unknown-linux-musl\.json: b64url/decode-reject\.json#0: '
new_case suffix-longest
put rust-core.json "$REFERENCE"
put wasm-pkg-node-linux.json "$(as_runner wasm-pkg-node)"
expect_pass "the longest runner name matches" '^PASS: wasm-pkg-node-linux\.json \(wasm-pkg-node, ' \
  '^SKIPPED \(no results: node\)$'

# A file naming no runner, or whose runner member is another runner's, fails.
new_case unknown-runner
put rust-core.json "$REFERENCE"
put nodejs.json "$(as_runner node)"
expect_fail "a file naming no runner" '^FAIL: nodejs\.json: names no runner' '^FAIL: nodejs\.json: names no runner'
new_case runner-mismatch
put rust-core.json "$REFERENCE"
put node.json "$(as_runner jvm)"
expect_fail "runner disagrees with the file name" '^FAIL: node\.json: runner is "jvm"' '^FAIL: node\.json: runner is "jvm"'
new_case suffix-in-runner
put rust-core.json "$REFERENCE"
put node-linux.json "$(as_runner node-linux)"
expect_fail "a suffix in the runner member" '^FAIL: node-linux\.json: not valid per .*/runner: must be one of' \
  '^FAIL: node-linux\.json: not valid per '

# Malformed files fail, each named: not JSON, schema-invalid (a pass without actual, an unknown
# member, an id without #0), a repeated id; the reference too.
new_case not-json
put rust-core.json "$REFERENCE"
put jvm.json '{"runner":'
expect_fail "a binding file that is not JSON" '^FAIL: jvm\.json: not readable as JSON' '^FAIL: jvm\.json: not readable as JSON'
new_case pass-without-actual
put rust-core.json "$REFERENCE"
put jvm.json "$(edit "$(as_runner jvm)" '"status":"pass","actual":{"ok":true}}' '"status":"pass"}')"
expect_fail "a pass without actual" '^FAIL: jvm\.json: not valid per .*/results/0: must match exactly one oneOf branch' \
  '^FAIL: jvm\.json: not valid per '
new_case unknown-member
put rust-core.json "$REFERENCE"
put jvm.json "$(edit "$(as_runner jvm)" '"polyjose":"0.1.0"' '"polyjose":"0.1.0","target":"x"')"
expect_fail "an unknown member" '^FAIL: jvm\.json: not valid per .*: unknown member target' '^FAIL: jvm\.json: not valid per '
new_case bad-id
put rust-core.json "$REFERENCE"
put jvm.json "$(edit "$(as_runner jvm)" '"b64url/encode.json#0"' '"b64url/encode.json#3"')"
expect_fail "an id other than <path>#0" '^FAIL: jvm\.json: not valid per .*/results/0' '^FAIL: jvm\.json: not valid per '
new_case repeated-id
put rust-core.json "$REFERENCE"
put jvm.json "$(edit "$(as_runner jvm)" '"results":[' \
  '"results":[{"id":"b64url/encode.json#0","op":"b64url.encode","status":"pass","actual":{"ok":true}},')"
expect_fail "a repeated id" '^FAIL: jvm\.json: b64url/encode\.json#0: listed twice' '^FAIL: jvm\.json: b64url/encode\.json#0: listed twice'
new_case reference-invalid
put rust-core.json "$(edit "$REFERENCE" '"error_codes":["InvalidBase64","InvalidKey","DecryptionFailed"]' '"error_codes":[]')"
put node.json "$(as_runner node)"
expect_fail "a schema-invalid reference" '^FAIL: rust-core\.json: not valid per .*/error_codes' '^FAIL: rust-core\.json: not valid per '

# Usage and tool errors exit 2: two arguments; no node on PATH.
tests_run=$((tests_run + 1))
rc=0
"$parity" "$scratch" "$scratch" >"$scratch/out" 2>&1 || rc=$?
if [ "$rc" -eq 2 ] && grep -q '^ERROR: usage' "$scratch/out"; then echo "ok   - two arguments: exit 2"
else echo "FAIL - two arguments: exit $rc (expected 2)"; sed 's/^/       /' "$scratch/out"; tests_failed=$((tests_failed + 1)); fi
tests_run=$((tests_run + 1))
mkdir -p "$scratch/bin"
ln -s "$(command -v dirname)" "$scratch/bin/dirname"
rc=0
PATH="$scratch/bin" "$BASH" "$parity" "$scratch" >"$scratch/out" 2>&1 || rc=$?
if [ "$rc" -eq 2 ] && grep -q '^ERROR: node not found' "$scratch/out"; then echo "ok   - no node: exit 2"
else echo "FAIL - no node: exit $rc (expected 2)"; sed 's/^/       /' "$scratch/out"; tests_failed=$((tests_failed + 1)); fi

finish
