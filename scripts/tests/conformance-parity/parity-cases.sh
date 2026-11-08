#!/usr/bin/env bash
# The parity rules of scripts/conformance-parity.sh (ADR 0034 §5, §8; feature 0013 T02 cases a-g):
# identical files pass; a missing id, a different error code, a different skip reason, a `fail`
# entry or a different error_codes list fails, printing the id (or list) and both outcomes; and
# a directory with only the reference passes with a SKIPPED line per runner. The ADR 0056 skip
# reason feature:!<name> (cases h) is compared like any other. ADR 0060 §6 (cases j-l): a different
# vectors_digest fails, printing both; the empty-input digest fails in any file; the member is
# required and must be 64 lowercase hex characters.
# Usage: scripts/tests/conformance-parity/parity-cases.sh
# Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
export LC_ALL=C
# shellcheck source=scripts/tests/conformance-parity/lib.sh
. "$(dirname "$0")/lib.sh"

# (a) Identical results, also under a CI matrix suffix (ADR 0034 §2), pass.
new_case identical
put rust-core.json "$REFERENCE"
put node.json "$(as_runner node)"
put jvm-linux-x86-64.json "$(as_runner jvm)"
put swift-ios-sim.json "$(as_runner swift-ios-sim)"
expect_pass "(a) identical files" \
  '^PASS: node\.json \(node, ' '^PASS: jvm-linux-x86-64\.json \(jvm, ' '^PASS: swift-ios-sim\.json ' \
  '^conformance parity: OK \(3 file'

# (b) An id the reference has and a binding lacks.
new_case missing-id
put rust-core.json "$REFERENCE"
put node.json "$(edit "$(as_runner node)" \
  '{"id":"b64url/decode-reject.json#0","op":"b64url.decode","status":"pass","actual":{"ok":false,"error":"InvalidBase64"}},' '')"
expect_fail "(b) an id missing in a binding" \
  '^FAIL: node\.json: b64url/decode-reject\.json#0: rust-core pass \{"ok":false,"error":"InvalidBase64"\} \| node \(missing\)$' \
  '^FAIL: node\.json: b64url/decode-reject\.json#0: '

# (b') And the converse: an id only the binding has.
new_case extra-id
put rust-core.json "$REFERENCE"
put node.json "$(edit "$(as_runner node)" '"results":[' \
  '"results":[{"id":"extra/new.json#0","op":"b64url.encode","status":"pass","actual":{"ok":true}},')"
expect_fail "(b') an id only a binding has" \
  '^FAIL: node\.json: extra/new\.json#0: rust-core \(missing\) \| node pass \{"ok":true\}$' \
  '^FAIL: node\.json: extra/new\.json#0: '

# (c) The same `ok: false`, with another error code.
new_case error-code
put rust-core.json "$REFERENCE"
put wasm-node.json "$(edit "$(as_runner wasm-node)" '"error":"InvalidBase64"' '"error":"InvalidKey"')"
expect_fail "(c) a different error code" \
  '^FAIL: wasm-node\.json: b64url/decode-reject\.json#0: rust-core pass \{"ok":false,"error":"InvalidBase64"\} \| wasm-node pass \{"ok":false,"error":"InvalidKey"\}$' \
  '^FAIL: wasm-node\.json: b64url/decode-reject\.json#0: '

# (c') A success where the reference has a failure.
new_case ok-differs
put rust-core.json "$REFERENCE"
put wasm-node.json "$(edit "$(as_runner wasm-node)" '"actual":{"ok":false,"error":"InvalidBase64"}' '"actual":{"ok":true}')"
expect_fail "(c') ok true where the reference has ok false" \
  '^FAIL: wasm-node\.json: b64url/decode-reject\.json#0: rust-core pass \{"ok":false,"error":"InvalidBase64"\} \| wasm-node pass \{"ok":true\}$' \
  '^FAIL: wasm-node\.json: b64url/decode-reject\.json#0: '

# (d) A skip with another reason.
new_case skip-reason
put rust-core.json "$REFERENCE"
put jvm.json "$(edit "$(as_runner jvm)" '"reason":"feature:deflate"' '"reason":"feature:deflate,fixed-rng"')"
expect_fail "(d) a skip with a different reason" \
  '^FAIL: jvm\.json: jwe/zip/decrypt\.json#0: rust-core skipped feature:deflate \| jvm skipped feature:deflate,fixed-rng$' \
  '^FAIL: jvm\.json: jwe/zip/decrypt\.json#0: '

# (d') A binding that runs what the reference skips (a binding built with deflate).
new_case skip-ran
put rust-core.json "$REFERENCE"
put jvm.json "$(edit "$(as_runner jvm)" '"status":"skipped","reason":"feature:deflate"' '"status":"pass","actual":{"ok":true}')"
expect_fail "(d') a binding runs a vector the reference skips" \
  '^FAIL: jvm\.json: jwe/zip/decrypt\.json#0: rust-core skipped feature:deflate \| jvm pass \{"ok":true\}$' \
  '^FAIL: jvm\.json: jwe/zip/decrypt\.json#0: '

# (e) A `fail` entry fails the check, even with the reference's outcome.
new_case fail-status
put rust-core.json "$REFERENCE"
put android-emulator.json "$(edit "$(as_runner android-emulator)" \
  '"status":"pass","actual":{"ok":true}}' '"status":"fail","actual":{"ok":true},"reason":"round trip: does not verify"}')"
expect_fail "(e) a fail status in a binding" \
  '^FAIL: android-emulator\.json: b64url/encode\.json#0: fail \{"ok":true\} \(reason: round trip: does not verify\)$' \
  '^FAIL: android-emulator\.json: b64url/encode\.json#0: fail '

# (e') A `fail` with no outcome (an unmapped operation, ADR 0034 §3) fails too.
new_case fail-unmapped
put rust-core.json "$REFERENCE"
put android-emulator.json "$(edit "$(as_runner android-emulator)" \
  '"status":"pass","actual":{"ok":true}}' '"status":"fail","reason":"operation b64url.encode is not mapped"}')"
expect_fail "(e') a fail without an outcome" \
  '^FAIL: android-emulator\.json: b64url/encode\.json#0: fail \(no outcome\) \(reason: operation b64url\.encode is not mapped\)$' \
  '^FAIL: android-emulator\.json: b64url/encode\.json#0: fail '

# (e'') A `fail` in the reference itself fails the check.
new_case reference-fail
put rust-core.json "$(edit "$REFERENCE" '"status":"pass","actual":{"ok":true}}' \
  '"status":"fail","actual":{"ok":true},"reason":"expected nothing, got b64u"}')"
expect_fail "(e'') a fail status in the reference" \
  '^FAIL: rust-core\.json: b64url/encode\.json#0: fail ' '^FAIL: rust-core\.json: b64url/encode\.json#0: fail '

# (f) Another error-code list: a code missing, or the same codes in another order (ADR 0034 §8).
new_case codes-missing
put rust-core.json "$REFERENCE"
put swift-macos.json "$(edit "$(as_runner swift-macos)" ',"DecryptionFailed"]' ']')"
expect_fail "(f) an error code missing from error_codes" \
  '^FAIL: swift-macos\.json: error_codes differ: rust-core \["InvalidBase64","InvalidKey","DecryptionFailed"\] \| swift-macos \["InvalidBase64","InvalidKey"\]$' \
  '^FAIL: swift-macos\.json: error_codes differ: '
new_case codes-order
put rust-core.json "$REFERENCE"
put swift-macos.json "$(edit "$(as_runner swift-macos)" '"InvalidBase64","InvalidKey"' '"InvalidKey","InvalidBase64"')"
expect_fail "(f') error_codes in another order" \
  '^FAIL: swift-macos\.json: error_codes differ: ' '^FAIL: swift-macos\.json: error_codes differ: '

# (i) Another polyjose version (review N1): a stale prebuild with every result equal still fails,
# printing both versions; a CI matrix file is compared the same way.
new_case version-differs
put rust-core.json "$REFERENCE"
put node.json "$(edit "$(as_runner node)" '"polyjose":"0.1.0"' '"polyjose":"0.0.9"')"
put jvm-linux-x86-64.json "$(as_runner jvm)"
expect_fail "(i) a different polyjose version" \
  '^FAIL: node\.json: polyjose version differs: rust-core 0\.1\.0 \| node 0\.0\.9$' \
  '^FAIL: node\.json: polyjose version differs: '
grep -q '^PASS: jvm-linux-x86-64\.json ' "$scratch/out" || {
  echo "FAIL - (i): the file with the reference's version does not pass"; tests_failed=$((tests_failed + 1))
}
new_case version-matrix
put rust-core.json "$REFERENCE"
put node-x86_64-unknown-linux-musl.json "$(edit "$(as_runner node)" '"polyjose":"0.1.0"' '"polyjose":"0.2.0-rc.1"')"
expect_fail "(i') a different polyjose version under a CI matrix suffix" \
  '^FAIL: node-x86_64-unknown-linux-musl\.json: polyjose version differs: rust-core 0\.1\.0 \| node 0\.2\.0-rc\.1$' \
  '^FAIL: node-x86_64-unknown-linux-musl\.json: polyjose version differs: '

# (j) ADR 0060 §6: a file from another vector corpus (a stale artifact, a drifted bundle) fails
# even with every id, status and outcome equal, printing both digests; the version check (i) and
# this one are made together, so a file can fail on both.
OTHER_DIGEST=ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356
new_case digest-differs
put rust-core.json "$REFERENCE"
put node.json "$(edit "$(as_runner node)" "\"vectors_digest\":\"$DIGEST\"" "\"vectors_digest\":\"$OTHER_DIGEST\"")"
put jvm-linux-x86-64.json "$(as_runner jvm)"
expect_fail "(j) a different vectors_digest" \
  "^FAIL: node\\.json: vectors_digest differs: rust-core $DIGEST \\| node $OTHER_DIGEST\$" \
  '^FAIL: node\.json: vectors_digest differs: '
grep -q '^PASS: jvm-linux-x86-64\.json ' "$scratch/out" || {
  echo "FAIL - (j): the file with the reference's digest does not pass"; tests_failed=$((tests_failed + 1))
}
new_case digest-matrix
put rust-core.json "$REFERENCE"
put swift-ios-sim-iphone.json "$(edit "$(as_runner swift-ios-sim)" "\"vectors_digest\":\"$DIGEST\"" "\"vectors_digest\":\"$OTHER_DIGEST\"")"
expect_fail "(j') a different vectors_digest under a CI matrix suffix" \
  "^FAIL: swift-ios-sim-iphone\\.json: vectors_digest differs: rust-core $DIGEST \\| swift-ios-sim $OTHER_DIGEST\$" \
  '^FAIL: swift-ios-sim-iphone\.json: vectors_digest differs: '
new_case digest-and-version
put rust-core.json "$REFERENCE"
put node.json "$(edit "$(edit "$(as_runner node)" '"polyjose":"0.1.0"' '"polyjose":"0.0.9"')" \
  "\"vectors_digest\":\"$DIGEST\"" "\"vectors_digest\":\"$OTHER_DIGEST\"")"
expect_fail "(j'') a different version and digest: both reported" \
  '^FAIL: node\.json: polyjose version differs: rust-core 0\.1\.0 \| node 0\.0\.9$' \
  '^FAIL: node\.json: (polyjose version|vectors_digest) differs: '
grep -q "^FAIL: node\\.json: vectors_digest differs: rust-core $DIGEST | node $OTHER_DIGEST\$" "$scratch/out" || {
  echo "FAIL - (j''): the digest difference is not reported next to the version one"; tests_failed=$((tests_failed + 1))
}

# (k) The SHA-256 of the empty input (a runner that read no vector file) fails in any file, the
# reference included (ADR 0060 §3, §6.2).
EMPTY_DIGEST=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
new_case empty-digest-binding
put rust-core.json "$REFERENCE"
put node.json "$(edit "$(as_runner node)" "\"vectors_digest\":\"$DIGEST\"" "\"vectors_digest\":\"$EMPTY_DIGEST\"")"
expect_fail "(k) the empty-input digest in a binding" \
  "^FAIL: node\\.json: vectors_digest is $EMPTY_DIGEST, the SHA-256 of the empty input " \
  '^FAIL: node\.json: vectors_digest is '
new_case empty-digest-reference
put rust-core.json "$(edit "$REFERENCE" "\"vectors_digest\":\"$DIGEST\"" "\"vectors_digest\":\"$EMPTY_DIGEST\"")"
put node.json "$(edit "$(as_runner node)" "\"vectors_digest\":\"$DIGEST\"" "\"vectors_digest\":\"$EMPTY_DIGEST\"")"
expect_fail "(k') the empty-input digest in the reference (and an equal binding)" \
  "^FAIL: rust-core\\.json: vectors_digest is $EMPTY_DIGEST, the SHA-256 of the empty input " \
  '^FAIL: (rust-core|node)\.json: vectors_digest is '
grep -q '^PASS: ' "$scratch/out" && {
  echo "FAIL - (k'): a file passed against an empty-corpus reference"; tests_failed=$((tests_failed + 1))
}

# (l) vectors_digest is required and must be 64 lowercase hex characters (ADR 0060 §1, §6.1), in
# the reference too.
new_case digest-missing
put rust-core.json "$REFERENCE"
put node.json "$(edit "$(as_runner node)" "\"vectors_digest\":\"$DIGEST\"," '')"
expect_fail "(l) a binding file without vectors_digest" \
  '^FAIL: node\.json: not valid per .*: missing required member vectors_digest' '^FAIL: node\.json: not valid per '
new_case digest-missing-reference
put rust-core.json "$(edit "$REFERENCE" "\"vectors_digest\":\"$DIGEST\"," '')"
put node.json "$(as_runner node)"
expect_fail "(l') a reference without vectors_digest" \
  '^FAIL: rust-core\.json: not valid per .*: missing required member vectors_digest' '^FAIL: rust-core\.json: not valid per '
upper=$(printf '%s' "$DIGEST" | tr 'a-f' 'A-F')
for bad in "$upper" "${DIGEST}0" "${DIGEST%?}" "sha256:$DIGEST" ""; do
  new_case "digest-malformed-${#bad}"
  put rust-core.json "$REFERENCE"
  put node.json "$(edit "$(as_runner node)" "\"vectors_digest\":\"$DIGEST\"" "\"vectors_digest\":\"$bad\"")"
  expect_fail "(l'') a malformed vectors_digest ${bad:-(empty string)}" \
    '^FAIL: node\.json: not valid per .*/vectors_digest: .* must match \^\[0-9a-f\]\{64\}\$' '^FAIL: node\.json: not valid per '
done

# (h) ADR 0056: a reference with a features_absent skip (feature:!deflate, as an --all-features
# build would give) and a skip of both kinds; an identical binding passes.
ABSENT_REFERENCE=$(edit "$REFERENCE" '"reason":"feature:fixed-rng"}' \
  '"reason":"feature:fixed-rng"},
{"id":"binding-surface/zip-off.json#0","op":"jwe.decrypt","status":"skipped","reason":"feature:!deflate"},
{"id":"binding-surface/mixed.json#0","op":"jwe.encrypt","status":"skipped","reason":"feature:fixed-rng,!deflate"}')
new_case absent-identical
put rust-core.json "$ABSENT_REFERENCE"
put node.json "$(as_runner node "$ABSENT_REFERENCE")"
expect_pass "(h) identical feature:!<name> skips" '^PASS: node\.json \(node, ' '^conformance parity: OK \(1 file'

# (h') The plain reason where the reference has the mirror one.
new_case absent-reason
put rust-core.json "$ABSENT_REFERENCE"
put node.json "$(edit "$(as_runner node "$ABSENT_REFERENCE")" '"reason":"feature:!deflate"' '"reason":"feature:deflate"')"
expect_fail "(h') feature:deflate where the reference has feature:!deflate" \
  '^FAIL: node\.json: binding-surface/zip-off\.json#0: rust-core skipped feature:!deflate \| node skipped feature:deflate$' \
  '^FAIL: node\.json: binding-surface/zip-off\.json#0: '

# (h'') A binding that runs what the reference skips with feature:!deflate.
new_case absent-ran
put rust-core.json "$ABSENT_REFERENCE"
put node.json "$(edit "$(as_runner node "$ABSENT_REFERENCE")" \
  '"status":"skipped","reason":"feature:!deflate"' '"status":"pass","actual":{"ok":false,"error":"UnsupportedAlgorithm"}')"
expect_fail "(h'') a binding runs a vector the reference skips with feature:!deflate" \
  '^FAIL: node\.json: binding-surface/zip-off\.json#0: rust-core skipped feature:!deflate \| node pass \{"ok":false,"error":"UnsupportedAlgorithm"\}$' \
  '^FAIL: node\.json: binding-surface/zip-off\.json#0: '

# (h''') A malformed mirror reason is not a valid results file.
new_case absent-malformed
put rust-core.json "$ABSENT_REFERENCE"
put node.json "$(edit "$(as_runner node "$ABSENT_REFERENCE")" '"reason":"feature:!deflate"' '"reason":"feature:deflate!"')"
expect_fail "(h''') a malformed feature:!<name> reason" \
  '^FAIL: node\.json: not valid per ' '^FAIL: node\.json: not valid per '

# (g) No binding files: passes, with one SKIPPED line per runner other than the reference.
new_case no-bindings
put rust-core.json "$REFERENCE"
skipped_patterns=()
count=0
while IFS= read -r runner; do
  [ "$runner" = rust-core ] && continue
  skipped_patterns+=("^SKIPPED \\(no results: $runner\\)\$")
  count=$((count + 1))
done < <(runner_names)
[ "$count" -eq 12 ] || lib_die "expected 12 runners besides rust-core in the schema, found $count"
expect_pass "(g) no binding files" "${skipped_patterns[@]}" '^conformance parity: OK \(0 file\(s\) equal to rust-core; 12 runner\(s\) SKIPPED\)$'
if grep -q '^SKIPPED (no results: rust-core)' "$scratch/out"; then
  echo "FAIL - (g): the reference is listed as SKIPPED"; tests_failed=$((tests_failed + 1))
fi

finish
