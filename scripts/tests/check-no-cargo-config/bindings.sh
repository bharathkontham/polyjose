#!/usr/bin/env bash
# Negative test of rule 2 of scripts/check-no-cargo-config.sh for bindings/** (feature 0006 F06,
# security audit L2): Cargo configuration passed on a command line (`--config`, `-Z`), a CARGO_* or
# RUST* variable assignment, or a `.cargo/config` write in any file under bindings/ fails, as under
# scripts/ and .github/. The one exception is ADR 0059's line in bindings/wasm/scripts/build-package.sh,
# allowed by path and exact text, once; `WASM_CARGO_ARGS` may be read but not assigned anywhere
# else under bindings/, so that line is the whole of the shipped build's extra Cargo arguments
# (which scripts/check-rsa-symbols.sh reads too).
#
# Must pass:
#   1. the unchanged tree, which holds the ADR 0059 line;
#   2. look-alikes under bindings/: a comment line with `--config`, a `[A-Z]` regex, an `env!` of
#      CARGO_MANIFEST_DIR and a read of `${WASM_CARGO_ARGS[@]}` and `${#WASM_CARGO_ARGS[@]}`.
# Must fail, on rule 2 only, naming the file and line:
#   3. the audit's plant: the ADR 0059 line plus a `build.rustflags` --cfg and a `[patch]`;
#   4. the ADR 0059 line with another value (opt-level "s"), and emptied (`WASM_CARGO_ARGS=()`);
#   5. the exact ADR 0059 line a second time in build-package.sh, and once in another file;
#   6. `WASM_CARGO_ARGS+=(...)` after it, with no Cargo flag;
#   7. `--config` on another command line in a bindings script;
#   8. `-Z` (attached and separate) in a bindings script, and `-Z` in a scripts/ file;
#   9. a RUSTFLAGS prefix assignment, an exported CARGO_TARGET_<triple>_RUSTFLAGS, a
#      `RUSTFLAGS:` key in a TypeScript file, and a `.cargo/config.toml` write, under bindings/.
#
# The planted flags and variable names are assembled from pieces below, because this file is under
# scripts/, which the gate scans: its own text must hold none of them.
# Usage: scripts/tests/check-no-cargo-config/bindings.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=../check-deps/lib.sh
. "$(dirname "$0")/../check-deps/lib.sh"

# Fail closed on a syntax error under bash 3.2 (feature 0013 F10; see scripts/test-all.sh): the
# EXIT trap of check-deps/lib.sh again, with the sentinel, which the last line sets.
completed=""
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "${0##*/}: stopped before its last line (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

gate_name=check-no-cargo-config.sh
run_gate() { scripts/check-no-cargo-config.sh; }

# cargo's config flag and its unstable-flag option, in two pieces each.
cfg="-""-config"
zf="-""Z"
rf="RUST""FLAGS"
dotcargo=".car""go"
build_package=bindings/wasm/scripts/build-package.sh
adr0059_line="WASM_CARGO_ARGS=($cfg 'profile.release.opt-level=\"z\"')"
rule2='^FAIL: scripts, workflows or bindings set cargo configuration'

# edit_in <path in the copy> <old> <new>: replaces the one occurrence of <old> (no relock: only
# text the gate reads changes).
edit_in() {
  python3 -I -c '
import sys
path, old, new = sys.argv[1:4]
with open(path, encoding="utf-8") as f:
    text = f.read()
if text.count(old) != 1:
    sys.exit("expected exactly one %r in %s" % (old, path))
with open(path, "w", encoding="utf-8") as f:
    f.write(text.replace(old, new))
' "$case_dir/$1" "$2" "$3" || lib_die "could not edit $1 in the copy"
}

# expect_also <description> <ERE>: the output of the last expect_pass/expect_fail also matches.
expect_also() {
  tests_run=$((tests_run + 1))
  if grep -Eq -- "$2" "$scratch/out"; then
    echo "ok   - $1"
  else
    echo "FAIL - $1: wanted output matching /$2/"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

# The ADR 0059 line is in the tree as this test expects it, or every case below tests nothing.
tests_run=$((tests_run + 1))
if [ "$(grep -cFx -- "$adr0059_line" "$repo/$build_package" || true)" = 1 ]; then
  echo "ok   - $build_package holds the ADR 0059 line once"
else
  echo "FAIL - $build_package does not hold the ADR 0059 line exactly once: $adr0059_line"
  tests_failed=$((tests_failed + 1))
fi

# --- Must pass ------------------------------------------------------------------------------------

new_case unchanged
expect_pass "the unchanged tree (the ADR 0059 line in $build_package)"
expect_also "rule 2 says it read bindings/" '^ok: no script, workflow or binding '

new_case look-alikes
append_to bindings/wasm/test.sh "# a comment may name cargo $cfg 'profile.release.opt-level=\"s\"' and $zf build-std
n=\${#WASM_CARGO_ARGS[@]}; args=(\"\${WASM_CARGO_ARGS[@]}\"); echo \"\$n \${args[*]}\""
append_to bindings/wasm/test-pkg/src/f06-look-alike.ts 'export const upper = /[A-Z]+/; // [a-zA-Z0-9_-Z]'
append_to bindings/wasm/src/f06_look_alike.rs 'pub const DIR: &str = env!("CARGO_MANIFEST_DIR");'
expect_pass "comments, regexes, env!(CARGO_MANIFEST_DIR) and reads of WASM_CARGO_ARGS under bindings/"

# --- Must fail ------------------------------------------------------------------------------------

new_case audit-plant
edit_in "$build_package" "$adr0059_line" \
  "WASM_CARGO_ARGS=($cfg 'profile.release.opt-level=\"z\"' $cfg 'build.rustflags=[\"--cfg\",\"polyjose_audit\"]' $cfg 'patch.crates-io.aes.path=\"/tmp/evil-aes\"')"
expect_fail "the audit's plant (rustflags --cfg and a [patch] added to the ADR 0059 line)" \
  "^  - bindings/wasm/scripts/build-package\\.sh:[0-9]+: WASM_CARGO_ARGS=\\(.*polyjose_audit" "$rule2"

new_case other-value
edit_in "$build_package" "$adr0059_line" "WASM_CARGO_ARGS=($cfg 'profile.release.opt-level=\"s\"')"
expect_fail "the ADR 0059 line with opt-level \"s\"" \
  "^  - bindings/wasm/scripts/build-package\\.sh:[0-9]+: WASM_CARGO_ARGS=\\(.*opt-level=\"s\"" "$rule2"

new_case emptied
edit_in "$build_package" "$adr0059_line" "WASM_CARGO_ARGS=()"
expect_fail "the ADR 0059 line emptied" \
  '^  - bindings/wasm/scripts/build-package\.sh:[0-9]+: WASM_CARGO_ARGS=\(\)$' "$rule2"

new_case twice
edit_in "$build_package" "$adr0059_line" "$adr0059_line
$adr0059_line"
expect_fail "the ADR 0059 line twice in $build_package" \
  "^  - bindings/wasm/scripts/build-package\\.sh:[0-9]+: WASM_CARGO_ARGS=\\($cfg 'profile" "$rule2"

new_case other-file
append_to bindings/node/scripts/f06.sh "$adr0059_line"
expect_fail "the exact ADR 0059 line in another file" \
  "^  - bindings/node/scripts/f06\\.sh:1: WASM_CARGO_ARGS=" "$rule2"

new_case appended
edit_in "$build_package" "$adr0059_line" "$adr0059_line
WASM_CARGO_ARGS+=(--locked)"
expect_fail "WASM_CARGO_ARGS+=(...) after the ADR 0059 line" \
  '^  - bindings/wasm/scripts/build-package\.sh:[0-9]+: WASM_CARGO_ARGS\+=\(--locked\)$' "$rule2"

new_case config-elsewhere
append_to bindings/wasm/test.sh "cargo build $cfg 'build.rustc-wrapper=\"/tmp/wrap\"' -p polyjose-wasm"
expect_fail "$cfg on another command line in bindings/wasm/test.sh" \
  "^  - bindings/wasm/test\\.sh:[0-9]+: cargo build $cfg " "$rule2"

new_case z-attached
append_to bindings/wasm/test.sh "cargo ${zf}build-std build --target wasm32-unknown-unknown"
expect_fail "${zf}build-std in bindings/wasm/test.sh" "^  - bindings/wasm/test\\.sh:[0-9]+: cargo ${zf}build-std" "$rule2"

new_case z-separate
append_to bindings/wasm/test.sh "wasm-pack build -- $zf build-std"
expect_fail "$zf build-std in bindings/wasm/test.sh" "^  - bindings/wasm/test\\.sh:[0-9]+: wasm-pack build -- $zf " "$rule2"

new_case z-scripts
append_to scripts/conformance-parity.sh "cargo +nightly test ${zf}unstable-options"
expect_fail "${zf}unstable-options in a scripts/ file" "^  - scripts/conformance-parity\\.sh:[0-9]+: cargo " "$rule2"

new_case rustflags-prefix
append_to bindings/wasm/test.sh "$rf='--cfg getrandom_backend=\"custom\"' wasm-pack test --node"
expect_fail "a $rf prefix assignment in bindings/wasm/test.sh" "^  - bindings/wasm/test\\.sh:[0-9]+: $rf=" "$rule2"

new_case target-rustflags
append_to bindings/wasm/test-pkg/run.sh "export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_$rf=--cfg"
expect_fail "an exported CARGO_TARGET_<triple>_$rf in bindings/wasm/test-pkg/run.sh" \
  "^  - bindings/wasm/test-pkg/run\\.sh:[0-9]+: export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_$rf=" "$rule2"

new_case ts-env-key
append_to bindings/wasm/test-pkg/src/f06-env.ts "export const env = { $rf: \"--cfg x\" };"
expect_fail "a $rf: key in a TypeScript file" "^  - bindings/wasm/test-pkg/src/f06-env\\.ts:1: " "$rule2"

new_case config-write
append_to bindings/wasm/test.sh "mkdir -p $dotcargo && echo '[build]' >$dotcargo/config.toml"
expect_fail "a $dotcargo/config.toml write in bindings/wasm/test.sh" "^  - bindings/wasm/test\\.sh:[0-9]+: mkdir -p " "$rule2"

echo "$((tests_run - tests_failed))/$tests_run cases passed"
completed=1; exit "$((tests_failed > 0))"
