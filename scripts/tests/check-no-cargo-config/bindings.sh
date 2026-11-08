#!/usr/bin/env bash
# Negative test of rule 2 of scripts/check-no-cargo-config.sh for bindings/** (feature 0006 F06,
# security audit L2): Cargo configuration passed on a command line (`--config`, `-Z`), a CARGO_* or
# RUST* variable assignment, or a `.cargo/config` write in any file under bindings/ fails, as under
# scripts/ and .github/. The one exception is ADR 0059's line in
# bindings/wasm/scripts/wasm-cargo-args.sh, which build-package.sh and test.sh source, allowed by
# path and exact text, once; `WASM_CARGO_ARGS` may be read but not assigned anywhere else under
# bindings/, so that line is the whole of the shipped build's extra Cargo arguments (which
# scripts/check-rsa-symbols.sh reads too). The two others (0006 F10; 0007 review SF-1, pending
# owner Gate 2) are @polyjose/node's static-CRT RUSTFLAGS line in bindings/node/scripts/ci-build.sh
# and the regex of bindings/node/test/ci.test.ts that asserts it, by path and exact text, once each.
#
# Must pass:
#   1. the unchanged tree, which holds the ADR 0059 line;
#   2. look-alikes under bindings/: a `#` comment line with `--config`, `//` and `//!` comment
#      lines with `--config`, `-Z` and a RUSTFLAGS assignment in Rust and TypeScript files (as in
#      tests/memory.rs's docs), a `[A-Z]` regex, an `env!` of CARGO_MANIFEST_DIR and a read of
#      `${WASM_CARGO_ARGS[@]}` and `${#WASM_CARGO_ARGS[@]}`.
# Must fail, on rule 2 only, naming the file and line:
#   3. the audit's plant: the ADR 0059 line plus a `build.rustflags` --cfg and a `[patch]`;
#   4. the ADR 0059 line with another value (opt-level "s"), and emptied (`WASM_CARGO_ARGS=()`);
#   5. the exact ADR 0059 line a second time in wasm-cargo-args.sh, and once in another file
#      (build-package.sh, where it was before, and a new one);
#   6. `WASM_CARGO_ARGS+=(...)` after it, with no Cargo flag;
#   7. `--config` on another command line in a bindings script, among them a second literal
#      opt-level override on test.sh's release memory run;
#   8. `-Z` (attached and separate) in a bindings script, and `-Z` in a scripts/ file;
#   9. a RUSTFLAGS prefix assignment, an exported CARGO_TARGET_<triple>_RUSTFLAGS, a
#      `RUSTFLAGS:` key in a TypeScript file, and a `.cargo/config.toml` write, under bindings/;
#  10. `--config` in Rust code (not a comment), and on a shell line that starts with `//` (a path,
#      not a comment, in a shell script).
# The 0007 static-CRT lines (present on a tree with bindings/node, added to the copy otherwise):
#  11. must pass: both lines at their paths;
#  12. must fail: either line at another path, either one with a changed flag (`+crt-static,-foo`,
#      another `-C`), either one a second time, and another RUSTFLAGS line in ci-build.sh (an
#      assignment, and a `+=` one).
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
args_file=bindings/wasm/scripts/wasm-cargo-args.sh
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
if [ "$(grep -cFx -- "$adr0059_line" "$repo/$args_file" 2>/dev/null || true)" = 1 ]; then
  echo "ok   - $args_file holds the ADR 0059 line once"
else
  echo "FAIL - $args_file does not hold the ADR 0059 line exactly once: $adr0059_line"
  tests_failed=$((tests_failed + 1))
fi

# The 0007 static-CRT lines (F10): each at most once in the tree (absent without bindings/node).
crt_file=bindings/node/scripts/ci-build.sh
crt_line="  export $rf=\"\${$rf:+\$$rf }-C target-feature=+crt-static\""
crt_test_file=bindings/node/test/ci.test.ts
crt_test_line='    /^\s*export '"$rf"'="\$\{'"$rf"':\+\$'"$rf"' \}-C target-feature=\+crt-static"$/,'
for pair in "$crt_file:$crt_line" "$crt_test_file:$crt_test_line"; do
  tests_run=$((tests_run + 1))
  n=$(grep -cFx -- "${pair#*:}" "$repo/${pair%%:*}" 2>/dev/null || true)
  if [ "${n:-0}" -le 1 ]; then
    echo "ok   - ${pair%%:*} holds its static-CRT line at most once (${n:-0})"
  else
    echo "FAIL - ${pair%%:*} holds its static-CRT line $n times"
    tests_failed=$((tests_failed + 1))
  fi
done

# ensure_line <path in the copy> <line>: the copy's file holds the line (appended unless it is there
# once already, as on a tree with bindings/node).
ensure_line() {
  [ "$(grep -cFx -- "$2" "$case_dir/$1" 2>/dev/null || true)" = 1 ] || append_to "$1" "$2"
}
# crt_case <name>: a new case whose copy holds both static-CRT lines.
crt_case() { new_case "$1"; ensure_line "$crt_file" "$crt_line"; ensure_line "$crt_test_file" "$crt_test_line"; }

# --- Must pass ------------------------------------------------------------------------------------

new_case unchanged
expect_pass "the unchanged tree (the ADR 0059 line in $args_file)"
expect_also "rule 2 says it read bindings/" '^ok: no script, workflow or binding '

new_case look-alikes
append_to bindings/wasm/test.sh "# a comment may name cargo $cfg 'profile.release.opt-level=\"s\"' and $zf build-std
n=\${#WASM_CARGO_ARGS[@]}; args=(\"\${WASM_CARGO_ARGS[@]}\"); echo \"\$n \${args[*]}\""
append_to bindings/wasm/test-pkg/src/f06-look-alike.ts 'export const upper = /[A-Z]+/; // [a-zA-Z0-9_-Z]'
append_to bindings/wasm/src/f06_look_alike.rs 'pub const DIR: &str = env!("CARGO_MANIFEST_DIR");'
append_to bindings/wasm/src/f06_look_alike.rs "//! wasm-pack test --release -- $cfg 'profile.release.opt-level=\"z\"' --test memory
    // rustc $zf unstable-options --print target-spec-json, with $rf=--cfg"
append_to bindings/wasm/test-pkg/src/f06-look-alike.ts "  // $rf='--cfg x' cargo build $cfg 'build.rustc-wrapper=\"w\"'"
expect_pass "comments, regexes, env!(CARGO_MANIFEST_DIR) and reads of WASM_CARGO_ARGS under bindings/"

# --- Must fail ------------------------------------------------------------------------------------

new_case audit-plant
edit_in "$args_file" "$adr0059_line" \
  "WASM_CARGO_ARGS=($cfg 'profile.release.opt-level=\"z\"' $cfg 'build.rustflags=[\"--cfg\",\"polyjose_audit\"]' $cfg 'patch.crates-io.aes.path=\"/tmp/evil-aes\"')"
expect_fail "the audit's plant (rustflags --cfg and a [patch] added to the ADR 0059 line)" \
  "^  - bindings/wasm/scripts/wasm-cargo-args\\.sh:[0-9]+: WASM_CARGO_ARGS=\\(.*polyjose_audit" "$rule2"

new_case other-value
edit_in "$args_file" "$adr0059_line" "WASM_CARGO_ARGS=($cfg 'profile.release.opt-level=\"s\"')"
expect_fail "the ADR 0059 line with opt-level \"s\"" \
  "^  - bindings/wasm/scripts/wasm-cargo-args\\.sh:[0-9]+: WASM_CARGO_ARGS=\\(.*opt-level=\"s\"" "$rule2"

new_case emptied
edit_in "$args_file" "$adr0059_line" "WASM_CARGO_ARGS=()"
expect_fail "the ADR 0059 line emptied" \
  '^  - bindings/wasm/scripts/wasm-cargo-args\.sh:[0-9]+: WASM_CARGO_ARGS=\(\)$' "$rule2"

new_case twice
edit_in "$args_file" "$adr0059_line" "$adr0059_line
$adr0059_line"
expect_fail "the ADR 0059 line twice in $args_file" \
  "^  - bindings/wasm/scripts/wasm-cargo-args\\.sh:[0-9]+: WASM_CARGO_ARGS=\\($cfg 'profile" "$rule2"

new_case other-file
append_to bindings/node/scripts/f06.sh "$adr0059_line"
expect_fail "the exact ADR 0059 line in another file" \
  "^  - bindings/node/scripts/f06\\.sh:1: WASM_CARGO_ARGS=" "$rule2"

new_case old-place
append_to bindings/wasm/scripts/build-package.sh "$adr0059_line"
expect_fail "the exact ADR 0059 line in build-package.sh, where it was before" \
  "^  - bindings/wasm/scripts/build-package\\.sh:[0-9]+: WASM_CARGO_ARGS=" "$rule2"

new_case appended
edit_in "$args_file" "$adr0059_line" "$adr0059_line
WASM_CARGO_ARGS+=(--locked)"
expect_fail "WASM_CARGO_ARGS+=(...) after the ADR 0059 line" \
  '^  - bindings/wasm/scripts/wasm-cargo-args\.sh:[0-9]+: WASM_CARGO_ARGS\+=\(--locked\)$' "$rule2"

new_case config-elsewhere
append_to bindings/wasm/test.sh "cargo build $cfg 'build.rustc-wrapper=\"/tmp/wrap\"' -p polyjose-wasm"
expect_fail "$cfg on another command line in bindings/wasm/test.sh" \
  "^  - bindings/wasm/test\\.sh:[0-9]+: cargo build $cfg " "$rule2"

new_case test-sh-override
append_to bindings/wasm/test.sh "memory_release_run --release --node -- $cfg 'profile.release.opt-level=\"z\"' --test memory"
expect_fail "a second literal opt-level override on test.sh's release memory run" \
  "^  - bindings/wasm/test\\.sh:[0-9]+: memory_release_run --release --node -- $cfg " "$rule2"

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

new_case rust-code
append_to bindings/wasm/src/f06_spawn.rs "pub fn f() { let _ = std::process::Command::new(\"cargo\").args([\"$cfg\", \"x\"]); }"
expect_fail "$cfg in Rust code" "^  - bindings/wasm/src/f06_spawn\\.rs:1: " "$rule2"

new_case slashes-in-shell
append_to bindings/wasm/test.sh "//usr/bin/env cargo build $cfg 'build.rustc-wrapper=\"/tmp/wrap\"'"
expect_fail "a shell line starting with // (a path, not a comment)" "^  - bindings/wasm/test\\.sh:[0-9]+: //usr/bin/env cargo build " "$rule2"

# --- The 0007 static-CRT lines (F10) ---------------------------------------------------------------

crt_case crt-lines
expect_pass "the static-CRT lines at $crt_file and $crt_test_file"

crt_case crt-other-path
append_to bindings/node/scripts/f10.sh "$crt_line"
expect_fail "the static-CRT line of $crt_file in another file" \
  "^  - bindings/node/scripts/f10\\.sh:1:   export $rf=" "$rule2"

crt_case crt-test-other-path
append_to bindings/node/test/f10.test.ts "$crt_test_line"
expect_fail "the static-CRT line of $crt_test_file in another file" \
  "^  - bindings/node/test/f10\\.test\\.ts:1: " "$rule2"

crt_case crt-swapped
append_to "$crt_file" "$crt_test_line"
expect_fail "the line of $crt_test_file in $crt_file" "^  - bindings/node/scripts/ci-build\\.sh:[0-9]+:     /" "$rule2"

crt_case crt-extra-feature
edit_in "$crt_file" "$crt_line" "${crt_line%\"},-foo\""
expect_fail "the static-CRT line with +crt-static,-foo" \
  "^  - bindings/node/scripts/ci-build\\.sh:[0-9]+: .*crt-static,-foo\"$" "$rule2"

crt_case crt-other-flag
edit_in "$crt_file" "$crt_line" "${crt_line%\"} -C link-arg=/f10\""
expect_fail "the static-CRT line with another -C" \
  "^  - bindings/node/scripts/ci-build\\.sh:[0-9]+: .*crt-static -C link-arg=/f10\"$" "$rule2"

crt_case crt-test-changed
edit_in "$crt_test_file" "$crt_test_line" "${crt_test_line/crt-static/crt-static,-foo}"
expect_fail "the line of $crt_test_file with another flag" \
  "^  - bindings/node/test/ci\\.test\\.ts:[0-9]+: .*crt-static,-foo" "$rule2"

crt_case crt-twice
append_to "$crt_file" "$crt_line"
expect_fail "the static-CRT line a second time in $crt_file" \
  "^  - bindings/node/scripts/ci-build\\.sh:[0-9]+:   export $rf=" "$rule2"

crt_case crt-test-twice
append_to "$crt_test_file" "$crt_test_line"
expect_fail "the line of $crt_test_file a second time" "^  - bindings/node/test/ci\\.test\\.ts:[0-9]+: " "$rule2"

crt_case crt-other-line
append_to "$crt_file" "export $rf=\"-C target-feature=+crt-static\""
expect_fail "another $rf line in $crt_file" \
  "^  - bindings/node/scripts/ci-build\\.sh:[0-9]+: export $rf=\"-C target-feature" "$rule2"

crt_case crt-append-assign
append_to "$crt_file" "$rf+=\" -C link-arg=/f10\""
expect_fail "a $rf+= line in $crt_file" "^  - bindings/node/scripts/ci-build\\.sh:[0-9]+: $rf\\+=" "$rule2"

echo "$((tests_run - tests_failed))/$tests_run cases passed"
completed=1; exit "$((tests_failed > 0))"
