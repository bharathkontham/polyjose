#!/usr/bin/env bash
# Negative test of rule 2 of scripts/check-no-cargo-config.sh for bindings/** (feature 0006 F06,
# security audit L2): Cargo configuration passed on a command line (`--config`, `-Z`), a CARGO_* or
# RUST* variable assignment, or a `.cargo/config` write in any file under bindings/ fails, as under
# scripts/ and .github/. The exceptions are allowed by path and exact text, once each: ADR 0059's
# line in bindings/wasm/scripts/wasm-cargo-args.sh, which build-package.sh and test.sh source
# (`WASM_CARGO_ARGS` may be read but not assigned anywhere else under bindings/, so that line is
# the whole of the shipped build's extra Cargo arguments, which scripts/check-rsa-symbols.sh reads
# too); @polyjose/node's static-CRT RUSTFLAGS line in bindings/node/scripts/ci-build.sh and the
# regex of bindings/node/test/ci.test.ts that asserts it (0006 F10; 0007 review SF-1); ADR 0032
# §1's `-Zbuild-std` line and its README sentence (bindings/swift); and check-test-vectors-off.sh's
# `cargo rustc -- --print cfg` line.
#
# Must pass:
#   1. the unchanged tree, which holds the ADR 0059 line;
#   2. look-alikes under bindings/: a `#` comment line of a shell script with `--config`, a `[A-Z]`
#      regex, an `env!` of CARGO_MANIFEST_DIR and a read of `${WASM_CARGO_ARGS[@]}` and
#      `${#WASM_CARGO_ARGS[@]}` (`//` comment lines are read since the T06 fix round: 19 below).
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
# bindings/kotlin and bindings/swift (feature 0030 T06; read since then):
#  13. must pass: ADR 0032 §1's `-Zbuild-std` line of bindings/swift/scripts/build-xcframework.sh and
#      the README sentence about it, once each (the unchanged tree), the Gradle wrapper jar and the
#      PE fixtures of bindings/node (the unchanged tree), and `unzip -Z1` at the start of a shell line;
#  14. must fail: a RUSTFLAGS assignment and a `-Z` flag in a script under each tree, a `-Z` in a
#      Gradle commandLine; the allowed line twice, changed, with another `-Z`, in another file, and
#      a `-Z` on its continuation line; the README sentence changed, twice, in another file;
#  15. must fail, the unzip carve-out's edges: `unzip -Z1 a && cargo -Z...`, `unzip -Z1` as a
#      cargo argument, after `;`, with more attached (`-Z1build-std`), on a continuation line, and
#      at the start of a line of a .kts file and of a workflow; `-Z` at the start of a line, after
#      `+nightly`, after other arguments;
#  16. must fail: a text file at the Gradle wrapper jar's path, a zip-signed file at another path;
#      a RUSTFLAGS assignment after a NUL byte (under bindings/wasm too), a NUL inside the name and
#      a `-Z` after a NUL (one-true-awk ends a line at a NUL; the gate drops NULs first).
# A guarded name as the whole of a quoted string (feature 0030 T06):
#  17. must fail: `environment("NAME", ...)`, `environment["NAME"] = ...`, `put("NAME", ...)`,
#      `mapOf("NAME" to ...)` and a CARGO_TARGET_<triple>_LINKER name in a .kts file under
#      bindings/kotlin; `env["NAME"] = ...` and an escaped `\"NAME\"` in a .swift file; a double- and
#      a single-quoted name in a .sh file under bindings/swift; a single-quoted name under scripts/;
#  18. must pass: quoted non-guarded names (CARGO_MANIFEST_DIR, NAME_NOTE, CARGO_HOME_DIR) and a
#      guarded name inside a longer quoted string.
# The T06 fix round (bug B01; security audit B1, B2, L1-L3; review of 9ac6d193):
#  19. must fail: B01's `// note<CR>` then code in .kts, .swift, .java, .ts and .mjs files; a YAML
#      `#` comment, a CR, NEL or LS, then a guarded key; a properties `#` comment, a CR, then
#      polyjose.jniLibsDir=; `unzip -Z1` after `\`+CR and after a lone CR; the allowed nightly line
#      ending in CR; lines starting with `#` in Swift, TypeScript and Rust; a `//` line in a Kotlin
#      string run by bash, and `//`/`//!` comment lines with `--config`, `-Z` or an assignment;
#      `{NAME: x}` in YAML and TypeScript; Xcode conditional names (.xcconfig, .pbxproj, XcodeGen);
#      `cargo rustc`/`rustdoc` with `--` on its line, on a continuation line (also of the allowed
#      nightly line), in one- and multi-line Gradle commandLine lists; the allowed `--print cfg`
#      line twice, changed or elsewhere; CARGO_PROFILE_*, CARGO_ALIAS_*, RUSTUP_TOOLCHAIN (also
#      quoted in Gradle); polyjose.jniLibsDir set in .properties files (`=`, `:`, whitespace);
#  20. must pass: CRLF line ends; `#` comments in .sh, .yml, .toml, .properties and an
#      extensionless file; `//` prose naming the variables; `${NAME:-x}` and `${NAME:+x}`;
#      conditional settings of other names; `--` after cargo test, run and clippy and after a
#      closed cargo rustc list; a read of RUSTUP_TOOLCHAIN; other properties, and the
#      polyjose.jniLibsDir text in Markdown.
# Fix round 3 (feature 0030 T06: follow-up audit of 0a7be3ae, bug B02, round-2 tester (c)):
#  21. must fail: a `#` piece after a CR, a `#` line continuing `echo x\`, a `#` after a form feed,
#      a vertical tab or a leading CR (shell code, not comments); B02's `# note )` inside a Python
#      argv list and a Ruby `# see )` before `--`, and the balanced `# (see note)` variant; a word
#      starting with `@` after cargo rustc/rustdoc (on its line, a continuation line, a Gradle
#      list); a CR or LS between a name and its `=` or `:`; polyjose.jniLibsDir then a `\`;
#  22. must pass: indented `#` comments naming a variable in a .sh file; a balanced `# (see note)`
#      in a Python list without `--`, and a `# )` comment and a `--` after the list closes; `@` on
#      lines that are not a cargo rustc command (`git show @{u}`, `"@here"`).
# Fix round 4 (feature 0030 T06: final audit B-1, L-1, L-4):
#  23. must fail: a quoted cargo in a call that closes, then the real argv list on the same line and
#      `--` on the next (Kotlin `if (listOf(...))`, JavaScript `assert(...)`); a list that closes
#      with a new one opening later on its line; a `'"'` string before a `# " ]` comment in a Python
#      list; a guarded name as a JavaScript template literal (also with an escaped closing backtick);
#  24. must pass: a cargo rustc list closed on its line (another call after it), then an unrelated
#      `--` in a later list; template literals holding a non-guarded name or a longer text.
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
expect_pass "a # comment in a shell script, regexes, env!(CARGO_MANIFEST_DIR) and reads of WASM_CARGO_ARGS under bindings/"

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

# --- bindings/kotlin and bindings/swift (feature 0030 T06) ------------------------------------------

# ADR 0032 §1's nightly line and the README sentence about it, each in the tree once (or every case
# below tests nothing).
xcf_file=bindings/swift/scripts/build-xcframework.sh
xcf_line="    cargo \"+\$nightly\" rustc --locked ${zf}build-std=std,panic_abort -p polyjose-ffi --release \\"
readme_file=bindings/swift/README.md
# shellcheck disable=SC2016 # the exact text of the line, not expansions
readme_line='  - Every Rust target is tier 2 on the stable toolchain of `rust-toolchain.toml` (the aarch64 watchOS targets since Rust 1.95), except `arm64_32-apple-watchos` (Apple Watch Series 4–8, SE 1–2, Ultra 1). That one is tier 3 and is built with the nightly pinned in `nightly-toolchain` and `'"$zf"'build-std`. Install it with `rustup toolchain install "$(cat bindings/swift/nightly-toolchain)" --profile minimal --component rust-src`.'
for pair in "$xcf_file:$xcf_line" "$readme_file:$readme_line"; do
  tests_run=$((tests_run + 1))
  if [ "$(grep -cFx -- "${pair#*:}" "$repo/${pair%%:*}" 2>/dev/null || true)" = 1 ]; then
    echo "ok   - ${pair%%:*} holds its allowed $zf line once"
  else
    echo "FAIL - ${pair%%:*} does not hold its allowed $zf line exactly once"
    tests_failed=$((tests_failed + 1))
  fi
done
unzip_z="unzip ${zf}1"
jar=bindings/kotlin/gradle/wrapper/gradle-wrapper.jar

new_case kotlin-swift-unzip
append_to bindings/kotlin/scripts/t06.sh "  $unzip_z \"\$aar\" >\"\$work/aar.list\"
$unzip_z \"\$zip\""
append_to bindings/swift/scripts/t06.sh "$unzip_z \"\$zip\" >\"\$scratch/entries.txt\" 2>/dev/null || true"
expect_pass "$unzip_z at the start of a shell line under bindings/kotlin and bindings/swift"

for tree in kotlin swift; do
  new_case "$tree-rustflags"
  append_to "bindings/$tree/scripts/t06.sh" "$rf='--cfg x' cargo build -p polyjose-ffi"
  expect_fail "a $rf assignment under bindings/$tree" "^  - bindings/$tree/scripts/t06\\.sh:1: $rf=" "$rule2"

  new_case "$tree-z"
  append_to "bindings/$tree/scripts/t06.sh" "cargo +nightly build ${zf}build-std=std -p polyjose-ffi"
  expect_fail "a $zf flag under bindings/$tree" "^  - bindings/$tree/scripts/t06\\.sh:1: cargo \\+nightly build " "$rule2"
done

new_case kotlin-gradle-z
append_to bindings/kotlin/t06.gradle.kts 'tasks.register<Exec>("t06") { commandLine("cargo", "'"${zf}"'build-std", "build") }'
expect_fail "a $zf argument in a Gradle commandLine" "^  - bindings/kotlin/t06\\.gradle\\.kts:1: " "$rule2"

# The allowed nightly line: once passes (the unchanged tree); twice, changed or elsewhere fails.
new_case xcf-twice
edit_in "$xcf_file" "$xcf_line" "$xcf_line
$xcf_line"
expect_fail "the ADR 0032 nightly line twice in $xcf_file" "^  - bindings/swift/scripts/build-xcframework\\.sh:[0-9]+:     cargo " "$rule2"

new_case xcf-changed
edit_in "$xcf_file" "$xcf_line" "${xcf_line/panic_abort/panic_abort,core}"
expect_fail "the ADR 0032 nightly line with another build-std value" \
  "^  - bindings/swift/scripts/build-xcframework\\.sh:[0-9]+: .*panic_abort,core" "$rule2"

new_case xcf-extra-flag
edit_in "$xcf_file" "$xcf_line" "${xcf_line/--locked/--locked ${zf}unstable-options}"
expect_fail "the ADR 0032 nightly line with another $zf flag" \
  "^  - bindings/swift/scripts/build-xcframework\\.sh:[0-9]+: .*unstable-options" "$rule2"

new_case xcf-other-file
append_to bindings/swift/scripts/package.sh "$xcf_line"
expect_fail "the ADR 0032 nightly line in another file" "^  - bindings/swift/scripts/package\\.sh:[0-9]+:     cargo " "$rule2"

new_case xcf-continuation
edit_in "$xcf_file" "$xcf_line" "$xcf_line
      ${zf}unstable-options \\"
expect_fail "a $zf flag on the allowed line's continuation line" \
  "^  - bindings/swift/scripts/build-xcframework\\.sh:[0-9]+:       ${zf}unstable-options" "$rule2"

# The allowed README sentence: changed, twice or elsewhere fails.
new_case readme-changed
edit_in "$readme_file" "$readme_line" "${readme_line/build-std/build-std,unstable-options}"
expect_fail "the README's $zf sentence changed" "^  - bindings/swift/README\\.md:[0-9]+: .*build-std,unstable" "$rule2"

new_case readme-twice
append_to "$readme_file" "$readme_line"
expect_fail "the README's $zf sentence twice" "^  - bindings/swift/README\\.md:[0-9]+:   - Every Rust target" "$rule2"

new_case readme-other-file
append_to bindings/kotlin/README.md "$readme_line"
expect_fail "the README's $zf sentence in another file" "^  - bindings/kotlin/README\\.md:[0-9]+:   - Every Rust target" "$rule2"

# The unzip carve-out is the exact command at the start of a shell line, not on a continuation line;
# a cargo -Z anywhere else on the line still fails.
unzip_case() { # <name> <description> <text> <ERE of the reported line>
  new_case "$1"
  append_to bindings/kotlin/scripts/t06.sh "$3"
  expect_fail "$2" "^  - bindings/kotlin/scripts/t06\\.sh:[0-9]+: $4" "$rule2"
}
unzip_case unzip-then-cargo "$unzip_z, then a cargo $zf on the same line" \
  "$unzip_z a.zip && cargo build ${zf}build-std" "unzip "
unzip_case unzip-cargo-arg "$unzip_z inside a cargo command (not at the start of the line)" \
  "cargo +nightly build -p x $unzip_z" "cargo "
unzip_case unzip-after-semicolon "$unzip_z after a ;" "true; $unzip_z a.zip" "true; "
unzip_case unzip-attached "$unzip_z with more attached (${zf}1build-std)" "$unzip_z""build-std a.zip" "unzip "
unzip_case unzip-continuation "$unzip_z on a continuation line (an argument of the command above)" \
  "cargo +nightly build -p polyjose-ffi \\
  $unzip_z" "  unzip "
unzip_case z-line-start "$zf at the start of a line" "${zf}build-std=std \\" "${zf}build-std"
unzip_case z-plus-nightly "$zf after +nightly" "cargo +nightly ${zf}unstable-options build" "cargo \\+nightly "
unzip_case z-after-args "$zf after other cargo arguments" "cargo build --release -p x ${zf}x" "cargo build "

# Review of 9ac6d193 (2): the carve-out is for *.sh files only, even at the start of a line.
new_case unzip-not-shell
append_to bindings/kotlin/t06.gradle.kts "$unzip_z a.zip"
append_to .github/workflows/t06.yml "          $unzip_z a.zip"
expect_fail "$unzip_z a.zip at the start of a line of a .kts file" "^  - bindings/kotlin/t06\\.gradle\\.kts:1: unzip " "$rule2"
expect_also "and of a workflow run block" "^  - \\.github/workflows/t06\\.yml:1:           unzip "

# The Gradle wrapper jar is skipped by its exact path, and only while it is a zip; a text file there,
# or a jar at another path, is scanned.
new_case jar-text
rm -f "$case_dir/$jar"
append_to "$jar" "$rf=--cfg cargo build"
expect_fail "a text file at the Gradle wrapper jar's path" "^  - ${jar//./\\.}:1: $rf=" "$rule2"

new_case jar-other-path
printf 'PK\003\004%s=x cargo build\n' "$rf" >"$case_dir/bindings/kotlin/gradle/wrapper/t06.jar"
expect_fail "a zip-signed file at another path" "^  - bindings/kotlin/gradle/wrapper/t06\\.jar:1: " "$rule2"

# NUL bytes cannot hide a line's rest from the scan (one-true-awk stops a record at a NUL; bash
# drops NULs when it runs a script).
new_case nul-hides-rest
printf 'echo a\000; %s=x cargo build\n' "$rf" >>"$case_dir/bindings/wasm/scripts/t06.sh"
expect_fail "a $rf assignment after a NUL byte (bindings/wasm, scanned before T06)" \
  "^  - bindings/wasm/scripts/t06\\.sh:1: echo a; $rf=" "$rule2"

new_case nul-splits-name
printf 'RUST\000FLAGS=x cargo build\nok\000 %sbuild-std\n' "$zf" >>"$case_dir/bindings/kotlin/scripts/t06.sh"
expect_fail "a NUL byte inside a variable name" "^  - bindings/kotlin/scripts/t06\\.sh:1: $rf=" "$rule2"
expect_also "and a $zf after a NUL byte" "^  - bindings/kotlin/scripts/t06\\.sh:2: ok ${zf}build-std"

# A guarded name as a whole quoted string: how Gradle and Swift set a process environment variable
# (`environment("NAME", ...)`, `env["NAME"] = ...`), none of which the assignment rules see.
rw="RUST""C_WRAPPER"
ch="CARGO""_HOME"
tl="CARGO_TARGET_AARCH64_LINUX_ANDROID""_LINKER"
quoted_case() { # <name> <file> <text> <description>
  new_case "$1"
  append_to "$2" "$3"
  expect_fail "$4" "^  - ${2//./\\.}:1: " "$rule2"
}
kts=bindings/kotlin/t06.gradle.kts
quoted_case quoted-environment-call "$kts" 'tasks.register<Exec>("t06") { environment("'"$rf"'", "--cfg x") }' \
  "environment(\"$rf\", ...) in a .kts file"
quoted_case quoted-environment-index "$kts" 'val e = environment; e["'"$rw"'"] = "/tmp/wrap"' \
  "environment[\"$rw\"] = ... in a .kts file"
quoted_case quoted-put "$kts" 'environment.put("'"$ch"'", "/tmp/home")' "put(\"$ch\", ...) in a .kts file"
quoted_case quoted-map-of "$kts" 'val e = mapOf("'"$rf"'" to "--cfg x")' "mapOf(\"$rf\" to ...) in a .kts file"
quoted_case quoted-family "$kts" 'environment("'"$tl"'", "/tmp/cc")' \
  "a CARGO_TARGET_<triple>_LINKER name, quoted, in a .kts file"
quoted_case quoted-swift-env bindings/swift/Sources/t06.swift 'env["'"$rf"'"] = "--cfg x"' \
  "env[\"$rf\"] = ... in a .swift file"
quoted_case quoted-swift-escaped bindings/swift/Sources/t06.swift 'let s = "env[\"'"$rf"'\"] = 1"' \
  "an escaped quoted name inside a .swift string"
quoted_case quoted-sh-double bindings/swift/scripts/t06.sh 'printf -v "'"$rf"'" %s "--cfg x"' \
  "printf -v \"$rf\" in a .sh file under bindings/swift"
quoted_case quoted-sh-single bindings/swift/scripts/t06.sh "printf -v '$rw' %s /tmp/wrap" \
  "a single-quoted name in a .sh file under bindings/swift"
quoted_case quoted-scripts scripts/t06.sh "export '$ch'" "a single-quoted name in a scripts/ file"

new_case quoted-look-alikes
append_to "$kts" 'tasks.register<Exec>("t06") { environment("CARGO_MANIFEST_DIR", "x"); environment("'"$rf"'_NOTE", "x") }
println("set '"$rf"' before building")'
append_to bindings/swift/scripts/t06.sh "echo '$rf is read by cargo'; echo \"${ch}_DIR\""
expect_pass "a quoted non-guarded name and a guarded name inside a longer string"

# Tester additions (feature 0030 T06 task test): behaviours that held on the tested tree.
unzip_case unzip-two-spaces "unzip  ${zf}1 (two spaces: not the exact command)" "unzip  ${zf}1 a.zip" "unzip "
unzip_case unzip-semicolon-cargo "$unzip_z;cargo ${zf}x (no space after the ;)" "$unzip_z;cargo build ${zf}x" "unzip "
new_case xcf-altered-before-original
edit_in "$xcf_file" "$xcf_line" "${xcf_line//panic_abort/panic_abort,x}
$xcf_line"
expect_fail "an altered copy of the ADR 0032 nightly line before the original" \
  "^  - bindings/swift/scripts/build-xcframework\\.sh:[0-9]+:     cargo .*panic_abort,x" "$rule2"
quoted_case quoted-yaml-key .github/workflows/t06.yml '      "'"$rf"'": --cfg x' "a double-quoted $rf key of a workflow env map"
quoted_case quoted-xcscheme bindings/swift/t06.xcscheme '<EnvironmentVariable key = "'"$rf"'" value = "--cfg x">' \
  "an Xcode scheme EnvironmentVariable key naming $rf"
quoted_case quoted-swift-raw bindings/swift/Sources/t06.swift 'env[#"'"$rf"'"#] = "--cfg x"' "a Swift raw string naming $rf"

# --- Fix round (feature 0030 T06: bug B01, security audit B1/B2/L1-L3, review of 9ac6d193) ---------
pt="CARGO_PRO""FILE_RELEASE_LTO"
al="CARGO_ALI""AS_B"
tc="RUSTUP_TOOL""CHAIN"
jl="polyjose.jniLibs""Dir"
dd="-""-"
rustc_word="rust""c"
rustdoc_word="rust""doc"
qcargo="\"car""go\""
yml=.github/workflows/t06.yml
# plant <path in the copy> <printf format> [<arguments>...]: appends printf's output (CRs and other
# bytes append_to cannot write).
plant() {
  local path=$1; shift
  mkdir -p "$(dirname "$case_dir/$path")" || lib_die "could not create the directory of $path"
  # shellcheck disable=SC2059 # the format is the test's text
  printf "$@" >>"$case_dir/$path" || lib_die "could not write $path in the copy"
}
plant_case() { # <name> <path> <ERE of the reported line after "path:"> <description> <printf format> [<arguments>...]
  local name=$1 path=$2 want=$3 desc=$4; shift 4
  new_case "$name"
  plant "$path" "$@"
  expect_fail "$desc" "^  - ${path//./\\.}:$want" "$rule2"
}

# A. A line break other than LF (CR; NEL, LS, PS) starts a new line for the comment skip (B01, B1).
plant_case b01-kts bindings/kotlin/build-logic/t06.kts '1: // note<CR>environment' \
  "B01: // note<CR> then environment(\"$rf\", ...) in a .kts file" '// note\renvironment("%s", "x")\n' "$rf"
plant_case b01-swift bindings/swift/Sources/t06.swift '1: // note<CR>setenv' \
  "B01: // note<CR> then setenv(\"$rf\", ...) in a .swift file" '// note\rsetenv("%s", "x", 1)\n' "$rf"
plant_case b01-java bindings/kotlin/jvm/src/T06.java '1: // note<CR>' \
  "B01: // note<CR> then a ProcessBuilder environment write in a .java file" '// note\rpb.environment().put("%s", "x");\n' "$rf"
plant_case b01-ts bindings/node/test/t06.ts '1: // note<CR>' \
  "B01: // note<CR> then process.env.$rf = ... in a .ts file" '// note\rprocess.env.%s = "x";\n' "$rf"
plant_case b01-js bindings/wasm/js/t06.mjs '1: // note<CR>' \
  "B01: // note<CR> then process.env.$rf = ... in a .mjs file" '// note\rprocess.env.%s = "x";\n' "$rf"
plant_case cr-yaml-comment "$yml" '1: # c<CR>' \
  "B1: a YAML # comment, a lone CR, then a $rw: key" '# c\r      %s: evil\n' "$rw"
plant_case cr-properties-comment bindings/kotlin/gradle.properties '[0-9]+: # c<CR>' \
  "a properties # comment, a lone CR, then $jl=" '# c\r%s=/tmp/libs\n' "$jl"
plant_case ls-yaml-comment "$yml" '1: # c' \
  "a YAML # comment, a U+2028 LINE SEPARATOR, then a $rw: key" '# c\342\200\250      %s: evil\n' "$rw"
plant_case nel-yaml-comment "$yml" '1: # c' \
  "a YAML # comment, a U+0085 NEXT LINE, then a $rw: key" '# c\302\205      %s: evil\n' "$rw"
plant_case unzip-after-backslash-cr bindings/kotlin/scripts/t06.sh '2: unzip ' \
  "$unzip_z after a line ending in a backslash and a CR (fails closed)" 'cargo build \\\r\n%s a.zip\n' "$unzip_z"
plant_case unzip-after-lone-cr bindings/kotlin/scripts/t06.sh '1: true<CR>unzip ' \
  "$unzip_z after a lone CR (in bash an argument of the command before it)" 'true\r%s a.zip\n' "$unzip_z"
new_case xcf-crlf
edit_in "$xcf_file" "$xcf_line" "$xcf_line"$'\r'
expect_fail "the ADR 0032 nightly line ending in CR (not the exact line)" \
  "^  - bindings/swift/scripts/build-xcframework\\.sh:[0-9]+:     cargo .*<CR>$" "$rule2"
new_case crlf-pass
plant "$yml" '# %s: x\r\non: push\r\n' "$rf"
plant bindings/kotlin/t06.gradle.kts 'val a = 1\r\n// cargo reads %s\r\n' "$rf"
expect_pass "CRLF line ends: a YAML # comment naming a guarded key, Kotlin code and a // comment"

# A. `#` starts a comment only in *.sh, *.yml, *.yaml, *.toml, *.properties and files without an
# extension (B1): a Swift raw string, a JavaScript private field, a Rust attribute are code.
quoted_case hash-swift-raw bindings/swift/Sources/t06.swift '#"'"$rf"'"#: "--cfg x",' \
  "a line starting with a Swift raw string #\"$rf\"#"
quoted_case hash-ts-private bindings/node/test/t06.ts '#a = (process.env.'"$rf"' = "x");' \
  "a line starting with a TypeScript private field that assigns process.env.$rf"
quoted_case hash-rust-attr bindings/uniffi/src/t06.rs '#[allow(unused)] fn f() { std::env::set_var("'"$rf"'", "x") }' \
  "a line starting with a Rust attribute"
new_case hash-comments-pass
append_to bindings/kotlin/scripts/t06.sh "# $rf=x cargo build"
append_to "$yml" "# $rw: x"
append_to bindings/uniffi/t06.toml "# $rf = \"x\""
append_to bindings/kotlin/gradle.properties "# $jl=/tmp/libs"
append_to bindings/kotlin/scripts/t06tool "  # $rf=x"
expect_pass "# comment lines in .sh, .yml, .toml, .properties and an extensionless file"

# A. `//` lines are read in every file type (B1: a // line can be inside a string handed to a shell).
new_case slash-in-kotlin-string
append_to bindings/kotlin/t06.gradle.kts 'tasks.register<Exec>("t06") { commandLine("bash", "-c", """
//usr/bin/env '"$rf"'=--cfg=x cargo build
""") }'
expect_fail "a // line inside a Kotlin multi-line string run by bash" \
  "^  - bindings/kotlin/t06\\.gradle\\.kts:2: //usr/bin/env $rf=" "$rule2"
new_case slash-comments-read
append_to bindings/wasm/src/f06_look_alike.rs "//! wasm-pack test --release -- $cfg 'profile.release.opt-level=\"z\"' --test memory
    // rustc ${zf} unstable-options --print target-spec-json"
append_to bindings/wasm/test-pkg/src/f06-look-alike.ts "  // $rf='--cfg x' cargo build"
expect_fail "a //! line with $cfg in a .rs file" "^  - bindings/wasm/src/f06_look_alike\\.rs:1: //! " "$rule2"
expect_also "a // line with $zf in a .rs file" "^  - bindings/wasm/src/f06_look_alike\\.rs:2:     // rustc "
expect_also "a // line with a $rf assignment in a .ts file" "^  - bindings/wasm/test-pkg/src/f06-look-alike\\.ts:1:   // $rf="
new_case slash-prose-pass
append_to bindings/kotlin/t06.gradle.kts "// cargo reads $rf and $rw from the environment"
append_to bindings/wasm/src/f06_look_alike.rs "//! See $rf in the cargo book."
expect_pass "// comments that name guarded variables in prose"

# B. A YAML flow mapping or JavaScript object `{NAME:` (security audit B2); `${NAME:-x}` is a read.
quoted_case yaml-flow-map "$yml" "      env: {$rf: x}" "a YAML flow mapping env: {$rf: x}"
quoted_case ts-object-tight bindings/node/test/t06.ts "spawn(\"x\", { env: {$rw: \"w\"} });" \
  "a TypeScript object {$rw: ...} without a space"
new_case brace-read-pass
append_to bindings/kotlin/scripts/t06.sh "echo \"\${$rf:-unset}\" \"\${$ch:+set}\""
expect_pass "\${$rf:-unset} and \${$ch:+set} (reads) in a shell script"

# C. An Xcode conditional setting name, NAME[sdk=...] (task tester (c)2).
quoted_case xcode-cond-xcconfig bindings/swift/t06.xcconfig "${rf}[sdk=iphoneos*] = -Cx" \
  "an .xcconfig ${rf}[sdk=iphoneos*] setting"
quoted_case xcode-cond-pbxproj bindings/swift/HostedTests/t06.pbxproj "				\"${rf}[sdk=iphoneos*]\" = \"-Cx\";" \
  "a .pbxproj \"${rf}[sdk=iphoneos*]\" setting"
quoted_case xcode-cond-xcodegen bindings/swift/HostedTests/t06.yml "        ${rf}[sdk=iphoneos*][arch=arm64]: -Cx" \
  "an XcodeGen ${rf}[sdk=iphoneos*][arch=arm64] setting (two conditions)"
new_case xcode-cond-pass
append_to bindings/swift/t06.xcconfig "OTHER_SWIFT_FLAGS[sdk=iphoneos*] = -DX
${rf}_NOTE[sdk=iphoneos*] = x"
expect_pass "conditional settings of names that are not guarded"

# D. rustc arguments after a standalone `--` of cargo rustc or cargo rustdoc (security audit L1).
quoted_case rustc-dashdash bindings/swift/scripts/t06.sh "cargo $rustc_word -p polyjose-ffi --release $dd -C linker=/tmp/x" \
  "cargo $rustc_word ... $dd -C linker=..."
quoted_case rustdoc-dashdash scripts/t06.sh "cargo +nightly $rustdoc_word -p polyjose $dd --cfg x" \
  "cargo +nightly $rustdoc_word ... $dd --cfg x"
new_case rustc-continuation
append_to bindings/kotlin/scripts/t06.sh "cargo $rustc_word -p polyjose-ffi \\
  --release \\
  $dd -C linker=/tmp/x"
expect_fail "$dd on the second continuation line of a cargo $rustc_word command" \
  "^  - bindings/kotlin/scripts/t06\\.sh:3:   $dd -C" "$rule2"
new_case xcf-continuation-dashdash
# shellcheck disable=SC2016 # the exact text of the line, not expansions
edit_in "$xcf_file" '      --target "$triple" --crate-type staticlib >&2' \
  "      --target \"\$triple\" --crate-type staticlib $dd -C linker=/tmp/x >&2"
expect_fail "$dd -C on the continuation line of the allowed ADR 0032 nightly line" \
  "^  - bindings/swift/scripts/build-xcframework\\.sh:[0-9]+:       --target .* $dd -C linker" "$rule2"
quoted_case gradle-rustc-oneline "$kts" "commandLine($qcargo, \"$rustc_word\", \"-p\", \"x\", \"$dd\", \"-C\", \"linker=/tmp/x\")" \
  "a one-line Gradle commandLine($qcargo, \"$rustc_word\", ..., \"$dd\", ...)"
new_case gradle-rustc-multiline
append_to "$kts" "commandLine(
    $qcargo, /* ) */
    \"$rustc_word\", \"-p\", \"x\", // a comment's )
    \"$dd\", \"-C\", \"linker=/tmp/x\",
)"
expect_fail "a multi-line Gradle commandLine with \"$dd\" two lines below $qcargo (a ) in comments between)" \
  "^  - bindings/kotlin/t06\\.gradle\\.kts:4:     \"$dd\"" "$rule2"
new_case dashdash-pass
append_to bindings/kotlin/scripts/t06.sh "cargo test -p polyjose $dd --nocapture
cargo run -p polyjose-uniffi-bindgen $dd generate x
cargo clippy --workspace $dd -D warnings"
append_to "$kts" "commandLine(
    $qcargo, \"run\", \"-p\", \"polyjose-uniffi-bindgen\",
    \"$dd\", \"generate\", \"$rustc_word\",
)
commandLine($qcargo, \"$rustc_word\", \"-p\", \"x\")
val sep = listOf(\"$dd\")"
expect_pass "$dd after cargo test, run and clippy; after a closed cargo $rustc_word argument list"
cfg_file=scripts/check-test-vectors-off.sh
# shellcheck disable=SC2016 # the exact text of the line, not expansions
cfg_line='if ! cfgs=$(cargo '"$rustc_word"' --locked -q -p polyjose --lib '"$dd"' --print cfg 2>&1); then'
tests_run=$((tests_run + 1))
if [ "$(grep -cFx -- "$cfg_line" "$repo/$cfg_file" 2>/dev/null || true)" = 1 ]; then
  echo "ok   - $cfg_file holds its allowed cargo $rustc_word $dd line once"
else
  echo "FAIL - $cfg_file does not hold its allowed cargo $rustc_word $dd line exactly once"
  tests_failed=$((tests_failed + 1))
fi
new_case cfg-line-twice
append_to "$cfg_file" "$cfg_line"
expect_fail "the allowed cargo $rustc_word $dd --print cfg line twice" "^  - scripts/check-test-vectors-off\\.sh:[0-9]+: if ! cfgs=" "$rule2"
new_case cfg-line-changed
edit_in "$cfg_file" "$cfg_line" "${cfg_line/--print cfg/--print cfg -C linker=/tmp/x}"
expect_fail "the allowed cargo $rustc_word $dd line with -C linker= added" \
  "^  - scripts/check-test-vectors-off\\.sh:[0-9]+: .*-C linker=/tmp/x" "$rule2"
new_case cfg-line-other-file
append_to scripts/t06.sh "$cfg_line"
expect_fail "the allowed cargo $rustc_word $dd line in another file" "^  - scripts/t06\\.sh:1: if ! cfgs=" "$rule2"

# E. CARGO_PROFILE_*, CARGO_ALIAS_* and RUSTUP_TOOLCHAIN (security audit L2).
quoted_case name-profile scripts/t06.sh "$pt=off cargo build --release" "$pt= (a CARGO_PROFILE_* variable)"
quoted_case name-alias bindings/kotlin/scripts/t06.sh "export $al=$rustc_word" "export $al= (a CARGO_ALIAS_* variable)"
quoted_case name-toolchain bindings/swift/scripts/t06.sh "$tc=nightly cargo build" "$tc=nightly cargo build"
quoted_case name-toolchain-gradle "$kts" "environment(\"$tc\", \"nightly\")" "environment(\"$tc\", ...) in a .kts file"
new_case names-pass
append_to bindings/kotlin/scripts/t06.sh "echo \"\$$tc\"
CARGO_PKG_VERSION=1 PROFILE=release rustup show"
expect_pass "a read of \$$tc and other CARGO_ names"

# F. polyjose.jniLibsDir set in a .properties file (security audit L3); reading it stays allowed.
new_case jnilibs-gradle-properties
append_to bindings/kotlin/gradle.properties "$jl=/tmp/libs"
expect_fail "$jl= in bindings/kotlin/gradle.properties" "^  - bindings/kotlin/gradle\\.properties:[0-9]+: $jl=" "$rule2"
new_case jnilibs-separators
append_to bindings/kotlin/android/t06.properties "$jl : /tmp/libs
  $jl /tmp/libs"
expect_fail "$jl with a ':' separator in another .properties file" "^  - bindings/kotlin/android/t06\\.properties:1: " "$rule2"
expect_also "and with a whitespace separator" "^  - bindings/kotlin/android/t06\\.properties:2: "
new_case jnilibs-pass
append_to bindings/kotlin/gradle.properties "${jl}Note=x
polyjose.other=1"
append_to bindings/kotlin/t06.md "$jl=<dir>"
expect_pass "other properties, and $jl=<dir> in a Markdown file"

# G. Round-2 tester pins (feature 0030 T06, second task test): behaviours that held under probing.
quoted_case r2-flow-map "$yml" "    env: {$rf: x}" "a flow mapping env: {$rf: x} in a workflow"
new_case r2-kotlin-rawstring-line-where
plant bindings/kotlin/t06.kt 'val s = """\n//usr/bin/env %s=-Cx cargo build\n"""\n' "$rf"
expect_fail "the same line is reported at line 2" "^  - bindings/kotlin/t06\\.kt:2: //usr/bin/env" "$rule2"
quoted_case r2-dashdash-nightly scripts/t06.sh "cargo +nightly $rustc_word $dd -Clinker=x" "cargo +nightly $rustc_word $dd"
quoted_case r2-dashdash-two-spaces scripts/t06.sh "cargo  $rustc_word $dd -Clinker=x" "cargo, two spaces, $rustc_word $dd"
new_case r2-dashdash-tab
plant scripts/t06.sh 'cargo\t%s\t%s\t-Clinker=x\n' "$rustc_word" "$dd"
expect_fail "cargo, tab, $rustc_word, tab, $dd" "^  - scripts/t06\\.sh:1: cargo" "$rule2"
quoted_case r2-dashdash-env scripts/t06.sh "env X=1 cargo $rustc_word -p a $dd -Clinker=x" "env X=1 cargo $rustc_word ... $dd"
quoted_case r2-dashdash-nested bindings/kotlin/t06.gradle.kts \
  "commandLine($qcargo, \"$rustc_word\", listOf(\"a\", foo(bar(\"b\"))), \"a)b\", \"$dd\", \"-C\")" \
  "a Gradle commandLine with nested brackets and a string holding ) before \"$dd\""
quoted_case r2-dashdash-escaped-quote bindings/kotlin/t06.gradle.kts \
  "commandLine($qcargo, \"$rustc_word\", \"\\\")\", \"$dd\", \"-C\")" \
  "a Gradle commandLine with an escaped quote and ) in a string before \"$dd\""
quoted_case r2-dashdash-char-literal bindings/kotlin/t06.gradle.kts \
  "commandLine($qcargo, \"$rustc_word\", ')', \"$dd\", \"-C\")" \
  "a Gradle commandLine with a Kotlin char literal ')' before \"$dd\""
new_case r2-dashdash-unbalanced-eof
append_to bindings/kotlin/t06.gradle.kts "commandLine($qcargo, \"$rustc_word\", \"x\"
foo
cargo $rustc_word $dd -C linker=x"
expect_fail "an unclosed commandLine( at the end of the file (fails closed)" "^  - bindings/kotlin/t06\\.gradle\\.kts:3: cargo" "$rule2"
new_case r2-cfg-line-variants
edit_in "$cfg_file" "$cfg_line" "$cfg_line"$'\r'
expect_fail "the check-test-vectors-off.sh cargo $rustc_word line with a CR at its end" "^  - scripts/check-test-vectors-off\\.sh:[0-9]+: if ! cfgs=" "$rule2"
new_case r2-cfg-line-altered
edit_in "$cfg_file" "$cfg_line" "${cfg_line/--print cfg/-C linker=x}"
expect_fail "the check-test-vectors-off.sh line with another rustc argument" "^  - scripts/check-test-vectors-off\\.sh:[0-9]+: if ! cfgs=" "$rule2"
new_case r2-cfg-line-twice
edit_in "$cfg_file" "$cfg_line" "$cfg_line"$'\n'"$cfg_line"
expect_fail "the check-test-vectors-off.sh line twice" "^  - scripts/check-test-vectors-off\\.sh:[0-9]+: if ! cfgs=" "$rule2"
new_case r2-utf8-lookalikes-pass
plant bindings/node/t06.js 'caf\303\205 \342\204\205 \342\200\246 \303\205\302\250 x\n'
expect_pass "UTF-8 text with bytes next to the NEL, LS and PS sequences but no line break"
new_case r2-continuation-breaks-pass
append_to scripts/t06.sh "cargo $rustc_word --lib \\
  # a comment line ends the continuation
  $dd not-a-cargo-argument
cargo $rustc_word --lib \\

$dd another"
expect_pass "$dd after a comment line or a blank line that ends a cargo $rustc_word continuation (a separate command)"

# H. Fix round 3 (feature 0030 T06: follow-up audit of 0a7be3ae F1-F5, bug B02, round-2 tester (c)).
# A `#` is a comment only as the first piece of a line that does not continue the one above, after
# spaces and tabs only: a shell ends a line at LF only, and FF, VT and CR are no blanks to it.
plant_case f1-cr-hash bindings/kotlin/scripts/t06.sh '1: : <CR>#; export' \
  "F1: ': <CR>#; export $rf=-Cx' in a .sh file (a CR does not end a shell line)" ': \r#; export %s=-Cx\n' "$rf"
plant_case f2-continued-hash bindings/swift/scripts/t06.sh '2: #; export' \
  "F2: a # line after 'echo x\\' (it continues the command, no comment)" 'echo x\\\n#; export %s=-Cx\n' "$rf"
plant_case f2-ff-indent scripts/t06.sh '1: .#; export' \
  "F2: a # after a form feed (not a shell comment)" '\f#; export %s=-Cx\n' "$rf"
plant_case f2-vt-indent bindings/node/scripts/t06.sh '1: .#; export' \
  "F2: a # after a vertical tab (not a shell comment)" '\v#; export %s=-Cx\n' "$rf"
plant_case f2-cr-indent bindings/wasm/scripts/t06.sh '1: <CR>#; export' \
  "F2: a # after a CR at the start of a line (not a shell comment)" '\r#; export %s=-Cx\n' "$rf"
new_case hash-indented-pass
plant bindings/kotlin/scripts/t06.sh '  # export %s=x before running\n\t# %s: x\n' "$rf" "$rw"
expect_pass "indented # comments (spaces, a tab) naming a variable in a .sh file"

# B02: closing brackets are counted without any comment style, whatever the file type.
new_case b02-python-unbalanced
append_to bindings/node/scripts/t06.py "subprocess.run([
  $qcargo,
  \"$rustc_word\",
  # note )
  \"$dd\",
  \"-C\", \"linker=x\",
])"
expect_fail "B02: a # comment holding ) inside a Python argv list, then \"$dd\"" \
  "^  - bindings/node/scripts/t06\\.py:5:   \"$dd\"" "$rule2"
new_case b02-ruby-inline
append_to bindings/swift/scripts/t06.rb "system($qcargo, \"$rustc_word\", # see )
  \"$dd\", \"-C\", \"linker=x\")"
expect_fail "B02: a Ruby # comment holding ) after \"$rustc_word\", then \"$dd\" on the next line" \
  "^  - bindings/swift/scripts/t06\\.rb:2:   \"$dd\"" "$rule2"
new_case b02-python-balanced
append_to bindings/node/scripts/t06.py "subprocess.run([
  $qcargo,
  \"$rustc_word\",
  # (see note)
  \"$dd\",
  \"-C\", \"linker=x\",
])"
expect_fail "B02: a balanced # (see note) comment inside a Python argv list, then \"$dd\"" \
  "^  - bindings/node/scripts/t06\\.py:5:   \"$dd\"" "$rule2"
new_case b02-pass
append_to bindings/node/scripts/t06.py "subprocess.run([
  $qcargo,
  \"$rustc_word\",
  # (see note)
  \"-p\", \"x\",
])
# note ) after the list
sep = [\"$dd\"]"
expect_pass "a balanced # (see note) in a Python list without $dd; a # ) comment and a $dd after it closes"

# F4: an `@` argument file after cargo rustc or rustdoc (rustc reads arguments from it, no `--`).
quoted_case f4-at-line scripts/t06.sh "cargo $rustc_word --lib @flags.txt" "F4: cargo $rustc_word --lib @flags.txt"
new_case f4-at-continuation
append_to bindings/swift/scripts/t06.sh "cargo $rustc_word --lib \\
  @flags.txt"
expect_fail "F4: @flags.txt on the continuation line of a cargo $rustc_word command" \
  "^  - bindings/swift/scripts/t06\\.sh:2:   @flags" "$rule2"
quoted_case f4-at-list "$kts" "commandLine($qcargo, \"$rustdoc_word\", \"-p\", \"x\", \"@flags\")" \
  "F4: \"@flags\" in a Gradle commandLine of cargo $rustdoc_word"
new_case f4-at-pass
append_to scripts/t06.sh "git show @{u}
echo \"@here\""
expect_pass "@ on lines that are not a cargo $rustc_word command (git show @{u}, \"@here\")"

# F5: the assignment rules read a line's pieces joined, so a CR or LS between a name and its = or :
# (whitespace in JavaScript) still matches.
plant_case f5-cr-eq bindings/node/test/t06.ts '1: process[.]env[.]' \
  "F5: process.env.$rf<CR>= ... in a .ts file" 'process.env.%s\r= "-Cx";\n' "$rf"
plant_case f5-ls-eq bindings/wasm/js/t06.mjs '1: process[.]env[.]' \
  "F5: process.env.$rf<LS>= ... in a .mjs file" 'process.env.%s\342\200\250= "-Cx";\n' "$rf"
plant_case f5-cr-colon bindings/node/test/t06.ts '1: spawn' \
  "F5: { $rf<CR>: ... } in a .ts object" 'spawn("x", { env: { %s\r: "-Cx" } });\n' "$rf"

# Round-2 tester (c): polyjose.jniLibsDir, a backslash continuation, then the separator.
new_case jnilibs-backslash
plant bindings/kotlin/gradle.properties '%s\\\n=/tmp/libs\n' "$jl"
expect_fail "$jl, a \\ continuation, then =" "^  - bindings/kotlin/gradle\\.properties:[0-9]+: ${jl//./\\.}\\\\$" "$rule2"

# I. Round-3 tester pins (feature 0030 T06, third task test): behaviours that held under probing.
new_case i-kts-line-comment-closer
append_to "$kts" "commandLine($qcargo, \"$rustc_word\",
  // )
  \"$dd\", \"-C\", \"linker=x\")"
expect_fail "a // comment holding ) inside a Gradle list, then \"$dd\"" "^  - ${kts//./\\.}:3:   \"$dd\"" "$rule2"
new_case i-kts-block-comment-closer
append_to "$kts" "commandLine($qcargo, \"$rustc_word\",
  /* ) */
  \"$dd\", \"-C\", \"linker=x\")"
expect_fail "a /* ) */ comment inside a Gradle list, then \"$dd\"" "^  - ${kts//./\\.}:3:   \"$dd\"" "$rule2"
new_case i-kts-string-closer
append_to "$kts" "commandLine($qcargo, \"$rustc_word\",
  \"a)\",
  \"$dd\", \"-C\", \"linker=x\")"
expect_fail "a \")\" string inside a Gradle list, then \"$dd\"" "^  - ${kts//./\\.}:3:   \"$dd\"" "$rule2"
new_case i-python-bracket-comment
append_to bindings/node/scripts/t06.py "subprocess.run([
  $qcargo,
  \"$rustc_word\",
  # ]
  \"$dd\",
])"
expect_fail "a # ] comment inside a Python argv list, then \"$dd\"" "^  - bindings/node/scripts/t06\\.py:5:   \"$dd\"" "$rule2"
plant_case i-ls-hash-extensionless scripts/t06-noext '1: : .*#; export' \
  "a # after an LS in a file without an extension (shell code: LS is no line end for the shell)" ': \342\200\250#; export %s=-Cx\n' "$rf"
plant_case i-nel-colon bindings/node/test/t06.ts '1: spawn' \
  "{ $rf<NEL>: ... } in a .ts object" 'spawn("x", { env: { %s\302\205: "-Cx" } });\n' "$rf"
quoted_case i-at-nightly scripts/t06.sh "cargo +nightly $rustc_word @flags.txt" "an @ argument file after cargo +nightly $rustc_word"
quoted_case i-at-rustdoc scripts/t06.sh "cargo $rustdoc_word @flags.txt" "an @ argument file after cargo $rustdoc_word"
new_case i-at-pass
append_to scripts/t06.sh "cargo build -p x @flags.txt
cargo test @flags.txt"
expect_pass "an @ word on cargo build and cargo test lines (no rustc argument file)"
new_case i-crlf-pass
plant scripts/t06.sh 'echo ok\r\n# note\r\nls\r\n'
expect_pass "a CRLF-ended script with only allowed lines"
new_case i-crlf-fail
plant scripts/t06.sh 'echo ok\r\nexport %s=x\r\n' "$rf"
expect_fail "a CRLF-ended script with an assignment on its second line" "^  - scripts/t06\\.sh:2: export $rf=x" "$rule2"

# J. Fix round 4 (feature 0030 T06: final audit B-1, L-1, L-4).
# B-1: the depth is also walked from the line's start, so a list that opens after another one closed
# on the same line stays open.
new_case j-b1-kts-if
append_to "$kts" "if (listOf($qcargo).isNotEmpty()) commandLine($qcargo, \"$rustc_word\",
    \"$dd\", \"-Cx\")"
expect_fail "B-1: listOf($qcargo) in an if, then commandLine($qcargo, \"$rustc_word\", and \"$dd\" next" \
  "^  - ${kts//./\\.}:2:     \"$dd\"" "$rule2"
new_case j-b1-js-assert
append_to bindings/node/scripts/t06.mjs "assert(ok(which($qcargo))); run([$qcargo, \"$rustc_word\",
  \"$dd\", \"-C\", \"x\"])"
expect_fail "B-1: assert(ok(which($qcargo))); run([$qcargo, \"$rustc_word\", then \"$dd\" next" \
  "^  - bindings/node/scripts/t06\\.mjs:2:   \"$dd\"" "$rule2"
new_case j-b1-reopen
append_to "$kts" "run1([$qcargo, \"build\",
  \"--release\"])); run2($qcargo, \"$rustc_word\",
  \"$dd\", \"-Cx\")"
expect_fail "B-1: a list that closes, then run2($qcargo, \"$rustc_word\", on its line, then \"$dd\" next" \
  "^  - ${kts//./\\.}:3:   \"$dd\"" "$rule2"
new_case j-b1-pass
append_to "$kts" "commandLine($qcargo, \"$rustc_word\", \"-p\", \"x\"); exec(listOf(\"git\"))
val a = listOf(\"git\", \"$dd\")"
expect_pass "a cargo $rustc_word list closed on its line (another call after it), then an unrelated \"$dd\" list"
# L-1: both string kinds are taken out in one pass.
new_case j-l1-python
plant bindings/node/scripts/t06.py 'cmd = [%s, "%s", %s"%s and "--lib",  # " ]\n   "%s", "-Cx"]\n' \
  "$qcargo" "$rustc_word" "'" "'" "$dd"
expect_fail "L-1: a single-quoted double quote, then a # \" ] comment, in a Python list, then \"$dd\" next" \
  "^  - bindings/node/scripts/t06\\.py:2:    \"$dd\"" "$rule2"
# L-4: a guarded name as a JavaScript or TypeScript template literal (\140 is the backtick).
plant_case j-l4-ts bindings/node/test/t06.ts '1: process[.]env[[].RUST' \
  "L-4: process.env[<backtick>$rf<backtick>] = ... in a .ts file" 'process.env[\140%s\140] = "-Cx";\n' "$rf"
plant_case j-l4-escaped bindings/wasm/js/t06.mjs '1: eval' \
  "L-4: an escaped closing backtick around $rf inside a template literal" 'eval(\140process.env[\\\140%s\\\140] = 1\140);\n' "$rf"
new_case j-l4-pass
plant bindings/node/test/t06.ts 'const d = process.env[\140CARGO_MANIFEST_DIR\140];\nconsole.log(\140set %s first\140, \140%s_NOTE\140);\n' "$rf" "$rf"
expect_pass "template literals with a non-guarded name, a guarded name in a longer text, and NAME_NOTE"

echo "$((tests_run - tests_failed))/$tests_run cases passed"
completed=1; exit "$((tests_failed > 0))"
