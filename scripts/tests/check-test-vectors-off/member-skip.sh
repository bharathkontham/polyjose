#!/usr/bin/env bash
# Negative test of check 2 of scripts/check-test-vectors-off.sh (ADR 0005): which binding members
# the per-member inverted feature tree may skip.
#
# The gate skips a workspace member under bindings/ only when its whole tree (every dependency
# kind, all features, every target) holds no polyjose package, as for build tooling such as
# polyjose-uniffi-bindgen; such a member cannot enable polyjose's test-vector feature at all.
# Every other member is checked, and any cargo failure is a FAIL (fails closed).
#
# Must fail (the member is checked, not skipped):
#   1. a bin-only member that depends on polyjose and turns the feature on;
#   2-3. a member that depends on polyjose only as a dev- or a build-dependency, with the feature.
#   Each spells the feature with a TOML \u escape, so the text scans (checks 1 and 4) do not see
#   it and the cargo trees (checks 2 and 3) are what catch it.
#   4. the whole-tree probe of polyjose-uniffi-bindgen fails (a cargo shim exits 101): no skip.
#   5. the probe exits 0 with no output: no skip on output that does not look like a tree.
# Must pass:
#   6. the unchanged tree: polyjose-uniffi-bindgen is the only member skipped, and every binding
#      (polyjose-ffi, -node, -surface, -wasm) is checked;
#   7. a clean bin-only member with a dependency but no polyjose: skipped;
#   8. a member that reaches polyjose only through another member (polyjose-surface, as a
#      dev-dependency): checked, not skipped.
# The feature's name is not spelled here, so check 4 still sees it only in its allowed homes.
# Usage: scripts/tests/check-test-vectors-off/member-skip.sh
# Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
export LC_ALL=C CARGO_TERM_COLOR=never
# shellcheck source=../check-deps/lib.sh
. "$(dirname "$0")/../check-deps/lib.sh"

gate_name=check-test-vectors-off.sh
# path_prefix puts a cargo shim first on the gate's PATH (cases 4-5); empty otherwise.
path_prefix=""
run_gate() { PATH="$path_prefix$PATH" scripts/check-test-vectors-off.sh; }
# Share the checkout's target directory so polyjose's dependencies are not rebuilt for check 4's
# `cargo rustc`; each copy's polyjose has another path, so its artifacts never replace the checkout's.
export CARGO_TARGET_DIR="$repo/target"

# The feature, as a TOML basic string with \u escapes (cargo reads the real name).
escaped='"insecure\u002Dtest\u002Dvectors"'
probe=polyjose-probe
enable_fail="^FAIL: $probe can enable polyjose's "
any_enable_fail="^FAIL: ($probe can enable polyjose's |a workspace member enables polyjose's )"

# add_probe <manifest body after [package]>: a bin-only workspace member bindings/probe.
add_probe() {
  new_case "$1"
  append_to bindings/probe/Cargo.toml "[package]
name = \"$probe\"
version = \"0.0.0\"
edition = \"2024\"
publish = false

$2"
  append_to bindings/probe/src/main.rs 'fn main() {}'
  replace_in Cargo.toml 'members = [' 'members = ["bindings/probe", '
}

# expect_line <description> <fixed string>: the last run's output has a line that is the string.
expect_line() {
  tests_run=$((tests_run + 1))
  if grep -Fxq -- "$2" "$scratch/out"; then
    echo "ok   - $1: $2"
  else
    echo "FAIL - $1: no line '$2' in the output"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

# expect_no_skip <description> <package>: the last run did not skip the package.
expect_no_skip() {
  tests_run=$((tests_run + 1))
  if grep -q "^skipped $2:" "$scratch/out"; then
    echo "FAIL - $1: $2 was skipped"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  else
    echo "ok   - $1: $2 not skipped"
  fi
}

skip_line() { echo "skipped $1: polyjose not in its tree (every dependency kind, all features, every target)"; }
ok_line() { echo "ok: $1 cannot enable insecure""-test-vectors (all features, every target)"; }

# 1. A bin-only member with polyjose and the feature as a normal dependency.
add_probe normal "[dependencies]
polyjose = { workspace = true, features = [$escaped] }"
expect_fail "bin-only member enabling the feature" "$enable_fail" "$any_enable_fail"
expect_no_skip "bin-only member enabling the feature" "$probe"

# 2-3. polyjose only as a dev- or build-dependency, with the feature.
for kind in dev-dependencies build-dependencies; do
  add_probe "$kind" "[$kind]
polyjose = { workspace = true, features = [$escaped] }"
  if [ "$kind" = build-dependencies ]; then append_to bindings/probe/build.rs 'fn main() {}'; fi
  expect_fail "member enabling the feature in $kind" "$enable_fail" "$any_enable_fail"
  expect_no_skip "member enabling the feature in $kind" "$probe"
done

# 4-5. A cargo shim breaks the whole-tree probe of polyjose-uniffi-bindgen: it exits 101, or it
#      exits 0 and prints nothing. Every other cargo command runs the real cargo.
real_cargo=$(command -v cargo)
shim_dir="$scratch/shim"
mkdir -p "$shim_dir"
for mode in exit-101 empty-output; do
  # Each mode must fail on the probe itself, not on the inverted tree after it.
  case $mode in
    exit-101) action='exit 101'; want='^FAIL: cargo tree failed for polyjose-uniffi-bindgen \(its whole tree\)$' ;;
    *) action='exit 0'; want='^FAIL: the whole tree of polyjose-uniffi-bindgen does not show polyjose-uniffi-bindgen;' ;;
  esac
  cat >"$shim_dir/cargo" <<EOF
#!/bin/sh
probe=0 bindgen=0
for a in "\$@"; do
  case \$a in normal,build,dev) probe=1 ;; polyjose-uniffi-bindgen) bindgen=1 ;; esac
done
if [ "\$probe\$bindgen" = 11 ]; then $action; fi
exec "$real_cargo" "\$@"
EOF
  chmod +x "$shim_dir/cargo"
  new_case "probe-$mode"
  path_prefix="$shim_dir:"
  expect_fail "whole-tree probe of polyjose-uniffi-bindgen: $mode" "$want" "$want"
  expect_no_skip "whole-tree probe of polyjose-uniffi-bindgen: $mode" polyjose-uniffi-bindgen
  path_prefix=""
done

# 6. The unchanged tree.
new_case unchanged
expect_pass "unchanged tree"
expect_line "unchanged tree" "$(skip_line polyjose-uniffi-bindgen)"
tests_run=$((tests_run + 1))
skipped=$(grep -c '^skipped ' "$scratch/out" || true)
if [ "$skipped" = 1 ]; then
  echo "ok   - unchanged tree: only polyjose-uniffi-bindgen is skipped"
else
  echo "FAIL - unchanged tree: $skipped members skipped, expected 1"
  tests_failed=$((tests_failed + 1))
fi
for pkg in polyjose-ffi polyjose-node polyjose-surface polyjose-wasm; do
  expect_line "unchanged tree" "$(ok_line "$pkg")"
done

# 7. A clean bin-only member: a dependency, but no polyjose in its tree.
add_probe clean "[dependencies]
zeroize = { workspace = true }"
expect_pass "clean member"
expect_line "clean member" "$(skip_line "$probe")"

# 8. polyjose reached only through another workspace member.
add_probe indirect "[dev-dependencies]
polyjose-surface = { path = \"../surface\" }"
expect_pass "member reaching polyjose through polyjose-surface"
expect_no_skip "member reaching polyjose through polyjose-surface" "$probe"
expect_line "member reaching polyjose through polyjose-surface" "$(ok_line "$probe")"

# 9-10. polyjose reached only under a renamed dependency key (package = "polyjose"): cargo tree
#       prints the package name, so the member is checked, not skipped.
add_probe renamed-feature "[dependencies]
alias = { package = \"polyjose\", path = \"../../crates/polyjose\", features = [$escaped] }"
expect_fail "renamed polyjose dependency enabling the feature" "$enable_fail" "$any_enable_fail"
expect_no_skip "renamed polyjose dependency enabling the feature" "$probe"
add_probe renamed-clean "[dependencies]
alias = { package = \"polyjose\", path = \"../../crates/polyjose\" }"
expect_pass "renamed polyjose dependency without the feature"
expect_no_skip "renamed polyjose dependency without the feature" "$probe"

# 11. Warning lines around the whole-tree probe of a member that reaches polyjose
#     (polyjose-surface, as a dev-dependency): the member is still checked, never skipped.
cat >"$shim_dir/cargo" <<EOF
#!/bin/sh
probe=0
for a in "\$@"; do
  case \$a in normal,build,dev) probe=1 ;; esac
done
if [ "\$probe" = 1 ]; then
  echo "warning: unused manifest key: noise" >&2
  echo "  polyjose-ish v9.9.9"
  "$real_cargo" "\$@"
  rc=\$?
  echo "warning: trailing noise" >&2
  exit \$rc
fi
exec "$real_cargo" "\$@"
EOF
chmod +x "$shim_dir/cargo"
add_probe noisy "[dev-dependencies]
polyjose-surface = { path = \"../surface\" }"
path_prefix="$shim_dir:"
expect_pass "member reaching polyjose, probe output with warning lines"
expect_no_skip "member reaching polyjose, probe output with warning lines" "$probe"
expect_line "member reaching polyjose, probe output with warning lines" "$(ok_line "$probe")"
path_prefix=""

finish
