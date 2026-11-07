#!/usr/bin/env bash
# Negative test of deny.toml's one `cc` exception (feature 0006 T02, owner-approved at Gate 2):
# `{ name = "cc", wrappers = ["minicov"] }`. cargo-deny allows a banned crate only when every crate
# that depends on it directly is a listed wrapper (cargo-deny 0.20 src/bans.rs), so cc must stay
# banned (ADR 0002) whenever anything but minicov reaches it. Each case runs
# `cargo deny check bans` on a scratch copy of the working tree:
#
# Must pass:
#   1. the unchanged tree, where cc's only direct dependent is minicov (below wasm-bindgen-test,
#      a dev-dependency of bindings/wasm);
# Must fail, on the cc ban and nothing else:
#   2. cc as a build-dependency of crates/polyjose: reached through a crate other than minicov;
#   3. cc as a dev-dependency of bindings/wasm, beside minicov: one allowed and one other direct
#      dependent, which the wrapper must not cover.
#
# Offline only: the planted dependency is the cc version Cargo.lock already pins, resolved from the
# local registry cache (`cargo metadata --offline`), and cargo-deny runs with `--offline`. If that
# can't work here (no cargo-deny, cc not cached), the script prints `SKIPPED (<reason>)` as its last
# line and exits 2: scripts/test-all.sh's negative step reads the exit status only, so a skip shows
# as FAIL there, never as a vacuous PASS.
#
# Usage: scripts/tests/deny/cc-wrapper.sh
set -euo pipefail
export LC_ALL=C

skip() { echo "SKIPPED ($*)"; exit 2; }
command -v cargo-deny >/dev/null 2>&1 || skip "cargo-deny not on PATH; cargo install cargo-deny"

# The working-tree copy (new_case, $case_dir, $scratch, finish) of the check-deps negative tests.
# shellcheck source=../check-deps/lib.sh
. "$(dirname "$0")/../check-deps/lib.sh"

# The cc version Cargo.lock pins (minicov's build-dependency), so planting it needs no download.
cc_version=$(python3 -I -c '
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
versions = re.findall(r"\[\[package\]\]\nname = \"cc\"\nversion = \"([^\"]+)\"", text)
print(versions[0] if len(versions) == 1 else "")
' "$repo/Cargo.lock")
[ -n "$cc_version" ] || lib_die "Cargo.lock does not pin exactly one cc (expected minicov's build-dependency)"

# add_dependency <manifest in the copy> <table> <toml line>: adds the line under the table, which
# must exist exactly once, then relocks the copy offline.
add_dependency() {
  python3 -I -c '
import sys
path, table, line = sys.argv[1:4]
with open(path, encoding="utf-8") as f:
    text = f.read()
header = "\n[%s]\n" % table
if text.count(header) == 1:
    text = text.replace(header, header + line + "\n", 1)
elif header not in text:
    text = text.rstrip("\n") + "\n" + header + line + "\n"
else:
    sys.exit("more than one [%s] in %s" % (table, path))
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
' "$case_dir/$1" "$2" "$3" || lib_die "could not edit $1 in the copy"
  (cd "$case_dir" && cargo metadata --offline --format-version 1 >/dev/null 2>"$scratch/relock.err") || {
    cat "$scratch/relock.err" >&2
    skip "cc $cc_version did not resolve offline from the local registry cache (cargo fetch first)"
  }
}

run_deny() { (cd "$case_dir" && cargo deny --offline --all-features check bans) >"$scratch/out" 2>&1; }

# expect_deny_pass <description>
expect_deny_pass() {
  local rc=0
  tests_run=$((tests_run + 1))
  run_deny || rc=$?
  if [ "$rc" -eq 0 ] && grep -q 'bans ok' "$scratch/out"; then
    echo "ok   - $1: cargo deny check bans passes"
  else
    echo "FAIL - $1: cargo deny exited $rc, expected 0 with \"bans ok\""
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

# expect_cc_banned <description> <direct dependent that must be named>: cargo-deny exits non-zero,
# its only error is the cc ban, and the dependency path it prints names the planted dependent.
expect_cc_banned() {
  local rc=0 errors
  tests_run=$((tests_run + 1))
  run_deny || rc=$?
  errors=$(grep -E '^error(\[|:)' "$scratch/out" || true)
  if [ "$rc" -ne 0 ] && [ -n "$errors" ] \
    && ! grep -Ev "^error\[banned\]: crate 'cc = $cc_version' is explicitly banned$" <<<"$errors" | grep -q . \
    && grep -Eq -- "$2" "$scratch/out"; then
    echo "ok   - $1: cargo deny fails on the cc ban"
    sed 's/^/       /' <<<"$errors"
  else
    echo "FAIL - $1: exit $rc; wanted only the cc ban as an error, and output matching /$2/"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

new_case unchanged
expect_deny_pass "the unchanged tree (cc only below minicov)"

new_case core-build-dependency
add_dependency crates/polyjose/Cargo.toml build-dependencies "cc = \"=$cc_version\""
expect_cc_banned "cc as a build-dependency of crates/polyjose" '\(build\) polyjose v'

new_case beside-minicov
add_dependency bindings/wasm/Cargo.toml dev-dependencies "cc = \"=$cc_version\""
expect_cc_banned "cc as a dev-dependency of bindings/wasm, beside minicov" '\(dev\) polyjose-wasm v'

finish
