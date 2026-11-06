#!/usr/bin/env bash
# Negative test of check 5 of scripts/check-deps.sh: the guarded allowlist groups (ADR 0025,
# ADR 0042 §2, ADR 0049 §5). Each change below must make check-deps.sh fail with check 5's message
# (and, where noted, check 1's; no other check's).
#
# Path rule: a crate of a guarded group may be reached only through its required parent crate.
#   - a direct dependency of the core on `semver` (dalek-build: only below curve25519-dalek);
#   - a direct dependency on `syn` (dalek-proc-macro: only below curve25519-dalek-derive);
#   - a direct dependency on `autocfg` (num-traits-build: only below num-traits).
# Membership rule: each guarded group's members are fixed in check-deps.sh, and deps-allowlist.txt
# must agree with that table.
#   - the audit's case: num-traits' `libm` feature turned on, and `libm` (credited) added to the
#     num-traits-build group, where the path rule alone would accept it;
#   - a crate already in the tree (`cfg-if`) added to the dalek-build group;
#   - a member (`syn`) moved out of its guarded group into an unguarded one;
#   - a member (`autocfg`) removed from deps-allowlist.txt while still in the tree (check 1 too).
# Edge rule: dalek-build and num-traits-build crates are build-dependencies only (absent from
# `cargo tree -e normal`), and dalek-proc-macro crates are reached only through a proc-macro (absent
# from `-e normal,no-proc-macro`). The three direct dependencies above break it too, and:
#   - libm made a num-traits-build member (in the copy's check-deps.sh too, so only this rule is
#     left to catch it) and reached through num-traits' normal `libm` edge;
#   - a direct dependency on `proc-macro2` (dalek-proc-macro).
# The unchanged tree must pass. Usage: scripts/tests/check-deps/guarded-groups.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

guard='is reached without going through'
member='guarded group .*\(ADR 0049 §5'
not_allowed='contains crates that deps-allowlist.txt does not allow'
edge='is in cargo tree -e normal'

# expect_also <description> <ERE>: the output of the last expect_fail also matches the ERE.
expect_also() {
  tests_run=$((tests_run + 1))
  if grep -Eq -- "$2" "$scratch/out"; then
    echo "ok   - $1"
    grep -E -- "$2" "$scratch/out" | head -3 | sed 's/^/       /'
  else
    echo "FAIL - $1: wanted output matching /$2/"
    tests_failed=$((tests_failed + 1))
  fi
}

# credit_crate <crate>: a minimal CREDITS.md entry in the copy, so check 4 stays quiet.
credit_crate() {
  append_to CREDITS.md ''
  append_to CREDITS.md "### \`$1\`"
  append_to CREDITS.md ''
  append_to CREDITS.md "- **Used for:** test entry of scripts/tests/check-deps/guarded-groups.sh."
}

new_case clean
expect_pass "unchanged tree"

# --- Path rule --------------------------------------------------------------------------------------

new_case semver
add_core_dependency 'semver = { version = "1", default-features = false }'
expect_fail "direct core dependency on semver" \
  "FAIL: semver \\(guarded group dalek-build\\) $guard curve25519-dalek .*: polyjose -> semver$" "$guard|$edge"
expect_also "direct core dependency on semver breaks the edge rule too" \
  "FAIL: semver \\(guarded group dalek-build\\) $edge: .*: polyjose -> semver$"

new_case syn
add_core_dependency 'syn = { version = "2", default-features = false }'
expect_fail "syn reached outside curve25519-dalek-derive" \
  "FAIL: syn \\(guarded group dalek-proc-macro\\) $guard curve25519-dalek-derive .*: polyjose -> syn$" "$guard|$edge"
expect_also "direct core dependency on syn breaks the edge rule too" \
  "FAIL: syn \\(guarded group dalek-proc-macro\\) $edge,no-proc-macro: .*: polyjose -> syn$"

new_case autocfg
add_core_dependency 'autocfg = { version = "1", default-features = false }'
expect_fail "autocfg reached outside num-traits" \
  "FAIL: autocfg \\(guarded group num-traits-build\\) $guard num-traits .*: polyjose -> autocfg$" "$guard|$edge"
expect_also "direct core dependency on autocfg breaks the edge rule too" \
  "FAIL: autocfg \\(guarded group num-traits-build\\) $edge: .*: polyjose -> autocfg$"

# --- Membership rule --------------------------------------------------------------------------------

# The audit's reproduction: libm is only below num-traits, so the path rule passes it.
new_case libm-audit
add_core_dependency 'num-traits = { version = "0.2", default-features = false, features = ["libm"] }'
replace_in deps-allowlist.txt $'\nautocfg\n' $'\nautocfg\nlibm\n'
credit_crate libm
expect_fail "libm (num-traits/libm) added to num-traits-build" \
  "FAIL: libm is listed in guarded group num-traits-build in deps-allowlist.txt but is not a member of it" "$member"

new_case cfg-if-added
replace_in deps-allowlist.txt $'\ncfg-if\n' $'\n'
replace_in deps-allowlist.txt $'\nsemver\n' $'\nsemver\ncfg-if\n'
expect_fail "cfg-if added to dalek-build" \
  "FAIL: cfg-if is listed in guarded group dalek-build in deps-allowlist.txt but is not a member of it" "$member"

new_case syn-moved
replace_in deps-allowlist.txt $'\nsyn\n' $'\n'
replace_in deps-allowlist.txt $'\nsha2\n' $'\nsha2\nsyn\n'
expect_fail "syn moved from dalek-proc-macro to primitives" \
  "FAIL: syn is a member of guarded group dalek-proc-macro \\(scripts/check-deps.sh\\) but deps-allowlist.txt lists it in group primitives" "$member"

# The heading is demoted to level 4, which CREDITS.md's parser ignores, so check 4 stays quiet.
new_case autocfg-unlisted
replace_in deps-allowlist.txt $'\nautocfg\n' $'\n'
replace_in CREDITS.md "### \`autocfg\`" '#### autocfg (removed by the test)'
expect_fail "autocfg removed from deps-allowlist.txt while in the tree" \
  "FAIL: autocfg is a member of guarded group num-traits-build \\(scripts/check-deps.sh\\) and in the core's tree, but deps-allowlist.txt does not list it" \
  "$member|$not_allowed"

# --- Edge rule ----------------------------------------------------------------------------------------

# libm is only below num-traits, and a member of num-traits-build in the copy's script and allowlist,
# so the path and membership rules pass it; num-traits' edge to it is a normal one.
new_case libm-normal-edge
add_core_dependency 'num-traits = { version = "0.2", default-features = false, features = ["libm"] }'
replace_in deps-allowlist.txt $'\nautocfg\n' $'\nautocfg\nlibm\n'
replace_in scripts/check-deps.sh $'\nnum-traits-build autocfg num-traits\n' \
  $'\nnum-traits-build autocfg num-traits\nnum-traits-build libm num-traits\n'
credit_crate libm
expect_fail "build-only libm reached through a normal edge" \
  "FAIL: libm \\(guarded group num-traits-build\\) $edge: .*: polyjose -> num-traits -> libm$" "$edge"

new_case proc-macro2
add_core_dependency 'proc-macro2 = { version = "1", default-features = false }'
expect_fail "proc-macro2 reached outside a proc-macro" \
  "FAIL: proc-macro2 \\(guarded group dalek-proc-macro\\) $edge,no-proc-macro: .*: polyjose -> proc-macro2$" "$guard|$edge"

finish
