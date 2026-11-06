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
# The unchanged tree must pass. Usage: scripts/tests/check-deps/guarded-groups.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

guard='is reached without going through'
member='guarded group .*\(ADR 0049 §5'
not_allowed='contains crates that deps-allowlist.txt does not allow'

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
  "FAIL: semver \\(guarded group dalek-build\\) $guard curve25519-dalek .*: polyjose -> semver$" "$guard"

new_case syn
add_core_dependency 'syn = { version = "2", default-features = false }'
expect_fail "syn reached outside curve25519-dalek-derive" \
  "FAIL: syn \\(guarded group dalek-proc-macro\\) $guard curve25519-dalek-derive .*: polyjose -> syn$" "$guard"

new_case autocfg
add_core_dependency 'autocfg = { version = "1", default-features = false }'
expect_fail "autocfg reached outside num-traits" \
  "FAIL: autocfg \\(guarded group num-traits-build\\) $guard num-traits .*: polyjose -> autocfg$" "$guard"

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

finish
