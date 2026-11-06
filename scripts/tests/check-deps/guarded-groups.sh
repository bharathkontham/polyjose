#!/usr/bin/env bash
# Negative test of check 5 of scripts/check-deps.sh: the guarded allowlist groups (ADR 0025,
# ADR 0042 §2). A crate of a guarded group may be reached only through its required parent crate,
# so each change below, which opens a second path to one, must make check-deps.sh fail with the
# guard's message (and no other check's):
#   - a direct dependency of the core on `semver` (dalek-build: only below curve25519-dalek);
#   - a direct dependency on `syn` (dalek-proc-macro: only below curve25519-dalek-derive);
#   - a direct dependency on `autocfg` (num-traits-build: only below num-traits).
# The unchanged tree must pass. Usage: scripts/tests/check-deps/guarded-groups.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

guard='is reached without going through'

new_case clean
expect_pass "unchanged tree"

new_case semver
add_core_dependency 'semver = { version = "1", default-features = false }'
expect_fail "direct core dependency on semver" \
  "FAIL: semver \\(group dalek-build in deps-allowlist.txt\\) $guard curve25519-dalek .*: polyjose -> semver$" "$guard"

new_case syn
add_core_dependency 'syn = { version = "2", default-features = false }'
expect_fail "syn reached outside curve25519-dalek-derive" \
  "FAIL: syn \\(group dalek-proc-macro in deps-allowlist.txt\\) $guard curve25519-dalek-derive .*: polyjose -> syn$" "$guard"

new_case autocfg
add_core_dependency 'autocfg = { version = "1", default-features = false }'
expect_fail "autocfg reached outside num-traits" \
  "FAIL: autocfg \\(group num-traits-build in deps-allowlist.txt\\) $guard num-traits .*: polyjose -> autocfg$" "$guard"

finish
