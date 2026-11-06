#!/usr/bin/env bash
# Negative compile test for the FixedRng source of rng::CryptoRngAdapter (ADR 0005, ADR 0041 §3).
#
# `CryptoRngAdapter::fixed` and the `Source::Fixed` variant exist only in polyjose's own tests and
# with its test-vectors cargo feature. This test proves that a normal build cannot name either:
#   1. In a copy of the working tree, a probe that names both is appended to crates/polyjose/src/rng.rs.
#   2. Negative: `cargo check -p polyjose --lib` (no features, not a test build) must fail, with
#      E0599 for `fixed` and for `Fixed`, and with no other error code.
#   3. Positive controls, so the probe is not vacuous: the same probe compiles with --all-features
#      (the feature on) and in the test profile (cfg(test) on).
# The real checkout is never modified. The feature's name is not spelled here, so the guard's
# check 4 (scripts/check-test-vectors-off.sh) still sees it only in its allowed homes.
# Usage: scripts/tests/check-test-vectors-off/fixed-adapter-unreachable.sh
# Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
export LC_ALL=C CARGO_TERM_COLOR=never

repo=$(cd "$(dirname "$0")/../../.." && pwd -P)
die() { echo "ERROR: $*" >&2; exit 2; }
command -v git >/dev/null 2>&1 || die "git not found on PATH"
command -v cargo >/dev/null 2>&1 || die "cargo not found on PATH"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/fixed-adapter-test.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$scratch"' EXIT

# A copy of the working tree: tracked and untracked files, not ignored ones (so no target/).
copy="$scratch/tree"
mkdir "$copy"
(cd "$repo" && git ls-files -z --cached --others --exclude-standard) >"$scratch/files.z" \
  || die "git ls-files failed in $repo"
# shellcheck disable=SC2016 # the inner script expands its own "$f"
(cd "$repo" && xargs -0 sh -c 'for f; do [ -e "$f" ] && printf "%s\0" "$f"; done; true' sh \
  <"$scratch/files.z") >"$scratch/present.z" || die "could not list the working tree"
(cd "$repo" && tar --null -T "$scratch/present.z" -cf -) | (cd "$copy" && tar -xf -) \
  || die "could not copy the working tree"

rng="$copy/crates/polyjose/src/rng.rs"
grep -q 'pub(crate) struct CryptoRngAdapter' "$rng" || die "CryptoRngAdapter not found in rng.rs; check the test"
cat >>"$rng" <<'EOF'

/// Probe: names the FixedRng source of the adapter from non-test code.
pub(crate) fn fixed_source_probe() {
    let _constructor = CryptoRngAdapter::fixed;
    let _variant = Source::Fixed;
}
EOF

# Share the real target directory so registry dependencies are not rebuilt; the copy's polyjose
# has another path, so its artifacts never replace the checkout's.
export CARGO_TARGET_DIR="$repo/target"
failed=0
check() { (cd "$copy" && cargo check --locked --offline -p polyjose --lib "$@") >"$scratch/out" 2>&1; }

if check; then
  echo "FAIL - a build without features or cfg(test) can name CryptoRngAdapter::fixed / Source::Fixed"
  failed=1
else
  codes=$(grep -oE '^error\[E[0-9]{4}\]' "$scratch/out" | sort -u | tr '\n' ' ')
  # shellcheck disable=SC2016 # the backticks are rustc's, matched literally
  if [ "$codes" = "error[E0599] " ] \
    && grep -Eq '^error\[E0599\]: no .* named `fixed` found for struct `CryptoRngAdapter' "$scratch/out" \
    && grep -Eq '^error\[E0599\]: no .* named `Fixed` found for enum `(rng::)?Source' "$scratch/out"; then
    echo "ok   - without features or cfg(test), CryptoRngAdapter::fixed and Source::Fixed do not exist (E0599)"
  else
    echo "FAIL - the probe failed to compile, but not only because fixed/Fixed are missing (codes: ${codes:-none}):"
    sed 's/^/       /' "$scratch/out"
    failed=1
  fi
fi

for mode in "--all-features" "--profile test"; do
  # shellcheck disable=SC2086 # the mode is two words on purpose
  if check $mode; then
    echo "ok   - the probe compiles with $mode (positive control)"
  else
    echo "FAIL - the probe does not compile with $mode, so the negative case proves nothing:"
    sed 's/^/       /' "$scratch/out"
    failed=1
  fi
done

[ "$failed" -eq 0 ] && echo "3/3 cases passed"
exit "$failed"
