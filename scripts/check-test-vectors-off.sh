#!/usr/bin/env bash
# Fails if any binding crate's dependency graph enables polyjose's `test-vectors` feature.
#
# That feature exposes a deterministic byte source for reproducing published test vectors and
# must never ship (ADR 0005). Every crate under bindings/ is checked on every target, so a
# binding (or a dependency of one) can't turn it on silently.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
for manifest in bindings/*/Cargo.toml; do
  pkg=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$manifest" | head -n 1)
  [ -n "$pkg" ] || { echo "FAIL: no package name in $manifest"; status=1; continue; }
  # --target all includes target-specific dependencies (e.g. wasm32-only ones).
  if ! tree=$(cargo tree --locked -e features -p "$pkg" --target all 2>&1); then
    echo "FAIL: cargo tree failed for $pkg:"; echo "$tree"; status=1; continue
  fi
  # Guard against a vacuous pass: the binding must actually depend on polyjose.
  if ! grep -q 'polyjose v' <<<"$tree"; then
    echo "FAIL: $pkg does not depend on polyjose; check the script"; status=1; continue
  fi
  if grep -n 'test-vectors' <<<"$tree"; then
    echo "FAIL: $pkg enables polyjose's test-vectors feature (ADR 0005)"; status=1
  else
    echo "ok: $pkg does not enable test-vectors"
  fi
done
exit $status
