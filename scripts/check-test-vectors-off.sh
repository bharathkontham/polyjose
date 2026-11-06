#!/usr/bin/env bash
# Fails if any binding crate's dependency graph enables polyjose's `insecure-test-vectors` feature.
#
# That feature exposes a deterministic byte source for reproducing published test vectors and
# must never ship (ADR 0005). Every workspace package under bindings/ is checked on every target
# (cargo lists the packages, so a manifest with several targets or a new binding is covered), and a
# binding (or a dependency of one) can't turn it on silently.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd); root_physical=$(pwd -P)

# One line per workspace member: "<name> v<version> (<path>)". Keep those under bindings/.
members=$(cargo tree --locked --workspace -e normal --depth 0 --prefix none)
pkgs=()
while read -r name _version path; do
  case $path in
    "($root/bindings/"* | "($root_physical/bindings/"*) pkgs+=("$name") ;;
  esac
done <<<"$members"
# Fail loudly rather than pass vacuously if cargo's output format or the layout changes.
[ ${#pkgs[@]} -gt 0 ] || { echo "FAIL: found no binding packages under bindings/; check the script"; exit 1; }

status=0
for pkg in "${pkgs[@]}"; do
  # --target all includes target-specific dependencies (e.g. wasm32-only ones).
  if ! tree=$(cargo tree --locked -e features -p "$pkg" --target all 2>&1); then
    echo "FAIL: cargo tree failed for $pkg:"; echo "$tree"; status=1; continue
  fi
  # Guard against a vacuous pass: the binding must actually depend on polyjose.
  if ! grep -q 'polyjose v' <<<"$tree"; then
    echo "FAIL: $pkg does not depend on polyjose; check the script"; status=1; continue
  fi
  if grep -n 'feature "insecure-test-vectors"' <<<"$tree"; then
    echo "FAIL: $pkg enables polyjose's insecure-test-vectors feature (ADR 0005)"; status=1
  else
    echo "ok: $pkg does not enable insecure-test-vectors"
  fi
done
exit $status
