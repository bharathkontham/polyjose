#!/usr/bin/env bash
# A single --target still writes exactly what it wrote before the generator learned repeated
# --target (feature 0013 F14): for each artifact and target that bindings.sh checks, the current
# scripts/third-party-notices.sh and the one of commit $baseline_rev (the feature branch before
# F14) give byte-identical files on today's workspace. A deliberate change to the single-target
# format moves the pin.
#
# Needs the git history of $baseline_rev (any full clone has it). Offline (cargo --offline): run
# `cargo fetch --locked` first if the registry cache is cold.
set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
export LC_ALL=C

baseline_rev=bb65246
base="$scratch/baseline"
mkdir -p "$base"
if git -C "$repo" archive "$baseline_rev" scripts/third-party-notices.sh scripts/licenses | tar -x -C "$base"; then
  pass "the generator of $baseline_rev is available"
else
  fail "the generator of $baseline_rev is not in this clone's history (a shallow clone?)"
  finish; exit
fi

for pt in polyjose-node:aarch64-apple-darwin polyjose-wasm:wasm32-unknown-unknown \
  polyjose-ffi:aarch64-linux-android polyjose-ffi:aarch64-apple-ios; do
  pkg=${pt%%:*} target=${pt#*:}
  want="$scratch/$pkg-$target.before.txt" got="$scratch/$pkg-$target.txt"
  if ! "$base/scripts/third-party-notices.sh" -p "$pkg" --target "$target" -o "$want" \
    --manifest-path "$repo/Cargo.toml" >"$scratch/base.log" 2>&1; then
    fail "$pkg $target: the generator of $baseline_rev fails"; sed 's/^/    | /' "$scratch/base.log"; continue
  fi
  run_notices "$got" -p "$pkg" --target "$target"
  if [ "$rc" -eq 0 ] && cmp -s "$want" "$got"; then pass "$pkg $target: byte-identical to $baseline_rev's output"
  else
    fail "$pkg $target: differs from $baseline_rev's output (exit $rc)"
    show_log
    [ -s "$got" ] && diff "$want" "$got" | head -20 | sed 's/^/    | /'
  fi
done

finish
