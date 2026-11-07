#!/usr/bin/env bash
# Fails if anything that builds a binding can turn on polyjose's `insecure-test-vectors` feature.
#
# That feature exposes FixedRng, a deterministic byte source for reproducing published test
# vectors, and must never ship (ADR 0005). Every check fails closed: any cargo or git error, or
# output that doesn't look as expected, is a FAIL, never a pass.
#   1. No bindings/**/Cargo.toml mentions the feature, and each one is a workspace member, so
#      the cargo checks below see it.
#   2. Per binding package: the inverted feature tree of polyjose with ALL of the binding's
#      features on (optional ones too), every dependency kind and every target shows no
#      `insecure-test-vectors` node. A member is skipped only when its whole tree (every
#      dependency kind, all features, every target) holds no polyjose package, as for build
#      tooling such as polyjose-uniffi-bindgen: it cannot enable a feature of a crate it never
#      builds. If that tree cannot be read, the member fails.
#   3. Workspace-wide, with every member's features on: no normal or build edge enables it, so
#      feature unification in a `--workspace` build can't either. polyjose itself is excluded as
#      a root, because --all-features would otherwise switch its own feature on.
#   4. Cargo features are not the only switch: `--cfg feature="..."` in rustflags (a
#      .cargo/config.toml or the environment) or `--features polyjose/...` in a build script or
#      workflow bypasses 1-3. So the name may appear only in crates/polyjose (its manifest,
#      sources and tests), this script and Markdown docs, and not in any *RUSTFLAGS variable.
#      As a backstop that no spelling trick (e.g. a TOML \u escape) can dodge, rustc is asked
#      which cfgs cargo really passes to polyjose on the host with no features on.
#   0. First of all, scripts/check-no-cargo-config.sh: no cargo config file anywhere in the
#      repository. Check 4's scan and backstop see the host only, but a config can set rustflags
#      for one target (`[target.wasm32-unknown-unknown]`, `[target.'cfg(target_os = "android")']`)
#      in a spelling no text scan matches; with no config file at all, that switch is gone.
#   Deliberately obfuscated switches for other targets or in build commands are out of reach of
#   any scan; scripts/ and .github/ changes go through owner review for that reason. A config
#   outside the repository (~/.cargo, parent directories) and the caller's environment remain
#   residual risk (see scripts/check-no-cargo-config.sh).
# Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd); root_physical=$(pwd -P)

# --- 0. No cargo config file in the repository (before any cargo command runs) ---------------------
no_config_rc=0
scripts/check-no-cargo-config.sh || no_config_rc=$?
if [ "$no_config_rc" -ne 0 ]; then
  echo "FAIL: scripts/check-no-cargo-config.sh (exit $no_config_rc); a cargo config can set a cfg for any target"
  exit 1
fi
# The checks parse cargo's output; CI sets CARGO_TERM_COLOR=always, so turn colour off here.
export CARGO_TERM_COLOR=never

feature=insecure-test-vectors
# How cargo prints the feature when it is enabled, in a `-e features` tree.
node="polyjose feature \"$feature\""
# Any spelling of the name, for text scans.
name_re='insecure[-_]test[-_]vectors'

status=0
fail() { echo "FAIL: $*"; status=1; }

# --- Binding packages: workspace members under bindings/ -----------------------------------------
# One line per member: "<name> v<version> [(proc-macro)] (<path>)"; the path is the last group.
if ! members=$(cargo tree --locked --workspace -e normal --depth 0 --prefix none 2>&1); then
  echo "FAIL: cargo tree could not list the workspace members:"; echo "$members"; exit 1
fi
pkgs=(); member_dirs=""
while IFS= read -r line; do
  case $line in *" v"*" ("*")") ;; *) continue ;; esac
  name=${line%% *}; path=${line##*(}; path=${path%)}
  case $path in
    "$root/bindings/"*) rel=${path#"$root/"} ;;
    "$root_physical/bindings/"*) rel=${path#"$root_physical/"} ;;
    *) continue ;;
  esac
  pkgs+=("$name"); member_dirs="$member_dirs$rel
"
done <<<"$members"
# Fail loudly rather than pass vacuously if cargo's output format or the layout changes.
[ ${#pkgs[@]} -gt 0 ] || { echo "FAIL: found no binding packages under bindings/; check the script"; exit 1; }

# --- 1. Binding manifests -------------------------------------------------------------------------
# Tracked and untracked (not ignored) manifests, so a new binding is checked before it is committed.
if ! manifests=$(git ls-files --cached --others --exclude-standard -- ':(glob)bindings/**/Cargo.toml' 2>&1); then
  echo "FAIL: git ls-files failed:"; echo "$manifests"; exit 1
fi
[ -n "$manifests" ] || { echo "FAIL: found no bindings/**/Cargo.toml; check the script"; exit 1; }
while IFS= read -r manifest; do
  [ -f "$manifest" ] || continue # tracked but deleted in the working tree
  if grep -nE "$name_re" "$manifest"; then
    fail "$manifest mentions polyjose's $feature feature (ADR 0005)"
  fi
  if ! grep -Fxq "$(dirname "$manifest")" <<<"$member_dirs"; then
    fail "$manifest is not a workspace member, so the cargo checks can't see it; add it to the workspace"
  fi
done <<<"$manifests"
[ $status -eq 0 ] && echo "ok: no binding manifest mentions $feature, and every one is a workspace member"

# --- 2. Per binding: inverted feature tree, all features, every target -----------------------------
for pkg in "${pkgs[@]}"; do
  # `cargo tree -i polyjose` errors on a member that never builds polyjose (build tooling such as
  # polyjose-uniffi-bindgen, the UniFFI bindgen CLI of feature 0013 T10). Such a member cannot
  # enable a polyjose feature, so it is skipped, but only when its whole tree (every dependency
  # kind, all features, every target) shows it and no polyjose package. Anything else is checked
  # below, and a probe that fails or shows no tree fails the member (ADR 0005).
  if ! whole=$(cargo tree --locked -p "$pkg" -e normal,build,dev --all-features --target all \
    --prefix none 2>&1); then
    echo "$whole"; fail "cargo tree failed for $pkg (its whole tree)"; continue
  fi
  if ! grep -q "^$pkg v" <<<"$whole"; then
    echo "$whole"; fail "the whole tree of $pkg does not show $pkg; check the script"; continue
  fi
  if ! grep -q '^polyjose v' <<<"$whole"; then
    echo "skipped $pkg: polyjose not in its tree (every dependency kind, all features, every target)"
    continue
  fi
  if ! tree=$(cargo tree --locked -e features -i polyjose -p "$pkg" --all-features --target all 2>&1); then
    echo "$tree"; fail "cargo tree failed for $pkg"; continue
  fi
  # Guard against a vacuous pass: the tree must show polyjose and this binding depending on it.
  if ! grep -q '^polyjose v' <<<"$tree" || ! grep -Fq "$pkg v" <<<"$tree"; then
    echo "$tree"; fail "the inverted tree for $pkg does not show it depending on polyjose; check the script"; continue
  fi
  if grep -Fn "$node" <<<"$tree"; then
    fail "$pkg can enable polyjose's $feature feature (ADR 0005)"
  else
    echo "ok: $pkg cannot enable $feature (all features, every target)"
  fi
done

# --- 3. Workspace-wide: no normal or build edge enables it --------------------------------------------
if ! tree=$(cargo tree --locked -e features,normal,build -i polyjose --workspace --exclude polyjose \
  --all-features --target all 2>&1); then
  echo "$tree"; fail "cargo tree failed for the workspace"
elif ! grep -q '^polyjose v' <<<"$tree"; then
  echo "$tree"; fail "the workspace tree does not show polyjose; check the script"
elif grep -Fn "$node" <<<"$tree"; then
  fail "a workspace member enables polyjose's $feature feature through a normal or build dependency (ADR 0005)"
else
  echo "ok: no workspace member enables $feature through a normal or build dependency"
fi

# --- 4. No other switch: the name outside its allowed homes, or in rustflags ----------------------------
rc=0
hits=$(git grep --untracked -n -E "$name_re" -- . \
  ':(exclude)crates/polyjose/Cargo.toml' ':(exclude)crates/polyjose/src' \
  ':(exclude)crates/polyjose/tests' ':(exclude)scripts/check-test-vectors-off.sh' \
  ':(exclude,glob)**/*.md' 2>&1) || rc=$?
case $rc in
  0) echo "$hits"; fail "$feature is named outside crates/polyjose, this script and docs; a build file could enable it" ;;
  1) echo "ok: $feature is named only in crates/polyjose, this script and docs" ;;
  *) echo "$hits"; fail "git grep failed (exit $rc)" ;;
esac
if env | grep -E '^[A-Za-z0-9_]*RUST(DOC)?FLAGS=' | grep -E "$name_re"; then
  fail "a *RUSTFLAGS variable sets $feature as a cfg (ADR 0005)"
else
  echo "ok: no *RUSTFLAGS variable names $feature"
fi
# --print cfg makes rustc report its cfgs and stop; it resolves every cargo config file from here
# up, $CARGO_HOME and the environment.
if ! cfgs=$(cargo rustc --locked -q -p polyjose --lib -- --print cfg 2>&1); then
  echo "$cfgs"; fail "cargo rustc --print cfg failed for polyjose"
elif ! grep -q '^target_os=' <<<"$cfgs"; then
  echo "$cfgs"; fail "rustc printed no cfg list for polyjose; check the script"
elif grep -E "$name_re" <<<"$cfgs"; then
  fail "the cargo configuration passes $feature to polyjose as a cfg on the host (ADR 0005)"
else
  echo "ok: rustc gets no $feature cfg for polyjose on the host"
fi

exit $status
