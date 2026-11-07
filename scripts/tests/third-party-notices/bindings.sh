#!/usr/bin/env bash
# The notices of each binding artifact (ADR 0020 §4) on the real workspace: polyjose-node for
# aarch64-apple-darwin, polyjose-wasm for wasm32-unknown-unknown and polyjose-ffi for
# aarch64-linux-android and aarch64-apple-ios. Each must list exactly the crates of
# `cargo tree -p <package> --target <triple> -e normal,no-proc-macro`, with polyjose's own MIT
# LICENSE, the binding's framework crates and the crypto crates of ADR 0020's table, and no
# build-time-only or dev-only crate.
#
# Offline (cargo --offline): run `cargo fetch --locked` first if the registry cache is cold.
set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
export LC_ALL=C

# ADR 0020's licenses table, without sha1: ADR 0022 keeps SHA-1 out of the core, and
# scripts/check-deps.sh check 10 fails if it ever enters the tree.
crypto="aes aes-gcm aes-kw cbc hmac sha2 pbkdf2 p256 p384 p521 k256 ecdsa elliptic-curve rsa
crypto-bigint zeroize curve25519-dalek ed25519-dalek x25519-dalek subtle getrandom"
# Never linked: procedural macros and the crates only they use, build-dependencies (and build
# scripts' own dependencies), and polyjose's dev-dependencies.
build_only="napi-derive napi-derive-backend wasm-bindgen-macro wasm-bindgen-macro-support
uniffi_macros curve25519-dalek-derive syn quote proc-macro2 napi-build autocfg rustc_version"
dev_only="proptest miniz_oxide base64ct pkcs8 spki pkcs1 pem-rfc7468"

# headings <notices file>: the "<name> <version>" heading of every third-party crate section.
headings() {
  awk -v rule="$rule" 'prev == rule && $0 ~ /^[A-Za-z0-9_-]+ [0-9][^ ]*$/ { print } { prev = $0 }' "$1" | sort
}

# tree_crates <package> <target>: "<name> <version>" of every registry crate in the artifact's
# tree, as cargo prints it; the workspace's own path crates are covered by the polyjose section.
tree_crates() {
  (cd "$repo" && cargo tree --locked --offline -p "$1" --target "$2" -e normal,no-proc-macro \
    --prefix none -f '{p}') |
    sed 's/ (\*)$//' | grep -v ' (/' | sed 's/^\([^ ]*\) v\([^ ]*\)$/\1 \2/' | sort -u
}

check_binding() {
  local pkg=$1 target=$2 frameworks=$3 foreign=$4 out c missing
  out="$scratch/$pkg-$target.txt"
  run_notices "$out" -p "$pkg" --target "$target"
  if [ "$rc" -ne 0 ]; then fail "$pkg $target: the script fails (exit $rc)"; show_log; return; fi
  pass "$pkg $target: the script succeeds"

  if awk -v rule="$rule" 'prev == rule && $0 == "polyjose" { f = 1 } { prev = $0 } END { exit !f }' "$out" \
    && grep -qxF 'Copyright (c) 2026 The polyjose contributors' "$out"; then
    pass "$pkg $target: polyjose's own section with its MIT LICENSE"
  else fail "$pkg $target: no polyjose section with its MIT LICENSE"; fi
  expect_text "$pkg $target: the polyjose section names $pkg" "$out" "$pkg 0."

  # shellcheck disable=SC2086 # word lists
  expect_crates "$pkg $target: framework crates ($frameworks)" "$out" present $frameworks
  # shellcheck disable=SC2086
  expect_crates "$pkg $target: ADR 0020 crypto crates" "$out" present $crypto
  # shellcheck disable=SC2086
  expect_crates "$pkg $target: no other binding's framework ($foreign)" "$out" absent $foreign
  expect_crates "$pkg $target: no sha1 (ADR 0022)" "$out" absent sha1
  # shellcheck disable=SC2086
  expect_crates "$pkg $target: no proc-macro or build-dependency crate" "$out" absent $build_only
  # shellcheck disable=SC2086
  expect_crates "$pkg $target: no dev-dependency crate" "$out" absent $dev_only

  headings "$out" >"$scratch/got.txt"
  tree_crates "$pkg" "$target" >"$scratch/want.txt"
  if [ -s "$scratch/want.txt" ] && cmp -s "$scratch/got.txt" "$scratch/want.txt"; then
    pass "$pkg $target: exactly the crates of cargo tree ($(wc -l <"$scratch/want.txt" | tr -d ' '))"
  else
    fail "$pkg $target: crate sections differ from cargo tree (< notices, > cargo tree)"
    diff "$scratch/got.txt" "$scratch/want.txt" | sed 's/^/    | /'
  fi

  # Every third-party crate section carries at least one license text.
  missing=""
  while read -r c; do
    # shellcheck disable=SC2086 # "<name> <version>" splits into the two arguments
    crate_section "$out" $c | grep -q '^--- License text: ' || missing="$missing [$c]"
  done <"$scratch/got.txt"
  if [ -z "$missing" ]; then pass "$pkg $target: every crate has a license text"
  else fail "$pkg $target: crates without a license text:$missing"; fi
}

check_binding polyjose-node aarch64-apple-darwin "napi napi-sys" "wasm-bindgen uniffi_core"
check_binding polyjose-wasm wasm32-unknown-unknown "wasm-bindgen wasm-bindgen-shared" "napi napi-sys uniffi_core"
check_binding polyjose-ffi aarch64-linux-android "uniffi uniffi_core" "napi napi-sys wasm-bindgen"
check_binding polyjose-ffi aarch64-apple-ios "uniffi uniffi_core" "napi napi-sys wasm-bindgen"

# napi and uniffi_core ship no license file: their single-license expression gets the standard
# text from scripts/licenses/.
node_out="$scratch/polyjose-node-aarch64-apple-darwin.txt"
napi_ver=$(headings "$node_out" | sed -n 's/^napi \(.*\)$/\1/p')
if [ -n "$napi_ver" ] && crate_section "$node_out" napi "$napi_ver" | grep -q '^--- License text: standard MIT' \
  && crate_section "$node_out" napi "$napi_ver" | grep -q '^Permission is hereby granted'; then
  pass "napi (no license file): the standard MIT text"
else fail "napi (no license file): no standard MIT text"; fi
ffi_out="$scratch/polyjose-ffi-aarch64-apple-ios.txt"
uc_ver=$(headings "$ffi_out" | sed -n 's/^uniffi_core \(.*\)$/\1/p')
if [ -n "$uc_ver" ] && crate_section "$ffi_out" uniffi_core "$uc_ver" | grep -q '^--- License text: standard MPL-2.0' \
  && crate_section "$ffi_out" uniffi_core "$uc_ver" | grep -q '^Mozilla Public License Version 2.0$'; then
  pass "uniffi_core (no license file): the standard MPL-2.0 text"
else fail "uniffi_core (no license file): no standard MPL-2.0 text"; fi

finish
