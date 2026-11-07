#!/usr/bin/env bash
# Regenerates the Kotlin and Swift sources of polyjose-ffi and checks that they contain every name
# of bindings/api-inventory.txt (feature 0013 T12; ADR 0030 §2, §4, §8), then typechecks the Swift.
#
#   bindings/ffi/tests/generated-names.sh [<inventory>]
#
# <inventory> defaults to bindings/api-inventory.txt; another file is for testing this script.
#
# The stand-in for the `kotlin` and `swift` modes of scripts/check-binding-api.sh until features
# 0008 and 0009 add them (they also check for extra names; this script checks containment only).
#
# Steps:
#   1. builds polyjose-ffi alone (`-p polyjose-ffi`, so uniffi's `cli` feature is not unified into
#      it, bindings/ffi/Cargo.toml) and the polyjose-uniffi-bindgen CLI, in two cargo invocations;
#   2. generates Kotlin (`--no-format`) and Swift from the built library, with bindings/ffi/uniffi.toml
#      (Kotlin package dev.polyjose, Swift module Polyjose, ADR 0032 §2, ADR 0033), into a scratch
#      directory that is removed on exit;
#   3. derives from each generated file, in the inventory's normal form, the operations (top-level
#      functions), the records with their fields and the error codes, and requires every inventory
#      entry among them. A field must also have the inventory's form: a required field has no
#      default (so `allowedAlgs` and `allowedEnc` cannot be omitted, ADR 0030 §3), an optional one
#      defaults to null/nil, a flag to false. Each language must also have the exported `code()`
#      (ADR 0030 §5);
#   4. `xcrun swiftc -typecheck` of the generated Swift against its modulemap, with Swift 6 and
#      complete concurrency checking, which must print no diagnostic (ADR 0032 §3). Without xcrun
#      this step prints SKIPPED, which is not a pass (pipeline rule 9).
#
# Exit 0 when every check ran and passed, 1 on a failure, 2 on a setup error. Runs on macOS
# /bin/bash 3.2 and bash 5; needs cargo, awk, sort and comm.
set -uo pipefail
export LC_ALL=C

me=generated-names
repo=$(cd "$(dirname "$0")/../../.." && pwd -P) || exit 2
inventory=${1:-$repo/bindings/api-inventory.txt}
case $inventory in /*) ;; *) inventory=$PWD/$inventory ;; esac
[ -f "$inventory" ] || { echo "$me: no inventory $inventory"; exit 2; }
scratch=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-ffi-generated-names.XXXXXX") || exit 2
trap 'rm -rf "$scratch"' EXIT
failed=0

fail() { echo "$me: FAIL: $*"; failed=1; }
indent() { sed 's/^/  /'; }

cd "$repo" || exit 2
cargo build --quiet -p polyjose-ffi || { echo "$me: building polyjose-ffi failed"; exit 2; }
cargo build --quiet -p polyjose-uniffi-bindgen || { echo "$me: building the bindgen failed"; exit 2; }
target_dir=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
lib=
for candidate in "$target_dir/debug/libpolyjose_ffi.dylib" "$target_dir/debug/libpolyjose_ffi.so"; do
  [ -f "$candidate" ] && lib=$candidate && break
done
[ -n "$lib" ] || { echo "$me: no libpolyjose_ffi cdylib under $target_dir/debug"; exit 2; }
bindgen=$target_dir/debug/uniffi-bindgen
"$bindgen" generate "$lib" --language kotlin --no-format --out-dir "$scratch/kotlin" >/dev/null ||
  { echo "$me: Kotlin generation failed"; exit 2; }
"$bindgen" generate "$lib" --language swift --out-dir "$scratch/swift" >/dev/null ||
  { echo "$me: Swift generation failed"; exit 2; }
kotlin=$scratch/kotlin/dev/polyjose/polyjose_ffi.kt
swift=$scratch/swift/Polyjose.swift
[ -f "$kotlin" ] || { echo "$me: no $kotlin (is uniffi.toml's package_name dev.polyjose?)"; exit 2; }
[ -f "$swift" ] || { echo "$me: no $swift (is uniffi.toml's module_name Polyjose?)"; exit 2; }

# The inventory in normal form: op <name> | record <Name> | field <Name>.<name>[?|=false] | code <Code>
awk '
  { sub(/\r$/, ""); line = $0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line) }
  line == "" || line ~ /^#/ { next }
  { split(line, w, /[ \t]+/) }
  w[1] == "op" || w[1] == "code" { print w[1] " " w[2]; next }
  w[1] == "record" { record = w[2]; print "record " record; next }
  w[1] == "field" {
    rest = line; sub(/^field[ \t]+/, "", rest); gsub(/[ \t]+/, "", rest)
    print "field " record "." rest
  }
' "$inventory" | sort -u >"$scratch/inventory"
[ -s "$scratch/inventory" ] || { echo "$me: no entries read from $inventory"; exit 2; }

# Kotlin: `fun \`name\`(` functions; `data class Name (` records whose `var \`f\`: T [= d]` lines are
# the fields, up to the closing `){`; the subclasses `class Code(` of `sealed class
# PolyjoseException`, up to its closing `}`.
awk '
  function field(line,    name) {
    name = line; sub(/^[ \t]*var `/, "", name); sub(/`.*/, "", name)
    if (line ~ / = null[ \t]*$/) return name "?"
    if (line ~ / = false[ \t]*$/) return name "=false"
    if (line ~ / = /) return name "=other"
    return name
  }
  /^data class [A-Za-z0-9]+ \(/ { record = $3; print "record " record; next }
  record != "" && /^\)/ { record = ""; next }
  record != "" && /^[ \t]*var `/ { print "field " record "." field($0); next }
  /^sealed class PolyjoseException/ { errors = 1; next }
  errors && /^}/ { errors = 0; next }
  errors && /^    class [A-Za-z0-9]+\(/ { name = $2; sub(/\(.*/, "", name); print "code " name; next }
  /fun `[A-Za-z0-9]+`\(/ { name = $0; sub(/.*fun `/, "", name); sub(/`.*/, "", name); print "op " name }
' "$kotlin" | sort -u >"$scratch/kotlin.names"

# Swift: `public func name(` functions; `public struct Name: Equatable` records whose fields are
# the parameters of their `public init(...)` (doc comments removed); the `case Code(` cases of
# `enum PolyjoseError`, up to its closing `}`.
awk '
  function fields(text,    n, i, p, name) {
    while (match(text, /\/\*\*([^*]|\*[^\/])*\*\//)) text = substr(text, 1, RSTART - 1) substr(text, RSTART + RLENGTH)
    sub(/^[ \t]*public init\(/, "", text); sub(/\)[ \t]*\{.*$/, "", text)
    n = split(text, parts, ",")
    for (i = 1; i <= n; i++) {
      p = parts[i]; gsub(/^[ \t]+|[ \t]+$/, "", p)
      if (p == "") continue
      name = p; sub(/:.*/, "", name)
      if (p ~ /= nil$/) name = name "?"
      else if (p ~ /= false$/) name = name "=false"
      else if (p ~ /=/) name = name "=other"
      print "field " record "." name
    }
  }
  /^public struct [A-Za-z0-9]+: Equatable/ { record = $3; sub(/:.*/, "", record); print "record " record; next }
  record != "" && /^[ \t]*public init\(/ { init = $0; collecting = 1 }
  collecting && init != $0 { init = init " " $0 }
  collecting && /\)[ \t]*\{[ \t]*$/ { fields(init); collecting = 0; record = ""; init = ""; next }
  collecting { next }
  # UniFFI 0.32.2 writes `public` and `enum PolyjoseError: ...` on two lines.
  /^(public )?enum PolyjoseError[:  ]/ { errors = 1; next }
  errors && /^}/ { errors = 0; next }
  errors && /^[ \t]+case [A-Za-z0-9]+\(/ { name = $2; sub(/\(.*/, "", name); print "code " name; next }
  /^public func [a-z][A-Za-z0-9]*\(/ { name = $3; sub(/\(.*/, "", name); print "op " name }
' "$swift" | sort -u >"$scratch/swift.names"

for language in kotlin swift; do
  missing=$(comm -23 "$scratch/inventory" "$scratch/$language.names")
  if [ -n "$missing" ]; then
    fail "$language: inventory entries missing or in another form (derived $(wc -l <"$scratch/$language.names" | tr -d ' ') names):"
    printf '%s\n' "$missing" | indent
  else
    echo "$me: $language: all $(wc -l <"$scratch/inventory" | tr -d ' ') inventory entries present"
  fi
done
# shellcheck disable=SC2016 # the backticks are Kotlin's, matched literally
grep -q 'fun `code`(): kotlin.String' "$kotlin" || fail "kotlin: no exported code() on PolyjoseException"
grep -q 'public func code() -> String' "$swift" || fail "swift: no exported code() on PolyjoseError"

if command -v xcrun >/dev/null 2>&1; then
  if diagnostics=$(cd "$scratch/swift" && xcrun swiftc -typecheck -swift-version 6 -strict-concurrency=complete \
      -Xcc -fmodule-map-file=PolyjoseFFI.modulemap -I . Polyjose.swift 2>&1); then
    if [ -n "$diagnostics" ]; then
      fail "swift: swiftc -typecheck printed diagnostics:"
      printf '%s\n' "$diagnostics" | indent
    else
      echo "$me: swift: swiftc -typecheck (Swift 6, strict concurrency) passed with no diagnostics"
    fi
  else
    fail "swift: swiftc -typecheck failed:"
    printf '%s\n' "$diagnostics" | indent
  fi
else
  echo "SKIPPED (swift typecheck: xcrun not found)"
fi

if [ "$failed" -ne 0 ]; then
  echo "$me: FAIL"
  exit 1
fi
echo "$me: PASS"
