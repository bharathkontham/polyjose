#!/usr/bin/env bash
# Negative test of checks 13 and 14 of scripts/check-deps.sh: the binding dependency allowlists
# (ADR 0030 §1, ADR 0016 §4) and no serde in the bindings (ADR 0030 §1). Each change below must make
# check-deps.sh fail with those checks' messages only.
#
# Check 13: for each bindings/deps-allowlist/<name>.txt whose bindings/<name> exists, the normal tree
# of that package (`cargo tree -e normal --target all`, with default, no-default and all features)
# lists only crates of that file, of deps-allowlist.txt and of the core's tree; the file lists no
# crate the tree lacks and none that deps-allowlist.txt already allows; every bindings/* package has
# a file. Cases: a crate added to polyjose-node, also behind a feature and on a Windows-only target;
# an entry missing, stale or already allowed; node.txt removed; a file whose bindings/<name> is not a
# package; malformed lines; and polyjose-surface, with a fixture package while T01's bindings/surface
# does not exist yet, so surface.txt is not checked vacuously. A file whose bindings/<name> does not
# exist is skipped with a message and passes.
# Check 14: serde, serde_json, serde_derive, serde-wasm-bindgen or any other serde-family crate in the
# normal tree of a bindings/* package fails, unless every path to it goes through a crate that a
# `# serde-only-below:` line of the package's allowlist names (ffi.txt: UniFFI's proc-macro and
# bindgen CLI) and comment lines explain. Cases: serde_json added to polyjose-node (the criterion's
# reproduction), also with the allowlist widened so only check 14 is left; serde_json as a direct
# dependency of polyjose-ffi, whose allowlist lists it below the bindgen; a crate dropped from
# ffi.txt's line, or the line removed; the line with no explanation, unneeded, or naming a crate
# outside the tree; and a core dependency on semver, which polyjose-ffi's build gives a serde edge,
# reported by the core's check 5 only.
# The unchanged tree must pass. Usage: scripts/tests/check-deps/binding-allowlists.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

not_allowed='contains crates that bindings/deps-allowlist/[a-z-]+\.txt does not allow'
serde='is in the normal tree of polyjose-[a-z]+ \(bindings/[a-z]+\)'
format='^FAIL: bindings/deps-allowlist/[a-z-]+\.txt:[0-9]+: '

# expect_also <description> <ERE>: the output of the last expect_pass/expect_fail also matches.
expect_also() {
  tests_run=$((tests_run + 1))
  if grep -Eq -- "$2" "$scratch/out"; then
    echo "ok   - $1"
    grep -E -- "$2" "$scratch/out" | head -3 | sed 's/^/       /'
  else
    echo "FAIL - $1: wanted output matching /$2/"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

# add_dependency <manifest in the copy> <toml line>: adds a line to the manifest's [dependencies]
# and relocks.
add_dependency() {
  python3 -I -c '
import sys
path, line = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    text = f.read()
if "\n[dependencies]\n" not in text:
    sys.exit("no [dependencies] table in %s" % path)
text = text.replace("\n[dependencies]\n", "\n[dependencies]\n" + line + "\n", 1)
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
' "$case_dir/$1" "$2" || lib_die "could not edit $1 in the copy"
  relock
}

# allow_new_crates <dir> <package>: appends to bindings/deps-allowlist/<dir>.txt every crate of the
# package's tree that neither that file, deps-allowlist.txt nor the core's tree covers, so only
# check 14 is left to see a serde crate.
allow_new_crates() {
  (cd "$case_dir" && {
    cargo tree --locked --offline -p polyjose -e normal,build --all-features --target all --prefix none
    grep -v '^[[:space:]]*#' deps-allowlist.txt
    grep -v '^[[:space:]]*#' "bindings/deps-allowlist/$1.txt"
  } | awk 'NF { print $1 }' | tr 'A-Z_' 'a-z-' | sort -u >"$scratch/covered") || lib_die "could not list the covered crates"
  (cd "$case_dir" && cargo tree --locked --offline -p "$2" -e normal --all-features --target all --prefix none) \
    | awk 'NR > 1 { print $1 }' | tr 'A-Z_' 'a-z-' | sort -u | comm -23 - "$scratch/covered" \
    | grep -vx "$2" >>"$case_dir/bindings/deps-allowlist/$1.txt" || lib_die "could not widen $1.txt"
}

# set_directive <path in the copy> <new serde-only-below line>: replaces the file's one line.
set_directive() {
  python3 -I -c '
import re, sys
path, new = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    text = f.read()
text, n = re.subn(r"(?m)^# serde-only-below:.*$", new, text)
if n != 1:
    sys.exit("expected one serde-only-below line in %s, found %d" % (path, n))
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
' "$case_dir/$1" "$2" || lib_die "could not edit $1 in the copy"
}

new_case clean
expect_pass "unchanged tree"
if [ ! -d "$repo/bindings/surface" ]; then
  expect_also "surface.txt is skipped while bindings/surface does not exist" \
    '^skip: bindings/deps-allowlist/surface\.txt: bindings/surface does not exist'
fi

# --- Check 13: the allowlists ---------------------------------------------------------------------------

new_case node-crate
add_dependency bindings/node/Cargo.toml 'base64ct = "1"'
expect_fail "a crate added to polyjose-node" \
  "FAIL: the tree of polyjose-node \\(bindings/node\\) $not_allowed" "$not_allowed"
expect_also "the offending crate is named" '^  - base64ct$'

new_case node-feature
python3 -I -c '
import sys
p = sys.argv[1]
t = open(p).read().replace("\n[dependencies]\n", "\n[features]\nfixture = [\"dep:base64ct\"]\n\n[dependencies]\nbase64ct = { version = \"1\", optional = true }\n", 1)
open(p, "w").write(t)
' "$case_dir/bindings/node/Cargo.toml"
relock
expect_fail "a crate added to polyjose-node behind a feature (--all-features)" \
  "FAIL: the tree of polyjose-node \\(bindings/node\\) $not_allowed" "$not_allowed"

new_case wasm-target
append_to bindings/wasm/Cargo.toml $'\n[target.\'cfg(windows)\'.dependencies]\nbase64ct = "1"'
relock
expect_fail "a crate added to polyjose-wasm on Windows only (--target all)" \
  "FAIL: the tree of polyjose-wasm \\(bindings/wasm\\) $not_allowed" "$not_allowed"

new_case wasm-missing
replace_in bindings/deps-allowlist/wasm.txt $'\nbumpalo\n' $'\n'
expect_fail "bumpalo dropped from wasm.txt" \
  "FAIL: the tree of polyjose-wasm \\(bindings/wasm\\) $not_allowed" "$not_allowed"
expect_also "the missing crate is named" '^  - bumpalo$'

new_case wasm-stale
append_to bindings/deps-allowlist/wasm.txt 'anyhow'
expect_fail "a stale entry in wasm.txt" \
  "FAIL: bindings/deps-allowlist/wasm\\.txt lists crates the tree of polyjose-wasm no longer contains" "no longer contains"
expect_also "the stale crate is named" '^  - anyhow$'

new_case node-core-dup
append_to bindings/deps-allowlist/node.txt 'sha2'
expect_fail "node.txt lists a crate that deps-allowlist.txt allows" \
  "FAIL: bindings/deps-allowlist/node\\.txt lists crates that deps-allowlist\\.txt already allows" "already allows"
expect_also "the duplicated crate is named" '^  - sha2$'

new_case node-unlisted
rm "$case_dir/bindings/deps-allowlist/node.txt"
expect_fail "polyjose-node without bindings/deps-allowlist/node.txt" \
  "FAIL: polyjose-node \\(bindings/node\\) has no bindings/deps-allowlist/node\\.txt" "has no bindings/deps-allowlist"

new_case absent
append_to bindings/deps-allowlist/absent-fixture.txt '# bindings/absent-fixture does not exist.'
append_to bindings/deps-allowlist/absent-fixture.txt 'base64ct'
expect_pass "an allowlist for a binding that does not exist yet"
expect_also "it is skipped with a message" \
  '^skip: bindings/deps-allowlist/absent-fixture\.txt: bindings/absent-fixture does not exist'

new_case not-a-package
append_to bindings/notapackage-fixture/README.md 'Not a cargo package.'
append_to bindings/deps-allowlist/notapackage-fixture.txt '# No Cargo.toml in bindings/notapackage-fixture.'
expect_fail "an allowlist for a bindings/ directory that is not a workspace package" \
  "FAIL: bindings/deps-allowlist/notapackage-fixture\\.txt: bindings/notapackage-fixture is not a workspace package" \
  "is not a workspace package"

new_case malformed
append_to bindings/deps-allowlist/wasm.txt 'js-sys extra'
append_to bindings/deps-allowlist/wasm.txt 'bumpalo'
expect_fail "malformed lines in wasm.txt" "${format}not a crate name: js-sys extra" "$format"
expect_also "a duplicate entry is reported" "${format}bumpalo is listed twice"

# polyjose-surface (ADR 0030 §1): polyjose and zeroize only, so surface.txt lists nothing. While T01
# has not created bindings/surface, a fixture package stands in for it.
new_surface_case() {
  new_case "$1"
  if [ ! -d "$case_dir/bindings/surface" ]; then
    append_to bindings/surface/Cargo.toml $'[package]\nname = "polyjose-surface"\nversion.workspace = true\nedition.workspace = true\nlicense.workspace = true\npublish = false\n\n[dependencies]\npolyjose.workspace = true\nzeroize.workspace = true'
    append_to bindings/surface/src/lib.rs '//! Fixture of scripts/tests/check-deps/binding-allowlists.sh: polyjose-surface before T01.'
    replace_in Cargo.toml 'members = [' 'members = ["bindings/surface", '
  fi
}

new_surface_case surface-clean
expect_pass "polyjose-surface with polyjose and zeroize only, against the empty surface.txt"

new_surface_case surface-crate
add_dependency bindings/surface/Cargo.toml 'base64ct = "1"'
expect_fail "a crate added to polyjose-surface" \
  "FAIL: the tree of polyjose-surface \\(bindings/surface\\) $not_allowed" "$not_allowed"
expect_also "the offending crate is named" '^  - base64ct$'

# --- Check 14: no serde in the bindings -------------------------------------------------------------------

# The criterion's reproduction: serde_json in polyjose-node fails check 14, and check 13 too.
new_case node-serde-json
add_dependency bindings/node/Cargo.toml 'serde_json = "1"'
expect_fail "serde_json added to polyjose-node" \
  "FAIL: serde_json $serde \\(ADR 0030 §1: no serde in the bindings\\): polyjose-node -> serde_json$" \
  "$serde|$not_allowed"
expect_also "check 13 also rejects it" "FAIL: the tree of polyjose-node \\(bindings/node\\) $not_allowed"

new_case node-serde-json-allowed
add_dependency bindings/node/Cargo.toml 'serde_json = "1"'
allow_new_crates node polyjose-node
expect_fail "serde_json in polyjose-node and in node.txt" \
  "FAIL: serde_json $serde \\(ADR 0030 §1: no serde in the bindings\\): polyjose-node -> serde_json$" "$serde"

# ffi.txt lists serde_json (below uniffi's bindgen CLI); a direct path avoids every crate of its line.
new_case ffi-serde-json
add_dependency bindings/ffi/Cargo.toml 'serde_json = "1"'
expect_fail "serde_json as a direct dependency of polyjose-ffi" \
  "FAIL: serde_json $serde \\(ADR 0030 §1: no serde in the bindings\\): polyjose-ffi -> serde_json$" "$serde"

# A change to the core is reported by the core's checks alone: with semver a direct dependency of
# the core, polyjose-ffi's build turns on semver's `serde` feature (through uniffi's cargo_metadata),
# so serde hangs below the core's semver only there; check 14 does not walk into the core, and check
# 5 (guarded group dalek-build) is what fails.
new_case core-semver
add_core_dependency 'semver = { version = "1", default-features = false }'
expect_fail "a core change that a binding's build unifies serde onto" \
  'FAIL: semver \(guarded group dalek-build\)' 'FAIL: semver \(guarded group dalek-build\)'

new_case ffi-below-narrowed
set_directive bindings/deps-allowlist/ffi.txt '# serde-only-below: uniffi_bindgen cargo_metadata camino uniffi_pipeline'
expect_fail "uniffi_macros dropped from ffi.txt's serde-only-below line" \
  "FAIL: serde $serde \\(ADR 0030 §1: no serde in the bindings\\): polyjose-ffi -> uniffi -> uniffi_macros -> serde$" "$serde"

new_case ffi-below-removed
python3 -I -c '
import sys
p = sys.argv[1]
lines = open(p).read().split("\n")
start = next(i for i, l in enumerate(lines) if l.startswith("# serde-only-below:"))
end = start + 1
while end < len(lines) and lines[end].startswith("#"):
    end += 1
open(p, "w").write("\n".join(lines[:start] + lines[end:]))
' "$case_dir/bindings/deps-allowlist/ffi.txt"
expect_fail "ffi.txt without its serde-only-below line" "FAIL: serde_json $serde" "$serde"

new_case ffi-below-unexplained
python3 -I -c '
import sys
p = sys.argv[1]
lines = open(p).read().split("\n")
i = next(i for i, l in enumerate(lines) if l.startswith("# serde-only-below:"))
lines.insert(i + 1, "")
open(p, "w").write("\n".join(lines))
' "$case_dir/bindings/deps-allowlist/ffi.txt"
expect_fail "a serde-only-below line with no comment explaining it" \
  "${format}serde-only-below must be followed by comment lines that explain" "$format"

new_case node-below-unneeded
append_to bindings/deps-allowlist/node.txt $'# serde-only-below: napi\n# Explained, but polyjose-node has no serde.'
expect_fail "a serde-only-below line in an allowlist whose tree has no serde" \
  "FAIL: bindings/deps-allowlist/node\\.txt: serde-only-below is not needed: no serde-family crate in the tree of polyjose-node" \
  "serde-only-below"

new_case ffi-below-outside
set_directive bindings/deps-allowlist/ffi.txt '# serde-only-below: uniffi_macros uniffi_bindgen cargo_metadata camino uniffi_pipeline napi'
expect_fail "a serde-only-below line naming a crate outside the tree" \
  "FAIL: bindings/deps-allowlist/ffi\\.txt: serde-only-below names napi, which is not in the tree of polyjose-ffi" \
  "serde-only-below"

finish
