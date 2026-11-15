#!/usr/bin/env bash
# Test of the @polyjose/node addon reuse (chore/test-speed): bindings/node/scripts/addon-reuse.sh,
# and bindings/node/scripts/build.sh, which uses it only under POLYJOSE_ADDON_REUSE=1 (set by
# scripts/test-all.sh):
#   - nothing changed (a touched file included) reuses the addon; changing any input (a source of
#     bindings/node, bindings/surface or crates/polyjose, a new untracked source, Cargo.lock, a
#     build-affecting environment variable such as MACOSX_DEPLOYMENT_TARGET; no RUST*/CARGO_*
#     assignment here: scripts/check-no-cargo-config.sh forbids them in scripts) rebuilds, and undoing the change reuses again;
#   - a missing or corrupt addon, binding.d.ts, record or addon-sha256.json pin rebuilds, and so do
#     POLYJOSE_FORCE_REBUILD=1, a CI run, build arguments and two addons;
#   - build.sh runs napi build without POLYJOSE_ADDON_REUSE=1 every time and records nothing, and
#     with it builds once and then reuses until an input changes; a build during which an input
#     changed is not recorded (the key is taken before napi build), so the next build runs again;
#   - another rustc (a stub first on PATH) and CARGO_BUILD_TARGET change the key.
# Not covered here, because scripts/check-no-cargo-config.sh forbids the lines a case would need
# in any script (assigning RUSTFLAGS or CARGO_HOME, writing a cargo config file): RUSTFLAGS and a
# $CARGO_HOME/config.toml change. Both go through the same code as the cases above (the
# environment filter, and a file hashed into the key).
# Each case works in a copy of the working tree (lib.sh) with a fake addon, and build.sh's napi
# and tsc are stubs, so nothing is compiled. Needs git, node and rustc.
# Usage: scripts/tests/test-all/addon-reuse.sh
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
command -v node >/dev/null 2>&1 || lib_die "node not found on PATH"
unset POLYJOSE_ADDON_REUSE POLYJOSE_FORCE_REBUILD CI GITHUB_ACTIONS

pkg() { printf '%s' "$case_dir/bindings/node"; }

# fake_build: a fake addon, its declarations and their addon-sha256.json pin, as a build leaves them.
fake_build() {
  printf 'fake addon\n' >"$(pkg)/polyjose.darwin-arm64.node"
  printf 'export declare function version(): string\n' >"$(pkg)/binding.d.ts"
  (cd "$(pkg)" && scripts/addon-hashes.sh addon-sha256.json polyjose.darwin-arm64.node) >/dev/null \
    || lib_die "addon-hashes.sh failed in the copy"
}

# reuse <check|save> [<argument>...]: runs addon-reuse.sh in the copy; sets $rc and $scratch/out.
reuse() {
  rc=0
  (cd "$(pkg)" && scripts/addon-reuse.sh "$@") </dev/null >"$scratch/out" 2>&1 || rc=$?
}

reused() { reuse check; check "$1: reused" 0 '^addon-reuse: reusing polyjose\.darwin-arm64\.node '; }
# rebuilt <description> <ERE of the reason>
rebuilt() { reuse check; check "$1: rebuilt" 1 "^addon-reuse: building: $2"; }

# --- The inputs key ------------------------------------------------------------------------------------

new_case key
fake_build
rebuilt "no record yet" 'no addon-inputs\.sha256'
key=$(cd "$(pkg)" && scripts/addon-reuse.sh key)
reuse save "$key"
check "save records the build" 0 '^addon-reuse: recorded polyjose\.darwin-arm64\.node'
reused "nothing changed"
reuse save "$(printf '%064d' 0)"
check "save with a key that is not the inputs' (they changed during the build) records nothing" 0 \
  '^addon-reuse: an input changed while napi build ran; not recorded'
rebuilt "so the next check" 'no addon-inputs\.sha256'
reuse save
rebuilt "save without a key records nothing either" 'no addon-inputs\.sha256'
reuse save "$key"
reused "the record restored"

touch "$case_dir/crates/polyjose/src/lib.rs"
reused "a touched source with the same content"

cp "$case_dir/crates/polyjose/src/lib.rs" "$scratch/lib.rs"
echo '// changed' >>"$case_dir/crates/polyjose/src/lib.rs"
rebuilt "a changed crates/polyjose source" "the addon's inputs changed"
cp "$scratch/lib.rs" "$case_dir/crates/polyjose/src/lib.rs"
reused "the change undone"

for f in bindings/surface/src/lib.rs bindings/node/src/lib.rs bindings/node/scripts/build.sh Cargo.lock Cargo.toml; do
  cp "$case_dir/$f" "$scratch/input"
  echo '# changed' >>"$case_dir/$f"
  rebuilt "a changed $f" "the addon's inputs changed"
  cp "$scratch/input" "$case_dir/$f"
done
reused "every change undone"

echo '// new' >"$case_dir/bindings/surface/src/untracked.rs"
rebuilt "a new untracked source" "the addon's inputs changed"
rm "$case_dir/bindings/surface/src/untracked.rs"
reused "the untracked source removed"

export MACOSX_DEPLOYMENT_TARGET=99.0
rebuilt "MACOSX_DEPLOYMENT_TARGET set" "the addon's inputs changed"
unset MACOSX_DEPLOYMENT_TARGET
reused "MACOSX_DEPLOYMENT_TARGET unset again"
export CARGO_BUILD_TARGET=x86_64-apple-darwin
rebuilt "CARGO_BUILD_TARGET set" "the addon's inputs changed"
unset CARGO_BUILD_TARGET
reused "CARGO_BUILD_TARGET unset again"

# Another toolchain: rustc and cargo stubs first on PATH, version A recorded, then version B.
mkdir -p "$scratch/toolchain"
toolchain() {
  printf '#!/bin/sh\necho "rustc %s (stub)"\necho "release: %s"\n' "$1" "$1" >"$scratch/toolchain/rustc"
  printf '#!/bin/sh\necho "cargo %s (stub)"\n' "$1" >"$scratch/toolchain/cargo"
  chmod +x "$scratch/toolchain/rustc" "$scratch/toolchain/cargo"
}
saved_path=$PATH
export PATH="$scratch/toolchain:$PATH"
toolchain 1.90.0
key_a=$(cd "$(pkg)" && scripts/addon-reuse.sh key)
reuse save "$key_a"
reused "the stub toolchain recorded"
toolchain 1.91.0
rebuilt "another rustc and cargo" "the addon's inputs changed"
toolchain 1.90.0
reused "the recorded toolchain again"
reuse save "$key_a"
export PATH=$saved_path
rebuilt "the real toolchain after the stub's record" "the addon's inputs changed"
reuse save "$key"
reused "the real toolchain recorded again"

# --- The addon, its pin and the guards ----------------------------------------------------------------

export POLYJOSE_FORCE_REBUILD=1
rebuilt "POLYJOSE_FORCE_REBUILD=1" 'POLYJOSE_FORCE_REBUILD=1'
unset POLYJOSE_FORCE_REBUILD
export CI=true
rebuilt "CI set" 'a CI run'
unset CI
export GITHUB_ACTIONS=true
rebuilt "GITHUB_ACTIONS set" 'a CI run'
unset GITHUB_ACTIONS
reuse check --target x86_64-apple-darwin
check "build arguments: rebuilt" 1 '^addon-reuse: building: build arguments \(--target x86_64-apple-darwin\)$'

cp "$(pkg)/polyjose.darwin-arm64.node" "$scratch/addon"
printf 'x' >>"$(pkg)/polyjose.darwin-arm64.node"
rebuilt "a corrupt addon" 'polyjose\.darwin-arm64\.node is not the addon recorded'
rm "$(pkg)/polyjose.darwin-arm64.node"
rebuilt "a missing addon" 'not exactly one polyjose\.\*\.node'
cp "$scratch/addon" "$(pkg)/polyjose.darwin-arm64.node"
cp "$scratch/addon" "$(pkg)/polyjose.linux-x64-gnu.node"
rebuilt "two addons" 'not exactly one polyjose\.\*\.node'
rm "$(pkg)/polyjose.linux-x64-gnu.node"
reused "the addon restored"

cp "$(pkg)/addon-sha256.json" "$scratch/pins"
printf '{\n  "darwin-arm64": "%064d"\n}\n' 0 >"$(pkg)/addon-sha256.json"
rebuilt "addon-sha256.json pinning another hash" 'addon-sha256\.json does not pin'
printf 'not json' >"$(pkg)/addon-sha256.json"
rebuilt "an unreadable addon-sha256.json" 'addon-sha256\.json is not readable JSON'
rm "$(pkg)/addon-sha256.json"
rebuilt "no addon-sha256.json" 'addon-sha256\.json missing'
cp "$scratch/pins" "$(pkg)/addon-sha256.json"

cp "$(pkg)/binding.d.ts" "$scratch/dts"
echo '// changed' >>"$(pkg)/binding.d.ts"
rebuilt "changed declarations" 'binding\.d\.ts is not the one recorded'
cp "$scratch/dts" "$(pkg)/binding.d.ts"
reused "the declarations restored"

reuse save "$key" --target x86_64-apple-darwin
tests_run=$((tests_run + 1))
if [ "$rc" -eq 0 ] && [ ! -e "$(pkg)/addon-inputs.sha256" ]; then echo "ok   - a build with arguments removes the record"
else echo "FAIL - a build with arguments removes the record (exit $rc)"; tests_failed=$((tests_failed + 1)); fi
rebuilt "after it" 'no addon-inputs\.sha256'

# --- build.sh ------------------------------------------------------------------------------------------

new_case build
mkdir -p "$(pkg)/node_modules/.bin" "$case_dir/bindings/js/node_modules/.bin"
# shellcheck disable=SC2016 # expanded by the stubs, not here
{
  echo '#!/bin/sh'
  echo 'echo "napi $*" >>"$STUB_LOG"'
  # An input edited while the build runs, when the case asks for it.
  echo 'if [ -f "$STUB_EDIT" ]; then rm -f "$STUB_EDIT"; echo "// edited during the build" >>../../crates/polyjose/src/lib.rs; fi'
  echo 'echo "fake addon" >polyjose.darwin-arm64.node'
  echo 'echo "export declare function version(): string" >binding.d.ts'
} >"$(pkg)/node_modules/.bin/napi"
# shellcheck disable=SC2016 # expanded by the stubs, not here
{
  echo '#!/bin/sh'
  echo 'case $PWD in */bindings/js) mkdir -p dist/src && echo "export {};" >dist/src/api.js && echo "export {};" >dist/src/api.d.ts ;; esac'
} >"$case_dir/bindings/js/node_modules/.bin/tsc"
chmod +x "$(pkg)/node_modules/.bin/napi" "$case_dir/bindings/js/node_modules/.bin/tsc"
export STUB_LOG="$scratch/napi.log" STUB_EDIT="$scratch/edit-during-build"
: >"$STUB_LOG"

# build <description> <napi builds expected so far> [<build.sh argument>...]: runs build.sh.
build() {
  local what=$1 want=$2 n
  shift 2
  rc=0
  (cd "$(pkg)" && scripts/build.sh "$@") </dev/null >"$scratch/out" 2>&1 || rc=$?
  n=$(wc -l <"$STUB_LOG" | tr -d ' ')
  tests_run=$((tests_run + 1))
  if [ "$rc" -eq 0 ] && [ "$n" = "$want" ]; then echo "ok   - $what ($n napi builds)"
  else
    echo "FAIL - $what: exit $rc, $n napi builds (expected $want)"; sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

build "without POLYJOSE_ADDON_REUSE build.sh builds" 1
build "and builds again" 2
check_absent "and records nothing" '^addon-reuse: '
[ ! -e "$(pkg)/addon-inputs.sha256" ] || { echo "FAIL - a build without the switch wrote a record"; tests_failed=$((tests_failed + 1)); }
export POLYJOSE_ADDON_REUSE=1
build "with POLYJOSE_ADDON_REUSE=1 the first build runs napi" 3
check "and records it" 0 '^addon-reuse: recorded polyjose\.darwin-arm64\.node'
build "the next build reuses the addon" 3
check "and says so" 0 '^addon-reuse: reusing polyjose\.darwin-arm64\.node ' '^    darwin-arm64 [0-9a-f]{64}$'
echo '// changed' >>"$case_dir/crates/polyjose/src/lib.rs"
build "a changed input builds again" 4
build "then reuses that build" 4
: >"$STUB_EDIT"
export POLYJOSE_FORCE_REBUILD=1
build "a build during which an input changes" 5
unset POLYJOSE_FORCE_REBUILD
check "is not recorded" 0 '^addon-reuse: an input changed while napi build ran; not recorded'
build "so the next build runs napi again, never reusing the stale addon" 6
build "and that build, made from the edited input, is reused" 6
export POLYJOSE_FORCE_REBUILD=1
build "POLYJOSE_FORCE_REBUILD=1 builds" 7
unset POLYJOSE_FORCE_REBUILD
build "and its build is reused next" 7
build "build arguments always build" 8 --target aarch64-apple-darwin
build "and leave nothing to reuse" 9

finish
