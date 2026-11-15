#!/usr/bin/env bash
# Decides whether scripts/build.sh may reuse the host addon it built before instead of running
# `napi build` again (chore/test-speed), and records what it built. Only for scripts/test-all.sh,
# which sets POLYJOSE_ADDON_REUSE=1 for its run; build.sh calls this script only then, so a
# standalone build, ci-build.sh (CI and the release candidate, binding-node.yml), pack.sh and every
# release or publish path always build.
#
# Usage, from anywhere (it works in bindings/node):
#   scripts/addon-reuse.sh check [<build.sh arguments>...]
#     exit 0 and `addon-reuse: reusing ...` when the addon may be reused; exit 1 and
#     `addon-reuse: building: <reason>` otherwise (any other failure also means build).
#   scripts/addon-reuse.sh key
#     prints the inputs key (below); build.sh takes it before napi build.
#   scripts/addon-reuse.sh save <key> [<build.sh arguments>...]
#     after a build: writes addon-inputs.sha256 (git-ignored, next to the addon) with <key>, the
#     key taken before the build, and only when the key computed now is still <key>: an input
#     edited while napi build ran may or may not be in the addon, so such a build is never
#     recorded (and the next run builds again). Otherwise, or when the build is not one that check
#     would reuse, it removes the record.
#
# The key, the SHA-256 of:
#   - this format's version, the host (uname -sm) and the profile (build.sh's napi build is
#     --release; build.sh itself is an input below, so any change of its flags changes the key);
#   - `rustc -vV` and `cargo -V` as run here (rust-toolchain.toml applies);
#   - the content of $CARGO_HOME/config and $CARGO_HOME/config.toml (default ~/.cargo), the user's
#     cargo configuration, which can set rustflags or a linker (the repository has none:
#     scripts/check-no-cargo-config.sh);
#   - the build-affecting environment: RUST*, CARGO_* (except CARGO_TARGET_DIR, CARGO_HOME,
#     CARGO_TERM_*, which change where or how cargo prints, not what it builds), NAPI_*,
#     MACOSX_DEPLOYMENT_TARGET, SDKROOT, DEVELOPER_DIR, CC, CXX, AR, CFLAGS, CXXFLAGS, LDFLAGS (and
#     their _<target> forms);
#   - the path and content SHA-256 of every file the addon is compiled from: `git ls-files
#     --cached --others --exclude-standard` (tracked and untracked, not ignored) of bindings/node,
#     bindings/surface and crates/polyjose, and Cargo.lock, Cargo.toml (the workspace profiles)
#     and rust-toolchain.toml.
# addon-inputs.sha256 holds that key and the SHA-256 of the addon (polyjose.<platform>.node) and of
# binding.d.ts as built. check reuses only when, all at once: POLYJOSE_FORCE_REBUILD is not 1, CI
# and GITHUB_ACTIONS are unset, build.sh got no arguments (a --target build is never reused), the
# tree is a git work tree, the key equals the recorded one, exactly one polyjose.*.node exists and
# it and binding.d.ts have the recorded SHA-256, and addon-sha256.json pins that same SHA-256 for
# the addon's platform (feature 0007 F07: the pin backend.js checks before it loads the addon). A
# missing, changed or corrupt addon, binding.d.ts, pin or record therefore rebuilds. On reuse
# build.sh refreshes the two files' modification times, so scripts/check-binding-api.d/node.sh
# does not see the reused declarations as older than their sources.
set -euo pipefail
cd "$(dirname "$0")/.."
record=addon-inputs.sha256
repo=$(cd ../.. && pwd -P)

# sha256 <file>, or `-` for stdin: the lowercase hex SHA-256 (Node's node:crypto, as addon-hashes.sh).
sha256() {
  node -e 'const fs = require("node:fs");
const f = process.argv[1];
process.stdout.write(require("node:crypto").createHash("sha256").update(fs.readFileSync(f === "-" ? 0 : f)).digest("hex") + "\n");' "$1"
}

inputs_key() {
  git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 1
  {
    echo "polyjose-node-addon-inputs 1"
    echo "host $(uname -sm)"
    echo "profile release"
    rustc -vV
    cargo -V
    for f in "${CARGO_HOME:-$HOME/.cargo}/config" "${CARGO_HOME:-$HOME/.cargo}/config.toml"; do
      if [ -f "$f" ]; then echo "cargo-home ${f##*/} $(sha256 "$f")"; else echo "cargo-home ${f##*/} absent"; fi
    done
    env | LC_ALL=C grep -E '^(RUST[A-Z0-9_]*|CARGO_[A-Z0-9_]*|NAPI_[A-Z0-9_]*|MACOSX_DEPLOYMENT_TARGET|SDKROOT|DEVELOPER_DIR|(CC|CXX|AR|CFLAGS|CXXFLAGS|LDFLAGS)(_[A-Za-z0-9_]*)?)=' \
      | LC_ALL=C grep -vE '^(CARGO_TARGET_DIR|CARGO_HOME|CARGO_TERM_[A-Z_]*)=' | LC_ALL=C sort || true
    git -C "$repo" ls-files -z --cached --others --exclude-standard -- \
      bindings/node bindings/surface crates/polyjose Cargo.lock Cargo.toml rust-toolchain.toml \
      | node -e 'const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const root = process.argv[1];
const names = [...new Set(fs.readFileSync(0, "utf8").split("\0").filter((n) => n !== ""))].sort();
for (const n of names) {
  let h = "missing";
  try { h = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, n))).digest("hex"); } catch {}
  process.stdout.write(h + " " + n + "\n");
}' "$repo"
  } | sha256 -
}

# addon: the one polyjose.<platform>.node here, or nothing (none, or more than one).
addon() {
  local f found=""
  for f in polyjose.*.node; do
    [ -f "$f" ] || continue
    [ -z "$found" ] || return 0
    found=$f
  done
  printf '%s' "$found"
}

build() { echo "addon-reuse: building: $*"; exit 1; }

case ${1:-} in
  check)
    shift
    [ "${POLYJOSE_FORCE_REBUILD:-}" != 1 ] || build "POLYJOSE_FORCE_REBUILD=1"
    [ -z "${CI:-}${GITHUB_ACTIONS:-}" ] || build "a CI run (CI or GITHUB_ACTIONS is set)"
    [ $# -eq 0 ] || build "build arguments ($*)"
    [ -f "$record" ] || build "no $record (no earlier build to reuse)"
    a=$(addon)
    [ -n "$a" ] || build "not exactly one polyjose.*.node"
    [ -f binding.d.ts ] || build "binding.d.ts missing"
    [ -f addon-sha256.json ] || build "addon-sha256.json missing"
    key=$(inputs_key) || build "could not compute the inputs key (not a git work tree?)"
    [ "$(sed -n 's/^inputs //p' "$record")" = "$key" ] || build "the addon's inputs changed"
    sum=$(sha256 "$a")
    [ "$(sed -n "s/^addon $a //p" "$record")" = "$sum" ] || build "$a is not the addon recorded in $record"
    [ "$(sed -n 's/^dts binding.d.ts //p' "$record")" = "$(sha256 binding.d.ts)" ] || build "binding.d.ts is not the one recorded in $record"
    platform=${a#polyjose.}; platform=${platform%.node}
    pin=$(node -e 'const p = JSON.parse(require("node:fs").readFileSync("addon-sha256.json", "utf8"));
process.stdout.write(typeof p[process.argv[1]] === "string" ? p[process.argv[1]] : "");' "$platform") \
      || build "addon-sha256.json is not readable JSON"
    [ "$pin" = "$sum" ] || build "addon-sha256.json does not pin $a's SHA-256 for $platform"
    echo "addon-reuse: reusing $a (sha256 $sum, pinned in addon-sha256.json): inputs unchanged (key ${key%"${key#????????????}"}); POLYJOSE_FORCE_REBUILD=1 rebuilds"
    exit 0 ;;
  key)
    inputs_key ;;
  save)
    shift
    rm -f "$record"
    before=${1:-}
    [ $# -eq 0 ] || shift
    [ -n "$before" ] || exit 0
    [ -z "${CI:-}${GITHUB_ACTIONS:-}" ] || exit 0
    [ $# -eq 0 ] || exit 0
    a=$(addon)
    [ -n "$a" ] && [ -f binding.d.ts ] || exit 0
    key=$(inputs_key) || exit 0
    if [ "$key" != "$before" ]; then
      echo "addon-reuse: an input changed while napi build ran; not recorded, the next build compiles the addon again"
      exit 0
    fi
    printf 'inputs %s\naddon %s %s\ndts binding.d.ts %s\n' "$key" "$a" "$(sha256 "$a")" "$(sha256 binding.d.ts)" >"$record.tmp"
    mv "$record.tmp" "$record"
    echo "addon-reuse: recorded $a's inputs in $record" ;;
  *) echo "usage: scripts/addon-reuse.sh check [<build.sh arguments>...] | key | save <key> [<build.sh arguments>...]" >&2; exit 2 ;;
esac
