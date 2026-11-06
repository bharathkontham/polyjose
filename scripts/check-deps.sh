#!/usr/bin/env bash
# Enforces polyjose's minimal dependency tree (ADR 0016), its supply chain (crates.io only, no
# patches, no build script in the core) and its public credits (ADR 0020).
#
# Fails, listing every offender, when:
#   1. the core's tree contains a crate that deps-allowlist.txt does not list (ADR 0016 §4);
#   2. deps-allowlist.txt lists a crate the tree no longer contains, so the list stays exact;
#   3. a dependency of crates/polyjose ([dependencies], [build-dependencies] or their
#      [target.*.…] forms) does not use `default-features = false` (ADR 0016 §3);
#   4. a crate in deps-allowlist.txt is not credited in CREDITS.md, or CREDITS.md credits a crate
#      that is not in deps-allowlist.txt (ADR 0020 §5);
#   5. deps-allowlist.txt uses a group that has no entry in check_group_rules below;
#   6. a package in the core's tree does not come from crates.io: a path package other than
#      polyjose itself, a git source or another registry (an allowlisted name is not enough when
#      the code behind it can be swapped);
#   7. the workspace root Cargo.toml has a [patch] or [replace] section;
#   8. crates/polyjose has a build script (build.rs, or a `build` key in [package]) or any
#      build-dependency ([build-dependencies] or [target.*.build-dependencies]).
#
# The tree is `cargo tree -p polyjose -e normal,build --all-features --target all --prefix none`:
# runtime dependencies and the build-dependencies of every crate in it (a build script or a
# build-dependency runs on the builder's machine and can change the code that ships, so it is
# audit surface too), on every target and with every feature, so a target- or feature-specific
# dependency cannot hide. Dev-dependencies never ship and are not checked (ADR 0016 §5).
#
# deny.toml (cargo-deny) is the second layer: it bans C/C++ build tooling (cc, cmake) and git or
# non-crates.io registry sources for the whole workspace, bindings included.
#
# Before any of that, scripts/check-no-cargo-config.sh must pass: a cargo config file in the
# repository could replace sources or wrap rustc for every cargo command below (see check 6).
#
# Fails closed: if cargo or python3 is missing, or any command errors, it exits non-zero.
# Runs on macOS /bin/bash 3.2 and on Linux bash, so no associative arrays or mapfile.
set -euo pipefail
# sort and comm must agree on one byte order whatever the caller's locale is.
export LC_ALL=C
cd "$(dirname "$0")/.."
root=$(pwd); root_physical=$(pwd -P)

# No cargo config file in the repository, checked before cargo runs at all, so a planted config
# cannot change what the cargo commands below resolve or build. Its exit status (1 found, 2 could
# not check) is this script's.
no_config_rc=0
scripts/check-no-cargo-config.sh || no_config_rc=$?
if [ "$no_config_rc" -ne 0 ]; then
  echo "check-deps: FAILED (scripts/check-no-cargo-config.sh)"
  exit "$no_config_rc"
fi

allowlist=deps-allowlist.txt
credits=CREDITS.md
core_pkg=polyjose
core_manifest=crates/polyjose/Cargo.toml

die() { echo "ERROR: $*" >&2; exit 2; }
failed=0
fail() { echo "FAIL: $*"; failed=1; }

command -v cargo >/dev/null 2>&1 || die "cargo not found on PATH; cannot check the dependency tree"
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH; cannot read cargo metadata"
[ -f "$allowlist" ] || die "$allowlist not found at the repository root"
[ -f "$credits" ] || die "$credits not found at the repository root"
[ -f "$core_manifest" ] || die "$core_manifest not found"

work=$(mktemp -d "${TMPDIR:-/tmp}/check-deps.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$work"' EXIT

# Crate names compare case-insensitively with `_` and `-` equivalent, as crates.io treats them.
normalize() { tr 'A-Z_' 'a-z-'; }

# --- Inputs -----------------------------------------------------------------------------------------

# deps-allowlist.txt -> "$work/groups" ("<group> <crate>" per line) and "$work/allowed" (sorted names).
# Malformed lines, crates outside a group and duplicates are errors, never silently dropped.
awk -v file="$allowlist" '
  function err(msg) { printf "ERROR: %s:%d: %s\n", file, NR, msg | "cat 1>&2"; bad = 1 }
  {
    line = $0; sub(/\r$/, "", line)
    if (line ~ /^[ \t]*#[ \t]*group:/) {
      g = line; sub(/^[ \t]*#[ \t]*group:[ \t]*/, "", g); sub(/[ \t]+$/, "", g)
      if (g !~ /^[a-z0-9][a-z0-9-]*$/) { err("bad group line: " line); next }
      if (g in groups) err("group " g " appears twice")
      groups[g] = 1; group = g; next
    }
    sub(/#.*/, "", line); gsub(/^[ \t]+|[ \t]+$/, "", line)
    if (line == "") next
    if (line !~ /^[A-Za-z0-9][A-Za-z0-9_-]*$/) { err("not a crate name: " $0); next }
    if (group == "") { err(line " is not inside a \"# group: <id>\" section"); next }
    name = tolower(line); gsub(/_/, "-", name)
    if (name in seen) { err(name " is listed twice"); next }
    seen[name] = 1; print group, name
  }
  END { exit bad }
' "$allowlist" >"$work/groups" || die "$allowlist is malformed (see above)"
awk '{ print $2 }' "$work/groups" | sort >"$work/allowed"
[ -s "$work/allowed" ] || die "$allowlist lists no crates"

# CREDITS.md -> "$work/credited". Every level-3 heading credits exactly one crate: "### `name`".
# Any other level-3 heading is an error, so a typo cannot drop a credit unnoticed.
awk -v file="$credits" '
  function err(msg) { printf "ERROR: %s:%d: %s\n", file, NR, msg | "cat 1>&2"; bad = 1 }
  /^```/ { fence = !fence; next }
  fence || !/^###[ \t]/ { next }
  {
    line = $0; sub(/\r$/, "", line); sub(/[ \t]+$/, "", line)
    if (line !~ /^### `[A-Za-z0-9][A-Za-z0-9_-]*`$/) { err("level-3 headings must be one crate name in backticks: " line); next }
    name = line; sub(/^### `/, "", name); sub(/`$/, "", name)
    name = tolower(name); gsub(/_/, "-", name)
    if (name in seen) { err(name " is credited twice"); next }
    seen[name] = 1; print name
  }
  END { exit bad }
' "$credits" >"$work/credited.unsorted" || die "$credits is malformed (see above)"
sort "$work/credited.unsorted" >"$work/credited"

# The core's tree -> "$work/tree" (sorted, unique names, without polyjose itself).
tree_cmd=(cargo tree --locked -p "$core_pkg" -e "normal,build" --all-features --target all --prefix none)
"${tree_cmd[@]}" >"$work/tree.raw" 2>"$work/tree.err" || { cat "$work/tree.err" >&2; die "'${tree_cmd[*]}' failed"; }
# The first line is the root package from this checkout; every other line is "<name> v<version> ...".
awk -v want="$core_pkg" -v dir="$root/crates/polyjose" -v pdir="$root_physical/crates/polyjose" '
  function err(msg) { print msg | "cat 1>&2"; bad = 1 }
  NR == 1 { if ($1 != want || (index($0, "(" dir ")") == 0 && index($0, "(" pdir ")") == 0)) err("unexpected root line: " $0); next }
  $1 !~ /^[A-Za-z0-9][A-Za-z0-9_-]*$/ || $2 !~ /^v[0-9]/ { err("unexpected line: " $0); next }
  { print $1 }
  END { if (NR == 0) bad = 1; exit bad }
' "$work/tree.raw" >"$work/tree.names" || die "cannot parse the output of '${tree_cmd[*]}'; check the script"
normalize <"$work/tree.names" | sort -u >"$work/tree"

# The whole resolved workspace -> "$work/metadata.json". With every feature and no platform filter,
# like the tree above. cargo metadata resolves `workspace = true` inheritance, so the checks below
# read what cargo will build, not the manifest text.
cargo metadata --locked --format-version 1 --all-features >"$work/metadata.json" 2>"$work/metadata.err" \
  || { cat "$work/metadata.err" >&2; die "cargo metadata failed"; }

# Reads keys from a Cargo.toml: `python3 -I -c "$toml_keys_py" <manifest> <dotted.key>...` prints one
# line per key that is present. With tomllib (Python 3.11+, as on the CI runners) the answer is exact.
# Without it, a conservative line scan reports every line that could define the key (after dropping
# quotes and whitespace, the key's last part followed by `=`, `.` or `]`), so it can only err toward
# failing; a manifest with \u escapes, which could spell a key, cannot be scanned and is an error.
# (Single-quoted for the shell, so the Python uses no single quotes.)
toml_keys_py='
import re, sys
path, keys = sys.argv[1], sys.argv[2:]
try:
    import tomllib
except ImportError:
    tomllib = None
def describe(node, depth=2):
    if not isinstance(node, dict):
        return "= ..."
    if depth == 0 or not node:
        return "{...}" if node else "{}"
    return "{" + ", ".join("%s %s" % (k, describe(v, depth - 1)) for k, v in sorted(node.items())) + "}"
if tomllib is not None:
    with open(path, "rb") as f:
        doc = tomllib.load(f)
    for key in keys:
        node = doc
        for part in key.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if node is not None:
            print("%s %s" % (key, describe(node)))
    sys.exit(0)
with open(path, encoding="utf-8") as f:
    text = f.read()
if "\\u" in text or "\\U" in text:
    sys.exit("%s has \\u escapes and python3 has no tomllib (Python 3.11+): cannot scan it safely" % path)
drop = re.compile("[\\s\"" + chr(39) + "]")
for number, line in enumerate(text.splitlines(), 1):
    stripped = line.strip()
    if stripped.startswith("#"):
        continue
    flat = drop.sub("", stripped)
    for key in keys:
        last = re.escape(key.split(".")[-1])
        if re.search("(^|[.{,\\[])" + last + "([.=\\]]|$)", flat):
            print("%s? line %d: %s (no tomllib, conservative scan; Python 3.11+ checks exactly)" % (key, number, stripped))
'

# --- Checks -----------------------------------------------------------------------------------------
# Each check reports every offender with fail(); the script exits 1 at the end if any check failed.
# A new rule (e.g. a source guard) is a new function, called with the others below them.

# 1. Every crate in the tree is allowlisted (ADR 0016 §4).
check_tree_allowlisted() {
  comm -23 "$work/tree" "$work/allowed" >"$work/offenders"
  if [ -s "$work/offenders" ]; then
    fail "the core's tree (normal and build dependencies) contains crates that $allowlist does not allow (ADR 0016 §4):"
    sed 's/^/  - /' "$work/offenders"
    echo "  Remove the dependency, or add it to $allowlist with an ADR. To see what pulls one in:"
    echo "    cargo tree -p $core_pkg -e normal,build --all-features --target all -i <crate>"
  fi
}

# 2. Every allowlisted crate is still in the tree, so the list stays exact.
check_allowlist_not_stale() {
  comm -13 "$work/tree" "$work/allowed" >"$work/stale"
  if [ -s "$work/stale" ]; then
    fail "$allowlist lists crates the core's tree no longer contains; remove them (and their CREDITS.md entries):"
    sed 's/^/  - /' "$work/stale"
  fi
}

# 3. Every normal and build dependency of the core turns default features off (ADR 0016 §3),
#    in [dependencies], [build-dependencies] and their [target.*.…] forms.
check_default_features_off() {
  python3 -I -c '
import json, os, sys
meta_path, pkg_name, manifest = sys.argv[1], sys.argv[2], os.path.realpath(sys.argv[3])
with open(meta_path, encoding="utf-8") as f:
    meta = json.load(f)
pkgs = [p for p in meta["packages"]
        if p["name"] == pkg_name and os.path.realpath(p["manifest_path"]) == manifest]
if len(pkgs) != 1:
    sys.exit("expected exactly one package %s at %s, found %d" % (pkg_name, manifest, len(pkgs)))
tables = {None: "dependencies", "build": "build-dependencies"}
for dep in pkgs[0]["dependencies"]:
    if dep["kind"] == "dev":  # dev-dependencies never ship (ADR 0016 §5)
        continue
    table = tables[dep["kind"]]  # any other kind is a KeyError: fail closed
    if dep["uses_default_features"] is not False:
        name = dep["name"] if not dep.get("rename") else "%s (as %s)" % (dep["name"], dep["rename"])
        where = "[target.%s.%s]" % (dep["target"], table) if dep.get("target") else "[%s]" % table
        print("%s in %s" % (name, where))
' "$work/metadata.json" "$core_pkg" "$core_manifest" >"$work/defaults" \
    || die "could not read $core_pkg's dependencies from cargo metadata"
  if [ -s "$work/defaults" ]; then
    fail "dependencies of $core_manifest without default-features = false (ADR 0016 §3):"
    sed 's/^/  - /' "$work/defaults"
  fi
}

# 4. deps-allowlist.txt and CREDITS.md name the same crates (ADR 0020 §5).
check_credits_match() {
  comm -23 "$work/allowed" "$work/credited" >"$work/uncredited"
  comm -13 "$work/allowed" "$work/credited" >"$work/overcredited"
  if [ -s "$work/uncredited" ]; then
    fail "crates in $allowlist with no \"### \`<crate>\`\" entry in $credits (ADR 0020 §5):"
    sed 's/^/  - /' "$work/uncredited"
  fi
  if [ -s "$work/overcredited" ]; then
    fail "crates credited in $credits that $allowlist does not list (ADR 0020 §5):"
    sed 's/^/  - /' "$work/overcredited"
  fi
}

# 5. Group-specific rules. Every group needs a case here, so a new group (e.g. one whose crates may
#    only be reached through a single parent crate) cannot land without deciding its rule.
#    ADR 0025's dalek group (feature 0002: curve25519-dalek-derive, syn, quote, proc-macro2,
#    unicode-ident) arrives as *normal* x86_64 dependencies of curve25519-dalek, not as
#    build-dependencies, so check 8 (the core's own manifest only) does not apply to it; its rule
#    ("only below curve25519-dalek-derive", via `cargo tree -e normal,build --target all -i <crate>`)
#    goes here. Because the tree includes build edges, curve25519-dalek's own build-dependency
#    (rustc_version, which pulls semver) is in the tree too and needs allowlisting like any crate.
check_group_rules() {
  local group crate
  while read -r group crate; do
    case $group in
      primitives | randomness | hygiene) ;; # may appear anywhere in the tree; no extra rule
      *) fail "$allowlist group '$group' (crate $crate) has no rule in check_group_rules (scripts/check-deps.sh)" ;;
    esac
  done <"$work/groups"
}

# 6. Every package in the core's tree comes from crates.io. The walk follows normal and build
#    edges from polyjose through cargo metadata's resolve graph (all features, all targets), the
#    same set as the tree above. A `[patch]` or `[replace]` in a manifest shows up here as a path
#    or git source. cargo-deny's [sources] check (deny.toml) covers git and other registries for
#    the whole workspace, but not path packages.
#    Neither sees cargo *source replacement*: a cargo config with `[source.crates-io] replace-with`
#    (e.g. a vendored directory) keeps reporting the crates.io source while compiling other code.
#    So no cargo config file may exist anywhere in the repository; scripts/check-no-cargo-config.sh
#    enforces that (and rejects --config and config variables in scripts/ and .github/) before
#    this script runs cargo. Residual risk, outside the repository and not checkable here: a config
#    in a directory above the checkout (e.g. ~/.cargo/config.toml), $CARGO_HOME/config.toml, CARGO_*
#    variables in the caller's environment, and `--config` on a command line.
check_sources_crates_io() {
  python3 -I -c '
import json, os, sys
meta_path, pkg_name, manifest = sys.argv[1], sys.argv[2], os.path.realpath(sys.argv[3])
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
with open(meta_path, encoding="utf-8") as f:
    meta = json.load(f)
packages = {p["id"]: p for p in meta["packages"]}
core = [p["id"] for p in meta["packages"]
        if p["name"] == pkg_name and os.path.realpath(p["manifest_path"]) == manifest]
if len(core) != 1:
    sys.exit("expected exactly one package %s at %s, found %d" % (pkg_name, manifest, len(core)))
if meta.get("resolve") is None:
    sys.exit("cargo metadata has no resolve graph")
nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
seen, todo = set(core), list(core)
while todo:
    for dep in nodes[todo.pop()]["deps"]:
        if dep["pkg"] in seen:
            continue
        # A missing dep_kinds (cargo older than 1.41) is a KeyError: fail closed.
        if any(k["kind"] in (None, "build") for k in dep["dep_kinds"]):
            seen.add(dep["pkg"])
            todo.append(dep["pkg"])
for pkg_id in sorted(seen - set(core)):
    p = packages[pkg_id]
    if p["source"] != CRATES_IO:
        where = p["source"] or "path " + os.path.dirname(p["manifest_path"])
        print("%s %s from %s" % (p["name"], p["version"], where))
' "$work/metadata.json" "$core_pkg" "$core_manifest" >"$work/sources" \
    || die "could not walk $core_pkg's dependency graph in cargo metadata"
  if [ -s "$work/sources" ]; then
    fail "packages in the core's tree that do not come from crates.io (registry+https://github.com/rust-lang/crates.io-index):"
    sed 's/^/  - /' "$work/sources"
    echo "  Depend on the published crates.io release; remove any [patch], [replace] or git/path/registry source."
  fi
}

# 7. No [patch] or [replace] in the workspace root manifest: it swaps a crates.io crate for other
#    code under the same name and version. Check 6 also catches the result; this names the cause.
check_no_patch_or_replace() {
  local ws_root
  ws_root=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["workspace_root"])' \
    "$work/metadata.json") || die "could not read workspace_root from cargo metadata"
  [ "$(cd "$ws_root" && pwd -P)" = "$root_physical" ] || die "cargo's workspace root $ws_root is not this repository ($root)"
  python3 -I -c "$toml_keys_py" Cargo.toml patch replace >"$work/patches" || die "could not read Cargo.toml"
  if [ -s "$work/patches" ]; then
    fail "the workspace root Cargo.toml must not have [patch] or [replace] sections; depend on crates.io releases:"
    sed 's/^/  - /' "$work/patches"
  fi
}

# 8. The core has no build script and no build-dependencies: it is plain Rust, and code that runs on
#    the builder's machine is audit surface it does not need. This is about crates/polyjose's own
#    manifest only; build scripts and build-dependencies of crates in its tree are covered by
#    checks 1, 2 and 6 like any other dependency.
check_core_no_build_script() {
  local core_dir=${core_manifest%/Cargo.toml}
  if [ -e "$core_dir/build.rs" ]; then
    fail "$core_dir/build.rs exists; the core must not have a build script"
  fi
  python3 -I -c "$toml_keys_py" "$core_manifest" package.build >"$work/build-key" || die "could not read $core_manifest"
  if [ -s "$work/build-key" ]; then
    fail "$core_manifest sets a build script; the core must not have one:"
    sed 's/^/  - /' "$work/build-key"
  fi
  python3 -I -c '
import json, os, sys
meta_path, pkg_name, manifest = sys.argv[1], sys.argv[2], os.path.realpath(sys.argv[3])
with open(meta_path, encoding="utf-8") as f:
    meta = json.load(f)
pkgs = [p for p in meta["packages"]
        if p["name"] == pkg_name and os.path.realpath(p["manifest_path"]) == manifest]
if len(pkgs) != 1:
    sys.exit("expected exactly one package %s at %s, found %d" % (pkg_name, manifest, len(pkgs)))
for target in pkgs[0]["targets"]:
    if "custom-build" in target["kind"]:
        print("build script %s" % target["src_path"])
for dep in pkgs[0]["dependencies"]:
    if dep["kind"] == "build":
        where = "[target.%s.build-dependencies]" % dep["target"] if dep.get("target") else "[build-dependencies]"
        print("%s in %s" % (dep["name"], where))
' "$work/metadata.json" "$core_pkg" "$core_manifest" >"$work/core-build" \
    || die "could not read $core_pkg's targets from cargo metadata"
  if [ -s "$work/core-build" ]; then
    fail "$core_manifest must have no build script and no build-dependencies:"
    sed 's/^/  - /' "$work/core-build"
  fi
}

check_tree_allowlisted
check_allowlist_not_stale
check_default_features_off
check_credits_match
check_group_rules
check_sources_crates_io
check_no_patch_or_replace
check_core_no_build_script

if [ "$failed" -ne 0 ]; then
  echo "check-deps: FAILED"
  exit 1
fi

echo "ok: the core's tree ($(wc -l <"$work/tree" | tr -d ' ') crates, normal and build) matches $allowlist, all with default features off, all credited in $credits, all from crates.io"
# One line per group, in allowlist order.
awk '$1 != last { if (NR > 1) printf "\n"; printf "  %s:", $1; last = $1 } { printf " %s", $2 } END { printf "\n" }' "$work/groups"
exit 0
