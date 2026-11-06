#!/usr/bin/env bash
# Enforces polyjose's minimal runtime dependency tree (ADR 0016) and its public credits (ADR 0020).
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
#
# The tree is `cargo tree -p polyjose -e normal,build --all-features --target all --prefix none`:
# runtime dependencies and the build-dependencies of every crate in it (a build script or a
# build-dependency runs on the builder's machine and can change the code that ships, so it is
# audit surface too), on every target and with every feature, so a target- or feature-specific
# dependency cannot hide. Dev-dependencies never ship and are not checked (ADR 0016 §5).
#
# Fails closed: if cargo or python3 is missing, or any command errors, it exits non-zero.
# Runs on macOS /bin/bash 3.2 and on Linux bash, so no associative arrays or mapfile.
set -euo pipefail
# sort and comm must agree on one byte order whatever the caller's locale is.
export LC_ALL=C
cd "$(dirname "$0")/.."
root=$(pwd); root_physical=$(pwd -P)

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
#    same set as the tree above. A `[patch]`, `[replace]` or `.cargo/config.toml` patch shows up
#    here as a path or git source. cargo-deny's [sources] check (deny.toml) covers git and other
#    registries for the whole workspace, but not path packages.
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

check_tree_allowlisted
check_allowlist_not_stale
check_default_features_off
check_credits_match
check_group_rules
check_sources_crates_io

if [ "$failed" -ne 0 ]; then
  echo "check-deps: FAILED"
  exit 1
fi

echo "ok: the core's tree ($(wc -l <"$work/tree" | tr -d ' ') crates, normal and build) matches $allowlist, all with default features off, all credited in $credits, all from crates.io"
# One line per group, in allowlist order.
awk '$1 != last { if (NR > 1) printf "\n"; printf "  %s:", $1; last = $1 } { printf " %s", $2 } END { printf "\n" }' "$work/groups"
exit 0
