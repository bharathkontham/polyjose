#!/usr/bin/env bash
# Enforces polyjose's minimal runtime dependency tree (ADR 0016) and its public credits (ADR 0020).
#
# Fails, listing every offender, when:
#   1. the core's runtime tree contains a crate that deps-allowlist.txt does not list (ADR 0016 §4);
#   2. deps-allowlist.txt lists a crate the tree no longer contains, so the list stays exact;
#   3. a dependency of crates/polyjose ([dependencies] or [target.*.dependencies]) does not use
#      `default-features = false` (ADR 0016 §3);
#   4. a crate in deps-allowlist.txt is not credited in CREDITS.md, or CREDITS.md credits a crate
#      that is not in deps-allowlist.txt (ADR 0020 §5);
#   5. deps-allowlist.txt uses a group that has no entry in check_group_rules below.
#
# The tree is `cargo tree -p polyjose -e normal --all-features --target all --prefix none`: runtime
# dependencies only (dev-dependencies never ship, ADR 0016 §5), on every target and with every
# feature, so a target- or feature-specific dependency cannot hide.
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

# The core's runtime tree -> "$work/tree" (sorted, unique names, without polyjose itself).
tree_cmd=(cargo tree --locked -p "$core_pkg" -e normal --all-features --target all --prefix none)
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

# --- Checks -----------------------------------------------------------------------------------------
# Each check reports every offender with fail(); the script exits 1 at the end if any check failed.
# A new rule (e.g. a source guard) is a new function, called with the others below them.

# 1. Every crate in the tree is allowlisted (ADR 0016 §4).
check_tree_allowlisted() {
  comm -23 "$work/tree" "$work/allowed" >"$work/offenders"
  if [ -s "$work/offenders" ]; then
    fail "the core's runtime tree contains crates that $allowlist does not allow (ADR 0016 §4):"
    sed 's/^/  - /' "$work/offenders"
    echo "  Remove the dependency, or add it to $allowlist with an ADR. To see what pulls one in:"
    echo "    cargo tree -p $core_pkg -e normal --all-features --target all -i <crate>"
  fi
}

# 2. Every allowlisted crate is still in the tree, so the list stays exact.
check_allowlist_not_stale() {
  comm -13 "$work/tree" "$work/allowed" >"$work/stale"
  if [ -s "$work/stale" ]; then
    fail "$allowlist lists crates the core's runtime tree no longer contains; remove them (and their CREDITS.md entries):"
    sed 's/^/  - /' "$work/stale"
  fi
}

# 3. Every runtime dependency of the core turns default features off (ADR 0016 §3). cargo metadata
#    resolves `workspace = true` inheritance and covers [dependencies] and [target.*.dependencies].
check_default_features_off() {
  cargo metadata --locked --format-version 1 --no-deps >"$work/metadata.json" 2>"$work/metadata.err" \
    || { cat "$work/metadata.err" >&2; die "cargo metadata failed"; }
  python3 -I -c '
import json, os, sys
meta_path, pkg_name, manifest = sys.argv[1], sys.argv[2], os.path.realpath(sys.argv[3])
with open(meta_path, encoding="utf-8") as f:
    meta = json.load(f)
pkgs = [p for p in meta["packages"]
        if p["name"] == pkg_name and os.path.realpath(p["manifest_path"]) == manifest]
if len(pkgs) != 1:
    sys.exit("expected exactly one package %s at %s, found %d" % (pkg_name, manifest, len(pkgs)))
for dep in pkgs[0]["dependencies"]:
    if dep["kind"] is not None:  # "dev" or "build": not part of the runtime tree
        continue
    if dep["uses_default_features"] is not False:
        name = dep["name"] if not dep.get("rename") else "%s (as %s)" % (dep["name"], dep["rename"])
        where = "[target.%s.dependencies]" % dep["target"] if dep.get("target") else "[dependencies]"
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

check_tree_allowlisted
check_allowlist_not_stale
check_default_features_off
check_credits_match
check_group_rules

if [ "$failed" -ne 0 ]; then
  echo "check-deps: FAILED"
  exit 1
fi

echo "ok: the core's runtime tree ($(wc -l <"$work/tree" | tr -d ' ') crates) matches $allowlist, all with default features off, all credited in $credits"
# One line per group, in allowlist order.
awk '$1 != last { if (NR > 1) printf "\n"; printf "  %s:", $1; last = $1 } { printf " %s", $2 } END { printf "\n" }' "$work/groups"
exit 0
