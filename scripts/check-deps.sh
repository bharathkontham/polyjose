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
#   5. deps-allowlist.txt uses a group that has no entry in check_group_rules below, or a crate of
#      a guarded group (ADR 0025, ADR 0042) is reached through a path that avoids its required
#      parent crate (for example a direct dependency of the core on `semver`);
#   6. a package in the core's tree does not come from crates.io: a path package other than
#      polyjose itself, a git source or another registry (an allowlisted name is not enough when
#      the code behind it can be swapped);
#   7. the workspace root Cargo.toml has a [patch] or [replace] section;
#   8. crates/polyjose has a build script (build.rs, or a `build` key in [package]) or any
#      build-dependency ([build-dependencies] or [target.*.build-dependencies]);
#   9. a Rust file under crates/polyjose/src or bindings names an RSA private-key or signing type,
#      or decrypts with rsa (ADR 0021 §3: RSA is used for public-key operations only), reported
#      with its file and line;
#  10. `sha1` is in the core's tree (ADR 0022: no SHA-1 anywhere in the core);
#  11. `rsa` is built with any feature enabled, by the core or by anything else in the workspace
#      (ADR 0021: no `getrandom`, `encoding`, `sha1`, `hazmat` or other feature);
#  12. a workspace member depends on the `rsa` package under another name (`package = "rsa"`),
#      which would hide its use from check 9.
#  Checks 9-12 are, with scripts/check-rsa-symbols.sh (the same rule read from the compiled object
#  code, ADR 0049 §1), the guard that deny.toml's ignore of RUSTSEC-2023-0071 depends on: removing
#  them means removing that ignore.
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

# 5. Group-specific rules. Every group needs a case here, so a new group cannot land without
#    deciding its rule. A *guarded* group holds build-time crates that a primitive needs on the
#    builder's machine only (they link nothing into the shipped artifact) and that polyjose cannot
#    switch off from its manifest. Each of its crates may be reached only through one required
#    parent crate (ADR 0025, ADR 0042 §1-§2):
#      dalek-proc-macro (ADR 0025): curve25519-dalek-derive, dalek's SIMD-backend code generator,
#        a normal dependency of curve25519-dalek on x86_64, only below curve25519-dalek; its own
#        tree (syn, quote, proc-macro2, unicode-ident) only below curve25519-dalek-derive.
#      dalek-build (ADR 0042): rustc_version and semver, curve25519-dalek's build-dependencies,
#        only below curve25519-dalek.
#      num-traits-build (ADR 0042): autocfg, num-traits' build-dependency, only below num-traits.
#    "Below" is checked on the tree of check 1 (cargo tree, normal and build edges, every target,
#    every feature): the crate must be unreachable from polyjose once every package named like
#    the parent is removed. So a second path to it (a direct dependency, or another crate that
#    pulls it in) fails, and every path to it is printed with `cargo tree ... -i <crate>`.
#    (Not cargo metadata's resolve graph, as check 6 walks: that graph unifies features across
#    the whole workspace, so it would also show what only a binding enables.)
check_group_rules() {
  local group crate
  : >"$work/guarded"
  while read -r group crate; do
    case $group in
      primitives | ecdsa | eddsa | rsa | randomness | hygiene) ;; # may appear anywhere in the tree; no extra rule
      dalek-proc-macro)
        if [ "$crate" = curve25519-dalek-derive ]; then
          echo "$crate curve25519-dalek $group" >>"$work/guarded"
        else
          echo "$crate curve25519-dalek-derive $group" >>"$work/guarded"
        fi ;;
      dalek-build) echo "$crate curve25519-dalek $group" >>"$work/guarded" ;;
      num-traits-build) echo "$crate num-traits $group" >>"$work/guarded" ;;
      *) fail "$allowlist group '$group' (crate $crate) has no rule in check_group_rules (scripts/check-deps.sh)" ;;
    esac
  done <"$work/groups"
  [ -s "$work/guarded" ] || return 0
  # The graph is the tree of check 1 itself, printed with depths so that each line's parent is the
  # nearest line above it one level up. cargo prints a repeated subtree only once (marked "(*)"),
  # but every package's own dependencies appear at its first occurrence, so the edges are complete.
  cargo tree --locked -p "$core_pkg" -e "normal,build" --all-features --target all --prefix depth \
    >"$work/tree.depth" 2>"$work/tree.err" || { cat "$work/tree.err" >&2; die "cargo tree --prefix depth failed"; }
  # Prints "<crate> <parent> <group> <path>" for each guarded crate reachable without its parent.
  python3 -I -c '
import re, sys
tree_path, guarded_path = sys.argv[1], sys.argv[2]
def norm(name):
    return name.lower().replace("_", "-")
line_re = re.compile(r"^([0-9]+)([A-Za-z0-9][A-Za-z0-9_-]*) (v[0-9][^ ]*)")
edges, stack, root = {}, [], None
with open(tree_path, encoding="utf-8") as f:
    for number, line in enumerate(f, 1):
        line = line.rstrip("\r\n")
        m = line_re.match(line)
        if m is None:
            sys.exit("unexpected cargo tree line %d: %s" % (number, line))
        depth, node = int(m.group(1)), (norm(m.group(2)), m.group(3))
        if depth == 0:
            if root is not None:
                sys.exit("cargo tree printed more than one root")
            root = node
        elif depth > len(stack):
            sys.exit("cargo tree line %d skips a level" % number)
        else:
            edges.setdefault(stack[depth - 1], set()).add(node)
        del stack[depth:]
        stack.append(node)
if root is None:
    sys.exit("cargo tree printed nothing")
with open(guarded_path, encoding="utf-8") as f:
    rules = [line.split() for line in f if line.strip()]
for crate, parent, group in rules:
    # Breadth-first walk from polyjose that never enters a package named `parent`.
    prev, todo, hit = {root: None}, [root], None
    while todo and hit is None:
        nxt = []
        for node in todo:
            for dep in sorted(edges.get(node, ())):
                if dep in prev or dep[0] == parent:
                    continue
                prev[dep] = node
                if dep[0] == crate:
                    hit = dep
                    break
                nxt.append(dep)
            if hit is not None:
                break
        todo = nxt
    if hit is not None:
        path, node = [], hit
        while node is not None:
            path.append(node[0])
            node = prev[node]
        print("%s %s %s %s@%s %s" % (crate, parent, group, hit[0], hit[1][1:], " -> ".join(reversed(path))))
' "$work/tree.depth" "$work/guarded" >"$work/guard-paths" \
    || die "could not read the dependency graph for the guarded groups (see above)"
  local parent spec path
  while read -r crate parent group spec path; do
    fail "$crate (group $group in $allowlist) is reached without going through $parent (ADR 0025, ADR 0042 §2): $path"
    echo "  Every path to it (cargo tree -p $core_pkg -e normal,build --all-features --target all -i $spec):"
    cargo tree --locked -p "$core_pkg" -e normal,build --all-features --target all -i "$spec" </dev/null 2>&1 | sed 's/^/    /' || true
  done <"$work/guard-paths"
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

# 9. RSA is used for public-key operations only (ADR 0021 §3): RUSTSEC-2023-0071 (Marvin) is a
#    timing leak of rsa's private-key operations, and deny.toml ignores it only while this check
#    holds. Every *.rs file under crates/polyjose/src and bindings (build output and node_modules
#    excluded) is scanned as text, comments and strings included, so the check errs toward
#    failing. Fails, naming the file and line, on:
#    - anywhere: `RsaPrivateKey` (so `RsaPrivateKey::new` too), `BlindedSigningKey`,
#      `DecryptingKey`, `RandomizedDecryptor`, `Pkcs1v15Sign` and the `Pss` scheme struct
#      (verification uses the typed `pkcs1v15::VerifyingKey` / `pss::VerifyingKey`), and
#      `Pkcs1v15Encrypt` (RSA1_5, ADR 0021);
#    - anywhere: `use rsa;`, `use rsa as …`, `pub use rsa…` and `extern crate rsa`, which would let
#      other files name rsa items without writing `rsa::`, and the same inside any use tree
#      (`use {rsa as r};`, `pub(crate) use {rsa::pkcs1v15};`, `use r#rsa as r;`; ADR 0049 §1);
#    - anywhere: `#[path …]` (also inside `cfg_attr`) and `include!`, which can load code from a
#      file outside the scanned roots (ADR 0049 §1); include_str!/include_bytes! stay allowed;
#    - in jws/rsa.rs and jwe/rsa_oaep.rs (or their mod.rs forms): any out-of-line child module
#      (`mod x;`), and any file in jws/rsa/ or jwe/rsa_oaep/. A child module reaches the parent's
#      private `use rsa::{pkcs1v15, ..}` as `super::pkcs1v15` without naming rsa (ADR 0049 §1).
#      Inline modules (`#[cfg(test)] mod tests { .. }`) are allowed: their text is the file's;
#    - in a file that names the rsa crate (`rsa::` not preceded by a path, `use rsa…`, or an `rsa`
#      token anywhere in a use tree, e.g. `use super::{hmac, rsa};`): the word
#      `SigningKey` (e.g. `rsa::pkcs1v15::SigningKey`), the word `Decryptor` (`rsa::traits::
#      Decryptor`) and any `decrypt(`/`decrypt_blinded(` call (e.g. an `Oaep` decryption). These
#      words are legitimate elsewhere (`p256::ecdsa::SigningKey`, `cbc::Decryptor`), so RSA code
#      lives in files of its own (jws/rsa.rs, jwe/rsa_oaep.rs) and refers to child modules named
#      `rsa` as `self::rsa::`;
#    - anywhere, the macro rule (ADR 0049 §1): `rsa` or `r#rsa` as an identifier inside the token
#      tree of a macro call (`name!(..)`, `name![..]`, `name!{..}`, `macro_rules! name {..}`, at
#      any depth) or of an attribute (`#[..]`, `#![..]`). A macro can make it the head of a path
#      (`macro_rules! k { ($c:ident) => { $c::pkcs1v15::SigningKey<..> } }` with `k!(rsa)`) that
#      no rule above sees, and the compiled-symbol check sees that path only in code that is
#      codegened, not in an uncalled `#[inline] pub fn`, a generic `pub fn` never instantiated in
#      the workspace, or code the built profiles leave out, all of which a downstream crate can
#      still compile. The rule reads the file with every comment and literal removed
#      (`format!("rsa")`, `k!(/* rsa */ x)` pass), and allows two forms:
#        - a later segment of a path, `<ident>::rsa` (`polyjose::jws::rsa::verify`, `self::rsa`,
#          `$crate::jws::rsa`), which names a module of polyjose; a global `::rsa` is the crate
#          and fails;
#        - inside the std macros of STD_MACROS called by their plain name (`assert!`,
#          `assert_eq!`, `format!`, `vec!`, ..), whose arguments are ordinary expressions,
#          patterns or format arguments that no path is built from, so the rules above read them
#          as any other code (`assert!(rsa.is_public())` in a test). Every enclosing macro call
#          must be one (`k!(assert!(rsa))` and `assert!(k!(rsa))` fail), and a `macro_rules!` or
#          an `as` that takes one of their names fails, so a local macro cannot pass as one.
#    Rust allows whitespace and comments between the tokens of a path (`rsa` / newline /
#    `::pkcs1v15::SigningKey`, `rsa /* … */ :: x`), and rustfmt need not have run. So every rule
#    but the macro rule (which reads tokens) runs on each line and also on two whole-file views,
#    with whitespace runs (newlines included) collapsed to one space and the spaces next to `::`
#    removed: one with the comments kept and one with each comment replaced by a space. A view
#    only adds findings; a finding that only a view sees is reported with the line where the
#    match starts.
#    Residual risk, outside this scan: a macro that drops the leading segments of a path it is
#    given (`k!(x::rsa)` to `rsa::..`), a dependency's macro with a std macro's name brought in by
#    a glob import, and a derive or attribute macro of a dependency that builds a path from an
#    item's own identifiers. This scan is the fast first layer; scripts/check-rsa-symbols.sh reads
#    the compiled objects of polyjose and the bindings (dev and release profiles), where no
#    spelling of a path can hide codegened code (ADR 0049 §1).
check_rsa_public_only() {
  python3 -I -c '
import bisect, os, re, sys
roots = sys.argv[1:]
word = lambda w: re.compile(r"(?<![A-Za-z0-9_])" + w + r"(?![A-Za-z0-9_])")
USE_TREE = r"[A-Za-z0-9_:{},*#\s]"
ANYWHERE = [
    (word("RsaPrivateKey"), "RsaPrivateKey: RSA private keys are not supported (ADR 0021)"),
    (word("BlindedSigningKey"), "BlindedSigningKey: RSA signing is not supported (ADR 0021)"),
    (word("DecryptingKey"), "DecryptingKey: RSA decryption is not supported (ADR 0021)"),
    (word("RandomizedDecryptor"), "RandomizedDecryptor: RSA decryption is not supported (ADR 0021)"),
    (word("Pkcs1v15Sign"), "Pkcs1v15Sign: use the typed rsa::pkcs1v15::VerifyingKey (ADR 0021)"),
    (word("Pss"), "Pss: use the typed rsa::pss::VerifyingKey (ADR 0021)"),
    (word("Pkcs1v15Encrypt"), "Pkcs1v15Encrypt: RSA1_5 is not supported (ADR 0021)"),
    (re.compile(r"(?<![A-Za-z0-9_])use\s+(::\s*)?rsa\s*(;|as(?![A-Za-z0-9_]))"),
     "use rsa / use rsa as: aliasing the rsa crate hides it from this check"),
    # A use tree is the text from `use` to its `;` when that text holds only path characters, so
    # `{`, `}`, `,`, `*`, `as`, `self` and raw identifiers (`r#rsa`) are all inside it.
    (re.compile(r"(?<![A-Za-z0-9_])use\s+" + USE_TREE + r"*?(?<![A-Za-z0-9_])rsa\s+as(?![A-Za-z0-9_])" + USE_TREE + r"*;"),
     "rsa as ... in a use tree: aliasing the rsa crate hides it from this check (ADR 0049 §1)"),
    (re.compile(r"(?<![A-Za-z0-9_])pub(\s*\([^)]*\))?\s+use\s+(::\s*)?rsa(?![A-Za-z0-9_])"),
     "pub use rsa: re-exporting rsa hides it from this check"),
    (re.compile(r"(?<![A-Za-z0-9_])pub(\s*\([^)]*\))?\s+use\s+" + USE_TREE + r"*?(?<![A-Za-z0-9_])rsa(?![A-Za-z0-9_])" + USE_TREE + r"*;"),
     "pub use rsa: re-exporting rsa hides it from this check"),
    (re.compile(r"(?<![A-Za-z0-9_])extern\s+crate\s+(r#)?rsa(?![A-Za-z0-9_])"),
     "extern crate rsa: aliasing the rsa crate hides it from this check"),
    # A module file named by #[path] (also through cfg_attr), or code pulled in by include!, can
    # sit outside the scanned roots (ADR 0049 §1). include_str!/include_bytes! read data, not code.
    (re.compile(r"#\s*!?\s*\[\s*(path(?![A-Za-z0-9_])|cfg_attr(?![A-Za-z0-9_])[^\]]*(?<![A-Za-z0-9_])path\s*=)"),
     "#[path]: a module file named by #[path] can sit outside the scanned roots (ADR 0049 §1)"),
    (re.compile(r"(?<![A-Za-z0-9_])include\s*!"),
     "include!: code included from another file can sit outside the scanned roots (ADR 0049 §1)"),
]
NAMES_RSA = re.compile(r"(?<![A-Za-z0-9_:])rsa\s*::|(?<![A-Za-z0-9_])::\s*rsa\s*::|(?<![A-Za-z0-9_])use\s+(::\s*)?rsa(?![A-Za-z0-9_])"
                       r"|(?<![A-Za-z0-9_])use\s+" + USE_TREE + r"*?(?<![A-Za-z0-9_])rsa(?![A-Za-z0-9_])" + USE_TREE + r"*;")
# The files that hold RSA code, and the directories their child module files would live in. An
# out-of-line child module (`mod x;`) reaches the private `use rsa::{pkcs1v15, ..}` as
# `super::pkcs1v15` in a file that never names rsa, so these files may only have inline modules
# (`mod x { .. }`, e.g. `#[cfg(test)] mod tests`), whose text this check sees as part of the file.
RSA_FILES = {"crates/polyjose/src/jws/rsa.rs", "crates/polyjose/src/jws/rsa/mod.rs",
             "crates/polyjose/src/jwe/rsa_oaep.rs", "crates/polyjose/src/jwe/rsa_oaep/mod.rs"}
RSA_CHILD_DIRS = ("crates/polyjose/src/jws/rsa/", "crates/polyjose/src/jwe/rsa_oaep/")
IN_RSA_MODULE_FILE = [
    (re.compile(r"(?<![A-Za-z0-9_])mod\s+((r#)?[A-Za-z_][A-Za-z0-9_]*)\s*;"),
     lambda m: "mod %s;: an out-of-line child module of an RSA file can use its private rsa imports"
               " through super:: (ADR 0049 §1); use an inline mod %s { .. }" % (m.group(1), m.group(1))),
]
IN_RSA_FILE = [
    (word("SigningKey"), "SigningKey in a file that uses the rsa crate: RSA signing is not supported (ADR 0021)"),
    (word("Decryptor"), "Decryptor in a file that uses the rsa crate: RSA decryption is not supported (ADR 0021)"),
    (re.compile(r"(?<![A-Za-z0-9_])decrypt(_blinded)?\s*(::\s*<[^()]*>)?\s*\("),
     "a decrypt call in a file that uses the rsa crate: RSA decryption is not supported (ADR 0021)"),
]
SKIP_DIRS = {"target", "node_modules", ".git"}
# The whole-file views. Comments are found with a small lexer that knows string, raw string and
# char literals (so a "//" inside a string is not a comment) and nested block comments; an
# unterminated literal or comment runs to the end of the file. The view with the comments kept
# covers any lexer mistake.
Q = chr(39)
RAW_STR = re.compile(r"[bc]?r(#*)\"")
CHAR_LIT = re.compile(Q + r"(?:\\(?:u\{[0-9A-Fa-f_]*\}|x[0-9A-Fa-f]{2}|.)|[^\\\n" + Q + "])" + Q)
def strip_comments(text, literals=False):
    """(char, offset) pairs of text with each comment replaced by one space at its offset, and
    with literals=True each string, raw string and char literal too (for the macro rule)."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append((" ", i))
        elif text.startswith("/*", i):
            depth, end = 1, i + 2
            while end < n and depth:
                if text.startswith("/*", end):
                    depth, end = depth + 1, end + 2
                elif text.startswith("*/", end):
                    depth, end = depth - 1, end + 2
                else:
                    end += 1
            out.append((" ", i))
        else:
            raw = None
            if i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"):
                raw = RAW_STR.match(text, i)
            char = CHAR_LIT.match(text, i) if text[i] == Q else None
            if raw is not None:
                close = text.find("\"" + raw.group(1), raw.end())
                end = n if close < 0 else close + 1 + len(raw.group(1))
            elif text[i] == "\"":
                end = i + 1
                while end < n and text[end] != "\"":
                    end += 2 if text[end] == "\\" else 1
                end = min(end + 1, n)
            elif char is not None:
                end = char.end()
            else:
                end = i + 1
            if literals and (raw is not None or text[i] == "\"" or char is not None):
                out.append((" ", i))
            else:
                out.extend((text[k], k) for k in range(i, end))
        i = end
    return out
def flatten(pairs):
    """Collapses whitespace runs to one space and drops the spaces next to ::, and returns the
    text and the source offset of each of its characters."""
    chars, offsets = [], []
    for ch, offset in pairs:
        if ch.isspace():
            if chars and chars[-1] == " ":
                continue
            ch = " "
        chars.append(ch)
        offsets.append(offset)
    keep = [k for k in range(len(chars)) if not (chars[k] == " " and (
        "".join(chars[k + 1:k + 3]) == "::" or "".join(chars[max(k - 2, 0):k]) == "::"))]
    return "".join(chars[k] for k in keep), [offsets[k] for k in keep]
# The macro rule (see the comment of check 9): the std macros whose arguments are ordinary
# expressions, patterns or format arguments, called by their plain name. Keywords never name a
# macro (`if !(x)`, `return !(x)` are negations).
STD_MACROS = {"assert", "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq", "debug_assert_ne",
              "format", "format_args", "print", "println", "eprint", "eprintln", "write", "writeln",
              "panic", "unreachable", "todo", "unimplemented", "vec", "matches"}
KEYWORDS = {"as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
            "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move",
            "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true",
            "type", "unsafe", "use", "where", "while", "yield"}
TOKEN = re.compile(r"(?:r#)?[A-Za-z_][A-Za-z0-9_]*|[0-9][A-Za-z0-9_]*|" + Q + r"[A-Za-z_][A-Za-z0-9_]*|::|\S")
IDENT = re.compile(r"(?:r#)?[A-Za-z_][A-Za-z0-9_]*$")
CLOSE = {"(": ")", "[": "]", "{": "}"}
def macro_rule(text):
    """(offset, reason) for each rsa identifier inside a macro call or attribute that the macro
    rule rejects, and for each local macro that takes a name of STD_MACROS."""
    pairs = strip_comments(text, literals=True)
    code = "".join(ch for ch, _ in pairs)
    toks = [(m.group(0), pairs[m.start()][1]) for m in TOKEN.finditer(code)]
    tok = lambda k: toks[k][0] if 0 <= k < len(toks) else ""
    # One entry per open delimiter: None, or (what it is the token tree of, trusted).
    found, stack = [], []
    for k, (t, offset) in enumerate(toks):
        if t in CLOSE:
            frame, shown = None, t + ".." + CLOSE[t]
            if tok(k - 1) == "!" and IDENT.match(tok(k - 2)) and tok(k - 2) not in KEYWORDS:
                name, plain = tok(k - 2), tok(k - 3) not in ("::", "$")
                frame = ("the macro call %s!%s%s" % (name, shown, "" if plain or name not in STD_MACROS
                         else " (a qualified or $ name is not the std macro)"), plain and name in STD_MACROS)
            elif IDENT.match(tok(k - 1)) and tok(k - 2) == "!" and tok(k - 3) in ("macro_rules", "r#macro_rules"):
                frame = ("the macro call macro_rules! %s %s" % (tok(k - 1), shown), False)
            elif t == "[" and (tok(k - 1) == "#" or (tok(k - 1) == "!" and tok(k - 2) == "#")):
                frame = ("the attribute #[%s ..]" % tok(k + 1), False)
            stack.append(frame)
        elif t in (")", "]", "}"):
            if stack:
                stack.pop()
        elif t in ("rsa", "r#rsa"):
            frames = [f for f in stack if f is not None]
            if not frames or all(trusted for _, trusted in frames):
                continue
            # A later segment of a path (`polyjose::jws::rsa`, `self::rsa`, `$crate::jws::rsa`)
            # names a module of polyjose; a global `::rsa` is the crate.
            if tok(k - 1) == "::" and (IDENT.match(tok(k - 2)) or tok(k - 2) == ">"):
                continue
            where = [w for w, trusted in frames if not trusted][-1]
            found.append((offset, "rsa as an identifier inside %s: a macro can build an rsa path from it"
                                  " that no other text rule sees (ADR 0049 §1)" % where))
        elif IDENT.match(t) and (t[2:] if t.startswith("r#") else t) in STD_MACROS:
            name = t[2:] if t.startswith("r#") else t
            if tok(k - 1) == "!" and tok(k - 2) in ("macro_rules", "r#macro_rules"):
                found.append((offset, "macro_rules! %s: a macro named like a std macro whose arguments"
                                      " the macro rule trusts (ADR 0049 §1); name it otherwise" % name))
            elif tok(k - 1) == "as":
                found.append((offset, "as %s: a macro named like a std macro whose arguments the macro"
                                      " rule trusts (ADR 0049 §1); name it otherwise" % name))
    return found
found = 0
for root in roots:
    if not os.path.isdir(root):
        continue
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            lines = text.split("\n")
            views = [flatten((ch, k) for k, ch in enumerate(text)), flatten(strip_comments(text))]
            rel = path.replace(os.sep, "/")
            rules = list(ANYWHERE)
            if any(NAMES_RSA.search(line) for line in lines) or any(NAMES_RSA.search(v) for v, _ in views):
                rules += IN_RSA_FILE
            if rel in RSA_FILES:
                rules += IN_RSA_MODULE_FILE
            reported = set()
            if rel.startswith(RSA_CHILD_DIRS) and rel not in RSA_FILES:
                print("%s:1: a child module file of an RSA file (ADR 0049 §1): RSA code stays in"
                      " jws/rsa.rs and jwe/rsa_oaep.rs, with inline modules only" % path)
                found += 1
            # The reason of a rule is a string, or a function of the match (to name what matched).
            explain = lambda why, m: why(m) if callable(why) else why
            for number, line in enumerate(lines, 1):
                for pattern, why in rules:
                    m = pattern.search(line)
                    if m:
                        print("%s:%d: %s" % (path, number, explain(why, m)))
                        found += 1
                        reported.add((number, explain(why, m)))
            line_starts = [0] + [k + 1 for k, ch in enumerate(text) if ch == "\n"]
            for view, offsets in views:
                for pattern, why in rules:
                    for m in pattern.finditer(view):
                        number = bisect.bisect_right(line_starts, offsets[m.start()])
                        if (number, explain(why, m)) not in reported:
                            print("%s:%d: %s (path split across lines, by whitespace or by a comment)" % (path, number, explain(why, m)))
                            found += 1
                            reported.add((number, explain(why, m)))
            for offset, why in macro_rule(text):
                number = bisect.bisect_right(line_starts, offset)
                if (number, why) not in reported:
                    print("%s:%d: %s" % (path, number, why))
                    found += 1
                    reported.add((number, why))
for root in roots:
    if not os.path.isdir(root):
        sys.exit("%s is not a directory" % root)
' crates/polyjose/src bindings >"$work/rsa-uses" || die "could not scan the sources for RSA private-key use"
  if [ -s "$work/rsa-uses" ]; then
    fail "RSA private-key or signing use (ADR 0021 §3; deny.toml ignores RUSTSEC-2023-0071 only while this holds):"
    sed 's/^/  - /' "$work/rsa-uses"
  fi
}

# 10. No SHA-1 in the core (ADR 0022). sha1 is not allowlisted, so check 1 also fails; this names
#     the rule, and still fails if sha1 is ever added to deps-allowlist.txt.
check_no_sha1() {
  if grep -qx 'sha1' "$work/tree"; then
    fail "sha1 is in the core's tree; polyjose uses no SHA-1 (ADR 0022). To see what pulls it in:"
    echo "    cargo tree -p $core_pkg -e normal,build --all-features --target all -i sha1"
  fi
}

# 11. rsa is built with no feature at all (ADR 0021): not `getrandom` (blinded private-key
#     operations), `encoding` (pkcs1/pkcs8/spki), `sha1` (ADR 0022), `hazmat`, `std` or any other.
#     Read from cargo metadata's resolve graph, whose features are unified across the whole
#     workspace with every feature on, so a binding or another member that enables one fails too.
check_rsa_no_features() {
  python3 -I -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    meta = json.load(f)
packages = {p["id"]: p for p in meta["packages"]}
if meta.get("resolve") is None:
    sys.exit("cargo metadata has no resolve graph")
for node in meta["resolve"]["nodes"]:
    p = packages[node["id"]]
    if p["name"] == "rsa" and node["features"]:
        print("rsa %s with features: %s" % (p["version"], ", ".join(sorted(node["features"]))))
' "$work/metadata.json" >"$work/rsa-features" || die "could not read rsa's features from cargo metadata"
  if [ -s "$work/rsa-features" ]; then
    fail "rsa must be built with no features (ADR 0021, ADR 0022):"
    sed 's/^/  - /' "$work/rsa-features"
    echo "  To see what enables them: cargo tree -e features --all-features --target all -i rsa"
  fi
}

# 12. No workspace member (the core, the bindings, anything else) depends on the rsa package under
#     another name (`foo = { package = "rsa", … }`, directly or through [workspace.dependencies]),
#     in any table: [dependencies], [dev-dependencies], [build-dependencies] or their [target.*.…]
#     forms. Code could then write `foo::pkcs1v15::SigningKey`, which check 9 cannot tie to rsa
#     (ADR 0021 §3). Read from cargo metadata (`rename`), so every way of spelling the manifest
#     is covered.
check_rsa_not_renamed() {
  python3 -I -c '
import json, os, sys
meta_path, root = sys.argv[1], os.path.realpath(sys.argv[2])
with open(meta_path, encoding="utf-8") as f:
    meta = json.load(f)
members = set(meta["workspace_members"])
if not members:
    sys.exit("cargo metadata lists no workspace members")
tables = {None: "dependencies", "dev": "dev-dependencies", "build": "build-dependencies"}
seen = 0
for p in meta["packages"]:
    if p["id"] not in members:
        continue
    seen += 1
    for dep in p["dependencies"]:
        table = tables[dep["kind"]]  # any other kind is a KeyError: fail closed
        if dep["name"].lower().replace("_", "-") != "rsa" or dep.get("rename") in (None, "rsa"):
            continue
        where = "[target.%s.%s]" % (dep["target"], table) if dep.get("target") else "[%s]" % table
        manifest = os.path.relpath(os.path.realpath(p["manifest_path"]), root)
        print("%s (%s): rsa as %s in %s" % (p["name"], manifest, dep["rename"], where))
if seen != len(members):
    sys.exit("cargo metadata is missing %d workspace member(s)" % (len(members) - seen))
' "$work/metadata.json" "$root_physical" >"$work/rsa-renames" || die "could not read the workspace's dependencies from cargo metadata"
  if [ -s "$work/rsa-renames" ]; then
    fail "the rsa package is a dependency under another name; depend on it as rsa, so check 9 can see its use (ADR 0021 §3):"
    sed 's/^/  - /' "$work/rsa-renames"
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
check_rsa_public_only
check_no_sha1
check_rsa_no_features
check_rsa_not_renamed

if [ "$failed" -ne 0 ]; then
  echo "check-deps: FAILED"
  exit 1
fi

echo "ok: the core's tree ($(wc -l <"$work/tree" | tr -d ' ') crates, normal and build) matches $allowlist, all with default features off, all credited in $credits, all from crates.io; RSA public-key use only, no sha1, rsa without features and under its own name (ADR 0021, ADR 0022)"
# One line per group, in allowlist order.
awk '$1 != last { if (NR > 1) printf "\n"; printf "  %s:", $1; last = $1 } { printf " %s", $2 } END { printf "\n" }' "$work/groups"
exit 0
