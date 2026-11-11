#!/usr/bin/env bash
# Enforces polyjose's minimal dependency tree (ADR 0016), its supply chain (crates.io only, no
# patches, no build script in the core), its public credits (ADR 0020) and the binding crates'
# trees (ADR 0030 §1).
#
# Fails, listing every offender, when:
#   1. the core's tree contains a crate that deps-allowlist.txt does not list (ADR 0016 §4);
#   2. deps-allowlist.txt lists a crate the tree no longer contains, so the list stays exact;
#   3. a dependency of crates/polyjose ([dependencies], [build-dependencies] or their
#      [target.*.…] forms) does not use `default-features = false` (ADR 0016 §3);
#   4. a crate in deps-allowlist.txt is not credited in CREDITS.md, or CREDITS.md credits a crate
#      that is not in deps-allowlist.txt (ADR 0020 §5);
#   5. deps-allowlist.txt uses a group that has no entry in check_group_rules below, or a guarded
#      group (ADR 0025, ADR 0042, ADR 0049 §5) breaks one of its rules. Its members are fixed in
#      the guarded_group_members table below, not read from deps-allowlist.txt: a crate the
#      allowlist lists in a guarded group must be a member of it, a member must not be listed in
#      another group, and a member in the core's tree must be listed. Each member is reachable only
#      below its required parent crate (a direct dependency of the core on `semver` fails), and
#      only through its group's edges: the dalek-build and num-traits-build crates must be absent
#      from `cargo tree -e normal`, and the dalek-proc-macro crates from `-e normal,no-proc-macro`;
#   6. a package in the normal or build graph of any workspace member does not come from
#      crates.io: a path package that is not a workspace member, a git source or another registry
#      (an allowlisted name is not enough when the code behind it can be swapped);
#   7. the workspace root Cargo.toml has a [patch] or [replace] section, or a [workspace] exclude;
#   8. crates/polyjose has a build script (build.rs, or a `build` key in [package]) or any
#      build-dependency ([build-dependencies] or [target.*.build-dependencies]); or
#      bindings/surface or bindings/ffi has a build script (build.rs, a `build` key, or a
#      custom-build target in cargo metadata; security audit L2 of feature 0013);
#   9. a Rust file of the workspace (crates/polyjose/src, bindings/, and every other workspace
#      member's directory and target directories, from cargo metadata) uses an RSA item that stays
#      forbidden (ADR 0067 §3, §6: key generation, RSA1_5, an unblinded or typed private-key entry
#      point, hazmat), or names the RSA private key type or a blinded private-key entry point
#      outside the RSA files (jws/rsa.rs, jwe/rsa_oaep.rs, keys/rsa.rs), or has a
#      spelling that could hide such a use from this scan (ADR 0049 §1): `rsa` aliased or
#      re-exported in a use tree (any `rsa` token in one names the crate), `#[path]` or `include!`,
#      an out-of-line `mod x;` in an RSA file (or a file below jws/rsa/, jwe/rsa_oaep/ or
#      keys/rsa/), or `rsa` as an identifier in a macro call or attribute (the macro rule; the
#      arguments of std macros such as `assert!` and `format!` are exempt). Reported with its file
#      and line;
#  10. `sha1` is in the core's tree (ADR 0022: no SHA-1 anywhere in the core);
#  11. `rsa` is built with any feature but `pkcs1v15`, by the core or by anything else in the
#      workspace (ADR 0067 §1: no `getrandom`, `encoding`, `sha1`, `hazmat` or other feature);
#  12. a workspace member depends on the `rsa` package under another name (`package = "rsa"`),
#      which would hide its use from check 9;
#  13. the normal and build tree of a binding package (bindings/<name>, any target, default,
#      no-default or all features) has a crate that bindings/deps-allowlist/<name>.txt,
#      deps-allowlist.txt and the core's tree do not cover; that file lists a crate the tree lacks
#      or one deps-allowlist.txt already allows, or is malformed; or a binding package has no such
#      file (ADR 0030 §1). A file whose bindings/<name> does not exist yet is skipped with a message;
#  14. a serde-family crate (serde, serde_core, serde_derive, serde_json, serde-wasm-bindgen, ...) is
#      in the normal tree of a binding package other than below the crates of the explained
#      `# serde-only-below:` line of its allowlist (ADR 0030 §1), or that line is not needed.
#  Checks 9-12 are, with scripts/check-rsa-symbols.sh (the same rule read from the compiled object
#  code of polyjose and the bindings, built in the dev and the release profile, ADR 0049 §1), the
#  guard that keeps RSA key generation, RSA1_5, unblinded private-key paths and hazmat out
#  (ADR 0067 §3, §6). They outlive the RUSTSEC-2023-0071 ignore, which rsa 0.10.0 made unneeded.
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
# Fails closed: if cargo or python3 is missing, or any command errors, it exits non-zero; so does a
# syntax error in this script, under macOS /bin/bash 3.2 too (the completion sentinel, F11).
# Exit status: 0 clean, 1 a check failed, 2 the checks could not run.
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
# Fail closed on a syntax error under bash 3.2 (feature 0013 F10, F11; see scripts/test-all.sh):
# with errexit, bash 3.2 runs the EXIT trap with $? = 0 after a parse error, so the trap turns an
# exit before the last line, which sets the sentinel, into status 2. A non-zero status (check
# failures exit 1, die exits 2) is kept.
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$work"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "check-deps.sh: stopped before its last line (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

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
tree_cmd=(cargo tree --color never --locked -p "$core_pkg" -e "normal,build" --all-features --target all --prefix none)
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
#    switch off from its manifest (ADR 0025, ADR 0042 §1-§2, ADR 0049 §5):
#      dalek-proc-macro (ADR 0025): curve25519-dalek-derive, dalek's SIMD-backend code generator,
#        a normal dependency of curve25519-dalek on x86_64, only below curve25519-dalek; its own
#        tree (syn, quote, proc-macro2, unicode-ident) only below curve25519-dalek-derive.
#      dalek-build (ADR 0042): rustc_version and semver, curve25519-dalek's build-dependencies,
#        only below curve25519-dalek.
#      num-traits-build (ADR 0042): autocfg, num-traits' build-dependency, only below num-traits.
#    Three rules hold for them:
#    a. Membership (ADR 0049 §5). The members of each guarded group are fixed in
#       guarded_group_members below, not read from deps-allowlist.txt, so the allowlist alone
#       cannot grow a guarded group or move a crate out of one. Rules b and c run on every crate of
#       that table, whatever the allowlist says, and the allowlist must agree with it:
#       - a crate the allowlist lists in a guarded group must be a member of that group here, so a
#         crate added to a group (e.g. libm, which num-traits' `libm` feature pulls in below
#         num-traits, where rule b alone would accept it) fails until this script and an ADR add
#         it (ADR 0042 §5);
#       - a member listed by the allowlist in any other group (e.g. syn under primitives) fails;
#       - a member in the core's tree that the allowlist does not list fails (check 1 also fails);
#       - a member in neither the tree nor the allowlist passes: the primitive dropped it, which
#         only shrinks the tree. Check 2 makes the allowlist entry go when the tree loses the
#         crate; the row here can then go too, and rules b and c still hold for the crate if it
#         ever comes back while its row is here.
#    b. Required parent (ADR 0025, ADR 0042 §2). "Below" is checked on the tree of check 1 (cargo
#       tree, normal and build edges, every target, every feature): the crate must be unreachable
#       from polyjose once every package named like the parent is removed. So a second path to it
#       (a direct dependency, or another crate that pulls it in) fails.
#    c. Edge kinds (ADR 0049 §5), from guarded_group_edges: the dalek-build and num-traits-build
#       crates must be absent from `cargo tree -e normal` (same flags otherwise), so they reach
#       polyjose through build edges only, and the dalek-proc-macro crates must be absent from
#       `-e normal,no-proc-macro`, so they reach it only through a proc-macro. Rule b alone would
#       accept a parent's *normal* edge to a build-time crate (e.g. num-traits -> libm).
#    Each failure prints a shortest offending path and every path, with `cargo tree ... -i <crate>`.
#    (Not cargo metadata's resolve graph, as check 6 walks: that graph unifies features across
#    the whole workspace, so it would also show what only a binding enables.)
#    A table row is "<group> <crate> <required parent>".

# The guarded groups' members (ADR 0025, ADR 0042 §1, ADR 0049 §5). Growing a group, or adding
# one, is a change here and needs an ADR (ADR 0042 §5).
guarded_group_members() {
  cat <<'EOF'
dalek-proc-macro curve25519-dalek-derive curve25519-dalek
dalek-proc-macro syn curve25519-dalek-derive
dalek-proc-macro quote curve25519-dalek-derive
dalek-proc-macro proc-macro2 curve25519-dalek-derive
dalek-proc-macro unicode-ident curve25519-dalek-derive
dalek-build rustc_version curve25519-dalek
dalek-build semver curve25519-dalek
num-traits-build autocfg num-traits
EOF
}

# guarded_membership_rules: checks deps-allowlist.txt's groups against guarded_group_members, as the
# comment of check 5 describes. Reads "$work/guard-table", "$work/groups" and "$work/tree".
guarded_membership_rules() {
  local group crate parent listed
  while read -r group crate; do
    if awk -v g="$group" '$1 == g { found = 1 } END { exit !found }' "$work/guard-table"; then
      awk -v g="$group" -v c="$crate" '$1 == g && $2 == c { found = 1 } END { exit !found }' "$work/guard-table" \
        || fail "$crate is listed in guarded group $group in $allowlist but is not a member of it in scripts/check-deps.sh (ADR 0049 §5; growing a guarded group needs an ADR, ADR 0042 §5)"
    else
      case $group in
        primitives | ecdsa | eddsa | rsa | randomness | hygiene) ;; # may appear anywhere in the tree; no extra rule
        *) fail "$allowlist group '$group' (crate $crate) has no rule in check_group_rules (scripts/check-deps.sh)" ;;
      esac
    fi
  done <"$work/groups"
  while read -r group crate parent; do
    listed=$(awk -v c="$crate" '$2 == c { print $1 }' "$work/groups")
    if [ -n "$listed" ] && [ "$listed" != "$group" ]; then
      fail "$crate is a member of guarded group $group (scripts/check-deps.sh) but $allowlist lists it in group $listed (ADR 0049 §5)"
    elif [ -z "$listed" ] && grep -qxF -- "$crate" "$work/tree"; then
      fail "$crate is a member of guarded group $group (scripts/check-deps.sh) and in the core's tree, but $allowlist does not list it (ADR 0049 §5)"
    fi
  done <"$work/guard-table"
}

# guarded_group_edges <group>: the edge kinds of `cargo tree -e` whose tree must not contain the
# group's crates (ADR 0049 §5). Build-time crates are absent from the normal edges, so they reach
# polyjose only as a build-dependency; the proc-macro group is absent from the normal edges that
# avoid proc-macro crates, so it reaches polyjose only through a proc-macro. Neither links into the
# artifact. A guarded group without a case here is an error.
guarded_group_edges() {
  case $1 in
    dalek-proc-macro) echo normal,no-proc-macro ;;
    dalek-build | num-traits-build) echo normal ;;
    *) return 1 ;;
  esac
}

# guarded_paths <edge kinds> <rules> <out>: for each rule "<crate> <avoid> <group>" in <rules>,
# writes "<crate> <avoid> <group> <name>@<version> <path>" to <out> when <crate> is reachable from
# polyjose in `cargo tree -p polyjose -e <edge kinds> --all-features --target all` without entering
# a package named <avoid> ("-" avoids nothing: no crate has that name). <path> is a shortest such
# path. The tree is printed with depths, so each line's parent is the nearest line above it one
# level up. cargo prints a repeated subtree only once (marked "(*)"), but every package's own
# dependencies appear at its first occurrence, so the edges are complete.
guarded_paths() {
  cargo tree --color never --locked -p "$core_pkg" -e "$1" --all-features --target all --prefix depth </dev/null \
    >"$work/tree.depth" 2>"$work/tree.err" || { cat "$work/tree.err" >&2; die "cargo tree -e $1 --prefix depth failed"; }
  # shellcheck disable=SC2016 # Python source in single quotes, with no shell expansion meant
  python3 -I -c '
import re, sys
tree_path, rules_path = sys.argv[1], sys.argv[2]
def norm(name):
    return name.lower().replace("_", "-")
line_re = re.compile(r"^([0-9]+)([A-Za-z0-9][A-Za-z0-9_-]*) (v[0-9][^ ]*)")
edges, stack, root, spelled = {}, [], None, {}
with open(tree_path, encoding="utf-8") as f:
    for number, line in enumerate(f, 1):
        line = line.rstrip("\r\n")
        m = line_re.match(line)
        if m is None:
            sys.exit("unexpected cargo tree line %d: %s" % (number, line))
        depth, node = int(m.group(1)), (norm(m.group(2)), m.group(3))
        spelled[node] = m.group(2)
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
with open(rules_path, encoding="utf-8") as f:
    rules = [line.split() for line in f if line.strip()]
for crate, avoid, group in rules:
    # Breadth-first walk from polyjose that never enters a package named `avoid`.
    prev, todo, hit = {root: None}, [root], None
    while todo and hit is None:
        nxt = []
        for node in todo:
            for dep in sorted(edges.get(node, ())):
                if dep in prev or dep[0] == avoid:
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
        print("%s %s %s %s@%s %s" % (crate, avoid, group, spelled[hit], hit[1][1:], " -> ".join(reversed(path))))
' "$work/tree.depth" "$2" </dev/null >"$3" || die "could not read the dependency graph for the guarded groups (see above)"
}

check_group_rules() {
  local group crate parent spec path kinds
  # The table, with crate names normalized like the allowlist's and the tree's. Fails closed on a
  # malformed row or a group without an edge rule.
  guarded_group_members | normalize >"$work/guard-table"
  awk 'NF != 3 || $1 !~ /^[a-z0-9][a-z0-9-]*$/ { bad = 1 } END { exit bad || NR == 0 }' "$work/guard-table" \
    || die "guarded_group_members in scripts/check-deps.sh is malformed"
  : >"$work/guard-edge-rules"
  while read -r group crate parent; do
    kinds=$(guarded_group_edges "$group") || die "guarded group $group has no case in guarded_group_edges (scripts/check-deps.sh)"
    echo "$kinds $crate - $group" >>"$work/guard-edge-rules"
  done <"$work/guard-table"
  guarded_membership_rules

  # Path rule: on the tree of check 1 (normal and build edges), every member is unreachable once
  # its required parent is removed.
  awk '{ print $2, $3, $1 }' "$work/guard-table" >"$work/guarded"
  guarded_paths normal,build "$work/guarded" "$work/guard-paths"
  while read -r crate parent group spec path; do
    fail "$crate (guarded group $group) is reached without going through $parent (ADR 0025, ADR 0042 §2): $path"
    echo "  Every path to it (cargo tree -p $core_pkg -e normal,build --all-features --target all -i $spec):"
    cargo tree --locked -p "$core_pkg" -e normal,build --all-features --target all -i "$spec" </dev/null 2>&1 | sed 's/^/    /' || true
  done <"$work/guard-paths"

  # Edge rule: no member is in its group's edge kinds of the tree at all (ADR 0049 §5).
  awk '{ print $1 }' "$work/guard-edge-rules" | sort -u >"$work/guard-edge-kinds"
  while read -r kinds; do
    awk -v k="$kinds" '$1 == k { print $2, $3, $4 }' "$work/guard-edge-rules" >"$work/guard-edge-rules.k"
    guarded_paths "$kinds" "$work/guard-edge-rules.k" "$work/guard-edge-paths"
    while read -r crate parent group spec path; do
      case $kinds in
        normal) fail "$crate (guarded group $group) is in cargo tree -e $kinds: a build-time crate may be reached through build edges only (ADR 0049 §5): $path" ;;
        *) fail "$crate (guarded group $group) is in cargo tree -e $kinds: it may be reached only through a proc-macro (ADR 0049 §5): $path" ;;
      esac
      echo "  Every path to it (cargo tree -p $core_pkg -e $kinds --all-features --target all -i $spec):"
      cargo tree --locked -p "$core_pkg" -e "$kinds" --all-features --target all -i "$spec" </dev/null 2>&1 | sed 's/^/    /' || true
    done <"$work/guard-edge-paths"
  done <"$work/guard-edge-kinds"
}

# 6. Every package that a workspace member depends on comes from crates.io, or is itself a workspace
#    member (ADR 0016 §4, ADR 0049 §1). The walk follows normal and build edges from *every*
#    workspace member, not only polyjose, through cargo metadata's resolve graph (all features, all
#    targets), the set the core's tree above and each binding's tree (check 13) are built from.
#    Delta audit D1 of feature 0013: checks 1 and 13 match crates by name, so a path package named
#    after an allowlisted crate (a `zeroize` fork carrying RSA signing) in a binding's tree passed
#    them, and as a non-member it escaped check 9's text scan and scripts/check-rsa-symbols.sh. A
#    path, git or other-registry package that is not a workspace member therefore fails here,
#    naming the member that pulls it in. A `[patch]` or `[replace]` in a manifest shows up as such a
#    source too. cargo-deny's [sources] check (deny.toml) covers git and other registries for the
#    whole workspace, but not path packages.
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
members = sorted(meta["workspace_members"])
core = [i for i in members
        if packages[i]["name"] == pkg_name and os.path.realpath(packages[i]["manifest_path"]) == manifest]
if len(core) != 1:
    sys.exit("expected exactly one workspace member %s at %s, found %d" % (pkg_name, manifest, len(core)))
if meta.get("resolve") is None:
    sys.exit("cargo metadata has no resolve graph")
nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
pulled_by = {}
for member in members:
    seen, todo = {member}, [member]
    while todo:
        for dep in nodes[todo.pop()]["deps"]:
            if dep["pkg"] in seen:
                continue
            # A missing dep_kinds (cargo older than 1.41) is a KeyError: fail closed.
            if any(k["kind"] in (None, "build") for k in dep["dep_kinds"]):
                seen.add(dep["pkg"])
                todo.append(dep["pkg"])
    for pkg_id in seen.difference(members):
        if packages[pkg_id]["source"] != CRATES_IO:
            pulled_by.setdefault(pkg_id, []).append(packages[member]["name"])
for pkg_id in sorted(pulled_by):
    p = packages[pkg_id]
    where = p["source"] or "path " + os.path.dirname(p["manifest_path"])
    print("%s %s from %s, pulled in by %s" % (p["name"], p["version"], where, ", ".join(sorted(pulled_by[pkg_id]))))
' "$work/metadata.json" "$core_pkg" "$core_manifest" >"$work/sources" \
    || die "could not walk the workspace members' dependency graphs in cargo metadata"
  if [ -s "$work/sources" ]; then
    fail "packages that do not come from crates.io (registry+https://github.com/rust-lang/crates.io-index) and are not workspace members (ADR 0016 §4):"
    sed 's/^/  - /' "$work/sources"
    echo "  Depend on the published crates.io release; remove any [patch], [replace] or git/path/registry source."
  fi
}

# 7. No [patch] or [replace] in the workspace root manifest: it swaps a crates.io crate for other
#    code under the same name and version. Check 6 also catches the result; this names the cause.
#    No `exclude` in the root [workspace] either (delta audit D1 of feature 0013, ADR 0016 §4,
#    ADR 0049 §1): it keeps a package in the repository out of the workspace, so out of every
#    per-member check (check 9's text scan, check 13, scripts/check-rsa-symbols.sh). There is none
#    today; one that is needed is added to this check with its reason.
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
  python3 -I -c "$toml_keys_py" Cargo.toml workspace.exclude >"$work/excludes" || die "could not read Cargo.toml"
  if [ -s "$work/excludes" ]; then
    fail "the workspace root Cargo.toml has a [workspace] exclude: a package kept out of the workspace escapes the per-member checks; an exclude that is needed must be added to check 7 of scripts/check-deps.sh with its reason:"
    sed 's/^/  - /' "$work/excludes"
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

# 8, the binding part (security audit L2 of feature 0013, second recommendation). A build script
#    runs arbitrary code on every developer, CI and release machine that builds the crate, and can
#    change what is compiled. The framework-free surface (ADR 0030 §1) and the UniFFI adapter
#    (proc-macro scaffolding, ADR 0032, ADR 0033) need none, so either one having a build script
#    fails, with or without build-dependencies (whose crates check 13 pins). bindings/node keeps
#    the build.rs that napi-build needs (ADR 0031), its build tree pinned by check 13;
#    bindings/wasm has no build script today and is not covered here (check 13 pins its build
#    edges too). A crate named here that is not a workspace package fails: the check cannot vouch
#    for it, so the list must be updated.
no_build_script_dirs="bindings/surface bindings/ffi"
nbs_checked="" # "<package> (<dir>), ...": what the ok line names
check_bindings_no_build_script() {
  local dir pkg checked=""
  for dir in $no_build_script_dirs; do
    python3 -I -c '
import json, os, sys
meta_path, manifest, out = sys.argv[1], os.path.realpath(sys.argv[2]), sys.argv[3]
with open(meta_path, encoding="utf-8") as f:
    meta = json.load(f)
members = set(meta["workspace_members"])
pkgs = [p for p in meta["packages"]
        if p["id"] in members and os.path.realpath(p["manifest_path"]) == manifest]
if len(pkgs) != 1:
    sys.exit(3)
with open(out, "w", encoding="utf-8") as f:
    f.write(pkgs[0]["name"] + "\n")
    for target in pkgs[0]["targets"]:
        if "custom-build" in target["kind"]:
            f.write("build script %s (cargo metadata)\n" % target["src_path"])
' "$work/metadata.json" "$dir/Cargo.toml" "$work/nbs" 2>"$work/nbs.err" || {
      if [ "$?" -eq 3 ]; then
        fail "$dir is not a workspace package, so check 8 cannot hold it to no build script; update no_build_script_dirs in this script"
        continue
      fi
      cat "$work/nbs.err" >&2; die "could not read $dir's targets from cargo metadata"
    }
    pkg=$(sed -n 1p "$work/nbs")
    sed 1d "$work/nbs" >"$work/nbs.found"
    if [ -e "$dir/build.rs" ] || [ -L "$dir/build.rs" ]; then
      echo "$dir/build.rs exists" >>"$work/nbs.found"
    fi
    python3 -I -c "$toml_keys_py" "$dir/Cargo.toml" package.build >>"$work/nbs.found" || die "could not read $dir/Cargo.toml"
    if [ -s "$work/nbs.found" ]; then
      fail "$pkg ($dir) has a build script; polyjose-surface and polyjose-ffi must not have one (security audit L2 of feature 0013, ADR 0030 §1):"
      sort "$work/nbs.found" | sed 's/^/  - /'
    fi
    checked="$checked${checked:+, }$pkg ($dir)"
  done
  nbs_checked=$checked
}

# 9. RSA private-key operations only where and as ADR 0067 allows them (§2, §3, §6; it supersedes
#    ADR 0021 §2-§3): RS*/PS* signing and RSA-OAEP-256 decryption through rsa 0.10's blinded
#    entry points, with polyjose's RNG (ADR 0005), in the RSA files only. Every *.rs file under
#    crates/polyjose/src, bindings/, and the directory of every other
#    workspace member (read from cargo metadata, so build tooling outside bindings/, such as a
#    tools/<name> member, is scanned too; feature 0013 security audit L1) and of each of its
#    targets is scanned as text, comments and strings included, so the check errs toward failing.
#    Exempt, as before: build output and node_modules, and crates/polyjose outside the directories
#    of its library and binary targets (src/): its tests and benches use RSA private keys as test
#    oracles, and dev-dependencies never ship (ADR 0016 §5). The RSA files are
#    crates/polyjose/src/jws/rsa.rs, jwe/rsa_oaep.rs and keys/rsa.rs (or their mod.rs forms).
#    Fails, naming the file and line, on:
#    - outside the RSA files, anywhere: `RsaPrivateKey`, and the blinded private-key entry points
#      `from_components`, `pkcs1v15_sign_with_rng`, `pss_sign_with_rng`, `oaep_decrypt_with_rng`
#      (and their `_prehash_` and `_with_wide_primes` forms); in a file that names the rsa crate
#      (see below), also the word `PrivateKey` (rsa 0.10's name for the type);
#    - anywhere: `BlindedSigningKey`, `DecryptingKey`, `RandomizedDecryptor` (the typed keys and
#      traits, some of them unblinded), `Pkcs1v15Sign` and the `Pss` scheme struct (scheme-based
#      signing can turn blinding off; verification uses the typed `pkcs1v15::VerifyingKey` /
#      `pss::VerifyingKey`), and RSA1_5 (ADR 0067 §3): `Pkcs1v15Encrypt`, `pkcs1v15_encrypt`,
#      `pkcs1v15_decrypt` and their `_with_rng` forms;
#    - anywhere: `use rsa;`, `use rsa as …`, `pub use rsa…` and `extern crate rsa`, which would let
#      other files name rsa items without writing `rsa::`, and the same inside any use tree
#      (`use {rsa as r};`, `pub(crate) use {rsa::pkcs1v15};`, `use r#rsa as r;`; ADR 0049 §1);
#    - anywhere: `#[path …]` (also inside `cfg_attr`) and `include!`, which can load code from a
#      file outside the scanned roots (ADR 0049 §1); include_str!/include_bytes! stay allowed;
#    - in an RSA file: any out-of-line child module (`mod x;`), and any file in jws/rsa/,
#      jwe/rsa_oaep/ or keys/rsa/. A child module reaches the parent's private
#      `use rsa::{pkcs1v15, ..}` as `super::pkcs1v15` without naming rsa (ADR 0049 §1).
#      Inline modules (`#[cfg(test)] mod tests { .. }`) are allowed: their text is the file's.
#      In an RSA file, also a `.sign(` method call and `PrivateKey::sign` (the unblinded
#      `PrivateKey::sign`, or a typed signing key's `Signer::sign`);
#    - in a file that names the rsa crate (`rsa::` not preceded by a path, `use rsa…`, or an `rsa`
#      token anywhere in a use tree, e.g. `use super::{hmac, rsa};`): the word
#      `SigningKey` (e.g. `rsa::pkcs1v15::SigningKey`), the word `Decryptor` (`rsa::traits::
#      Decryptor`), any `decrypt(`/`decrypt_blinded(` call (e.g. an `Oaep` scheme decryption;
#      OAEP-256 decryption is `oaep_decrypt_with_rng` only), key generation (`PrivateKey::new`,
#      `::new_with_exp`, `::from_p_q`, `::from_primes`, `::generate` and the other constructors
#      that make primes or d, and the word `Generate`), the unblinded or OS-RNG-default entry
#      points `pkcs1v15_sign`, `pkcs1v15_sign_prehash`, `pss_sign`, `pss_sign_prehash`,
#      `oaep_decrypt`, `sign_with_default_rng` and the scheme-based `sign_with_rng`, and the word
#      `hazmat`. These words are legitimate elsewhere (`p256::ecdsa::SigningKey`, `cbc::Decryptor`,
#      elliptic-curve's `Generate`), so RSA code lives in files of its own (the RSA files) and
#      refers to child modules named `rsa` as `self::rsa::`;
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
  # shellcheck disable=SC2016 # Python source in single quotes, with no shell expansion meant
  python3 -I -c '
import bisect, json, os, re, sys
meta_path, ws_root, core_dir = sys.argv[1], os.path.realpath(sys.argv[2]), sys.argv[3]
with open(meta_path, encoding="utf-8") as f:
    meta = json.load(f)
rel = lambda p: os.path.relpath(os.path.realpath(p), ws_root).replace(os.sep, "/")
# The scan roots: the two of before, and the directory and target directories of every
# workspace member. The core is scanned only in the directories of its library and binary targets
# (its tests and benches are exempt).
roots = {core_dir + "/src", "bindings"}
members = set(meta["workspace_members"])
if not members:
    sys.exit("cargo metadata lists no workspace members")
seen = 0
for p in meta["packages"]:
    if p["id"] not in members:
        continue
    seen += 1
    core = rel(os.path.dirname(p["manifest_path"])) == core_dir
    if not core:
        roots.add(rel(os.path.dirname(p["manifest_path"])))
    for t in p["targets"]:
        if core and set(t["kind"]) & {"test", "bench", "example"}:
            continue
        roots.add(rel(os.path.dirname(t["src_path"])))
if seen != len(members):
    sys.exit("cargo metadata is missing %d workspace member(s)" % (len(members) - seen))
roots = sorted(roots)
PRUNE = set(roots) | {core_dir}
word = lambda w: re.compile(r"(?<![A-Za-z0-9_])" + w + r"(?![A-Za-z0-9_])")
USE_TREE = r"[A-Za-z0-9_:{},*#\s]"
# The blinded private-key items ADR 0067 §6 allows, in the RSA files only.
BLINDED = re.compile(r"(?<![A-Za-z0-9_])(from_components(?:_with_wide_primes)?|pkcs1v15_sign(?:_prehash)?_with_rng"
                     r"|pss_sign(?:_prehash)?_with_rng|oaep_decrypt_with_rng)(?![A-Za-z0-9_])")
OUTSIDE_RSA_FILES = [
    (word("RsaPrivateKey"), "RsaPrivateKey outside the RSA files: RSA private keys are used only in jws/rsa.rs,"
                            " jwe/rsa_oaep.rs and keys/rsa.rs (ADR 0067 §6)"),
    (BLINDED, lambda m: "%s outside the RSA files: RSA private-key operations stay in jws/rsa.rs,"
                        " jwe/rsa_oaep.rs and keys/rsa.rs (ADR 0067 §6)" % m.group(1)),
]
OUTSIDE_RSA_FILES_NAMING_RSA = [
    (word("PrivateKey"), "PrivateKey in a file that uses the rsa crate, outside the RSA files: RSA private keys"
                         " are used only in jws/rsa.rs, jwe/rsa_oaep.rs and keys/rsa.rs (ADR 0067 §6)"),
]
ANYWHERE = [
    (word("BlindedSigningKey"), "BlindedSigningKey: RSA signing goes through pkcs1v15_sign_with_rng/pss_sign_with_rng only (ADR 0067 §6)"),
    (word("DecryptingKey"), "DecryptingKey: RSA-OAEP-256 decryption goes through oaep_decrypt_with_rng only (ADR 0067 §6)"),
    (word("RandomizedDecryptor"), "RandomizedDecryptor: RSA-OAEP-256 decryption goes through oaep_decrypt_with_rng only (ADR 0067 §6)"),
    (word("Pkcs1v15Sign"), "Pkcs1v15Sign: use the typed rsa::pkcs1v15::VerifyingKey, and pkcs1v15_sign_with_rng to sign (ADR 0067 §6)"),
    (word("Pss"), "Pss: use the typed rsa::pss::VerifyingKey, and pss_sign_with_rng to sign (ADR 0067 §6)"),
    (word("Pkcs1v15Encrypt"), "Pkcs1v15Encrypt: RSA1_5 is not supported in either direction (ADR 0067 §3)"),
    (re.compile(r"(?<![A-Za-z0-9_])(pkcs1v15_(?:en|de)crypt(?:_with_rng)?)(?![A-Za-z0-9_])"),
     lambda m: "%s: RSA1_5 is not supported in either direction (ADR 0067 §3)" % m.group(1)),
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
             "crates/polyjose/src/jwe/rsa_oaep.rs", "crates/polyjose/src/jwe/rsa_oaep/mod.rs",
             "crates/polyjose/src/keys/rsa.rs", "crates/polyjose/src/keys/rsa/mod.rs"}
RSA_CHILD_DIRS = ("crates/polyjose/src/jws/rsa/", "crates/polyjose/src/jwe/rsa_oaep/",
                  "crates/polyjose/src/keys/rsa/")
IN_RSA_MODULE_FILE = [
    (re.compile(r"(?<![A-Za-z0-9_])mod\s+((r#)?[A-Za-z_][A-Za-z0-9_]*)\s*;"),
     lambda m: "mod %s;: an out-of-line child module of an RSA file can use its private rsa imports"
               " through super:: (ADR 0049 §1); use an inline mod %s { .. }" % (m.group(1), m.group(1))),
    (re.compile(r"\.\s*sign\s*(::\s*<[^()]*>)?\s*\("),
     "a .sign( call in an RSA file: the unblinded PrivateKey::sign or a typed signing key; sign with"
     " pkcs1v15_sign_with_rng/pss_sign_with_rng (ADR 0067 §6)"),
    (re.compile(r"(?<![A-Za-z0-9_])(Rsa)?PrivateKey\s*::\s*sign(?![A-Za-z0-9_])"),
     "PrivateKey::sign in an RSA file: unblinded; sign with pkcs1v15_sign_with_rng/pss_sign_with_rng (ADR 0067 §6)"),
]
UNBLINDED = re.compile(r"(?<![A-Za-z0-9_])(pkcs1v15_sign|pkcs1v15_sign_prehash|pss_sign|pss_sign_prehash|oaep_decrypt"
                       r"|sign_with_default_rng|sign_with_rng)(?![A-Za-z0-9_])")
KEYGEN = re.compile(r"(?<![A-Za-z0-9_])(?:Rsa)?PrivateKey\s*::\s*(new|new_unchecked|new_with_exp|new_with_exp_unchecked"
                    r"|from_p_q|from_primes|generate|try_generate|from_rng|try_from_rng|generate_from_rng"
                    r"|try_generate_from_rng)(?![A-Za-z0-9_])")
IN_RSA_FILE = [
    (word("SigningKey"), "SigningKey in a file that uses the rsa crate: typed RSA signing keys are not used;"
                         " sign with pkcs1v15_sign_with_rng/pss_sign_with_rng (ADR 0067 §6)"),
    (word("Decryptor"), "Decryptor in a file that uses the rsa crate: RSA-OAEP-256 decryption goes through"
                        " oaep_decrypt_with_rng only (ADR 0067 §6)"),
    (re.compile(r"(?<![A-Za-z0-9_])decrypt(_blinded)?\s*(::\s*<[^()]*>)?\s*\("),
     "a decrypt call in a file that uses the rsa crate: RSA-OAEP-256 decryption goes through"
     " oaep_decrypt_with_rng only (ADR 0067 §6)"),
    (KEYGEN, lambda m: "PrivateKey::%s in a file that uses the rsa crate: RSA key generation is not supported;"
                       " keys are imported (ADR 0067 §3)" % m.group(1)),
    (word("Generate"), "Generate in a file that uses the rsa crate: RSA key generation is not supported (ADR 0067 §3)"),
    (UNBLINDED, lambda m: "%s in a file that uses the rsa crate: an unblinded, OS-RNG-default or scheme-based RSA"
                          " private-key entry point; use pkcs1v15_sign_with_rng, pss_sign_with_rng or"
                          " oaep_decrypt_with_rng (ADR 0067 §2, §6)" % m.group(1)),
    (word("hazmat"), "hazmat in a file that uses the rsa crate: the rsa hazmat module is not used (ADR 0067 §3)"),
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
        # A directory that is a root of its own is walked once, as that root; the core directory
        # is scanned only through its roots.
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                             and os.path.normpath(os.path.join(dirpath, d)).replace(os.sep, "/") not in PRUNE)
        for name in sorted(filenames):
            if not name.endswith(".rs"):
                continue
            path = os.path.normpath(os.path.join(dirpath, name))
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            lines = text.split("\n")
            views = [flatten((ch, k) for k, ch in enumerate(text)), flatten(strip_comments(text))]
            rel = path.replace(os.sep, "/")
            rules = list(ANYWHERE)
            names_rsa = any(NAMES_RSA.search(line) for line in lines) or any(NAMES_RSA.search(v) for v, _ in views)
            if names_rsa:
                rules += IN_RSA_FILE
            if rel in RSA_FILES:
                rules += IN_RSA_MODULE_FILE
            else:
                rules += OUTSIDE_RSA_FILES
                if names_rsa:
                    rules += OUTSIDE_RSA_FILES_NAMING_RSA
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
' "$work/metadata.json" "$root_physical" "$(dirname "$core_manifest")" >"$work/rsa-uses" || die "could not scan the sources for RSA private-key use"
  if [ -s "$work/rsa-uses" ]; then
    fail "RSA private-key or signing use that ADR 0067 does not allow (§3, §6):"
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

# 11. rsa is built with exactly one feature, `pkcs1v15` (ADR 0067 §1, owner 2026-11-10): rsa 0.10.0
#     puts RSASSA-PKCS1-v1_5 (RS256/384/512, RFC 7518 §3.3) behind it. Any other feature fails:
#     `getrandom`/`os_rng` (blinding randomness is polyjose's own, ADR 0005), `encoding`
#     (pkcs1/pkcs8/spki; polyjose owns DER), `sha1` (ADR 0022), `hazmat`, `std`, `serde`, `pkcs5`.
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
    extra = sorted(set(node["features"]) - {"pkcs1v15"})
    if p["name"] == "rsa" and extra:
        print("rsa %s with features: %s" % (p["version"], ", ".join(extra)))
' "$work/metadata.json" >"$work/rsa-features" || die "could not read rsa's features from cargo metadata"
  if [ -s "$work/rsa-features" ]; then
    fail "rsa must be built with no feature but pkcs1v15 (ADR 0067 §1, ADR 0022):"
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

# 13. The binding crates' trees (ADR 0030 §1, ADR 0016 §4-§5). The frameworks (napi-rs,
#     wasm-bindgen, UniFFI) are not counted against the core, but each binding's tree is pinned as
#     exactly as the core's: bindings/deps-allowlist/<name>.txt lists what the normal and build tree
#     of the package in bindings/<name> adds to the core's,
#       cargo tree -p <package> -e normal,build --target all --prefix none
#     read with default features, with --no-default-features and with --all-features, so neither a
#     target- nor a feature-specific dependency can hide. The build edges are included for the
#     reason they are in the core's tree (check 1): a build script and its build-dependencies run on
#     every developer, CI and release machine that builds the binding, and can change what is
#     compiled, so an unvetted build crate (one behind a new build.rs in the framework-free surface,
#     say) is audit surface like a runtime one (security audit L2 of feature 0013). Dev-dependencies
#     never ship and are not checked, as for the core (ADR 0016 §5). Fails when:
#     - that tree has a crate the file does not list, other than a workspace package, a crate of
#       deps-allowlist.txt or a crate of the core's own tree (check 1 governs those, so a crate the
#       core gains is reported once, by check 1);
#     - the file lists a crate the tree no longer contains (the list stays exact), or one that
#       deps-allowlist.txt already allows (the file lists only what the binding adds);
#     - a workspace package under bindings/ has no file (a new binding cannot skip the gate), or a
#       file's bindings/<name> exists but is not a workspace package;
#     - a line is malformed: not a crate name, a crate listed twice, or a `# serde-only-below:`
#       line (check 14) that is repeated, names no valid crate, or is not followed by a comment
#       line that explains it. A malformed file is not checked further until it is fixed.
#     A file whose bindings/<name> does not exist is skipped with a message (feature 0013 seeds
#     surface.txt before T01 creates bindings/surface). Adding an entry needs an ADR, like the core's.
binding_allowlist_dir=bindings/deps-allowlist

# The serde family (check 14): serde, serde_core, serde_derive, serde_json, serde-wasm-bindgen and any
# other crate named serde-<x> or serde_<x>, as normalized names.
serde_family_re='^serde(-.*)?$'

# binding_packages: "$work/binding-pkgs" ("<dir> <package>" for each workspace package whose
# manifest is in bindings/<dir>), "$work/ws-members" (every workspace package's normalized name).
binding_packages() {
  python3 -I -c '
import json, os, sys
meta_path, bindings = sys.argv[1], os.path.realpath(sys.argv[2])
with open(meta_path, encoding="utf-8") as f:
    meta = json.load(f)
members = set(meta["workspace_members"])
if not members:
    sys.exit("cargo metadata lists no workspace members")
with open(sys.argv[3], "w", encoding="utf-8") as pkgs, open(sys.argv[4], "w", encoding="utf-8") as names:
    for p in sorted(meta["packages"], key=lambda p: p["name"]):
        if p["id"] not in members:
            continue
        names.write(p["name"].lower().replace("_", "-") + "\n")
        d = os.path.dirname(os.path.realpath(p["manifest_path"]))
        if os.path.dirname(d) == bindings:
            pkgs.write("%s %s\n" % (os.path.basename(d), p["name"]))
        elif (d + os.sep).startswith(bindings + os.sep):
            pkgs.write("!%s %s\n" % (os.path.relpath(d, os.path.dirname(bindings)), p["name"]))
' "$work/metadata.json" bindings "$work/binding-pkgs" "$work/ws-members.unsorted" \
    || die "could not list the binding packages from cargo metadata"
  sort -u "$work/ws-members.unsorted" >"$work/ws-members"
}

# parse_binding_allowlist <file> <name>: "$work/bal/<name>.list" (sorted normalized crates) and
# "$work/bal/<name>.below" (the serde-only-below crates), or a fail() per malformed line and
# "$work/bal/<name>.bad".
parse_binding_allowlist() {
  local file=$1 name=$2 kind entry
  awk -v file="$file" '
    function err(line, msg) { printf "ERR %s:%d: %s\n", file, line, msg }
    function norm(s) { s = tolower(s); gsub(/_/, "-", s); return s }
    {
      line = $0; sub(/\r$/, "", line)
      if (pending) {
        if (line !~ /^[ \t]*#[ \t]*[^ \t#]/ || line ~ /^[ \t]*#[ \t]*serde-only-below:/)
          err(dline, "serde-only-below must be followed by comment lines that explain why each path to serde through these crates is build-time only")
        pending = 0
      }
      if (line ~ /^[ \t]*#[ \t]*serde-only-below:/) {
        if (below) err(NR, "serde-only-below appears twice")
        below = 1; pending = 1; dline = NR
        d = line; sub(/^[ \t]*#[ \t]*serde-only-below:[ \t]*/, "", d); sub(/[ \t]+$/, "", d)
        n = split(d, parts, /[ \t]+/)
        if (d == "" || n == 0) err(NR, "serde-only-below names no crate")
        for (k = 1; k <= n; k++) {
          if (parts[k] !~ /^[A-Za-z0-9][A-Za-z0-9_-]*$/) { err(NR, "serde-only-below: not a crate name: " parts[k]); continue }
          print "B", norm(parts[k])
        }
        next
      }
      sub(/#.*/, "", line); gsub(/^[ \t]+|[ \t]+$/, "", line)
      if (line == "") next
      if (line !~ /^[A-Za-z0-9][A-Za-z0-9_-]*$/) { err(NR, "not a crate name: " $0); next }
      name = norm(line)
      if (name in seen) { err(NR, name " is listed twice"); next }
      seen[name] = 1; print "C", name
    }
    END { if (pending) err(dline, "serde-only-below must be followed by comment lines that explain why each path to serde through these crates is build-time only") }
  ' "$file" >"$work/bal/$name.parsed" || die "could not read $file"
  : >"$work/bal/$name.list.unsorted"
  : >"$work/bal/$name.below.unsorted"
  while read -r kind entry; do
    case $kind in
      ERR) fail "$entry"; : >"$work/bal/$name.bad" ;;
      C) echo "$entry" >>"$work/bal/$name.list.unsorted" ;;
      B) echo "$entry" >>"$work/bal/$name.below.unsorted" ;;
    esac
  done <"$work/bal/$name.parsed"
  sort -u "$work/bal/$name.list.unsorted" >"$work/bal/$name.list"
  sort -u "$work/bal/$name.below.unsorted" >"$work/bal/$name.below"
}

# binding_tree <package> <out>: the sorted normalized names in the package's normal and build tree
# with default features, --no-default-features and --all-features, every target, the package
# included.
binding_tree() {
  local flags
  : >"$work/bt.names"
  for flags in --features= --no-default-features --all-features; do
    cargo tree --color never --locked -p "$1" -e normal,build --target all --prefix none "$flags" </dev/null >"$work/bt.raw" 2>"$work/bt.err" \
      || { cat "$work/bt.err" >&2; die "'cargo tree --locked -p $1 -e normal,build --target all --prefix none $flags' failed"; }
    awk -v want="$1" '
      function err(msg) { print msg | "cat 1>&2"; bad = 1 }
      NR == 1 { if ($1 != want) err("unexpected root line: " $0); print $1; next }
      $1 !~ /^[A-Za-z0-9][A-Za-z0-9_-]*$/ || $2 !~ /^v[0-9]/ { err("unexpected line: " $0); next }
      { print $1 }
      END { if (NR == 0) bad = 1; exit bad }
    ' "$work/bt.raw" >>"$work/bt.names" || die "cannot parse the tree of $1; check the script"
  done
  normalize <"$work/bt.names" | sort -u >"$2"
}

check_binding_allowlists() {
  local file name dir pkg
  mkdir -p "$work/bal"
  binding_packages
  # Everything check 1 already governs, plus the workspace's own packages.
  sort -u "$work/allowed" "$work/tree" "$work/ws-members" >"$work/bal-covered"
  : >"$work/bal-checked"
  while read -r dir pkg; do
    case $dir in
      !*) fail "$pkg (${dir#!}) is a workspace package below bindings/ but not directly in bindings/<name>, so no bindings/deps-allowlist/<name>.txt can name it (ADR 0030 §1)" ;;
    esac
  done <"$work/binding-pkgs"
  for file in "$binding_allowlist_dir"/*.txt; do
    [ -e "$file" ] || continue # bash 3.2 has no nullglob by default: an unmatched glob stays literal
    name=${file##*/}; name=${name%.txt}
    parse_binding_allowlist "$file" "$name"
    if [ ! -e "bindings/$name" ] && [ ! -L "bindings/$name" ]; then
      echo "skip: $file: bindings/$name does not exist (yet); it is checked once that package exists"
      continue
    fi
    pkg=$(awk -v d="$name" '$1 == d { print $2 }' "$work/binding-pkgs")
    if [ -z "$pkg" ]; then
      fail "$file: bindings/$name is not a workspace package (no bindings/$name/Cargo.toml in the workspace members)"
      continue
    fi
    echo "$name $pkg" >>"$work/bal-checked"
    [ ! -e "$work/bal/$name.bad" ] || continue
    binding_tree "$pkg" "$work/bal/$name.tree"
    comm -23 "$work/bal/$name.tree" "$work/bal/$name.list" | comm -23 - "$work/bal-covered" >"$work/bal/$name.offenders"
    if [ -s "$work/bal/$name.offenders" ]; then
      fail "the tree of $pkg (bindings/$name) contains crates that $file does not allow (ADR 0030 §1, ADR 0016 §4):"
      sed 's/^/  - /' "$work/bal/$name.offenders"
      echo "  Remove the dependency, or add it to $file with an ADR. To see what pulls one in:"
      echo "    cargo tree -p $pkg -e normal,build --all-features --target all -i <crate>"
    fi
    comm -13 "$work/bal/$name.tree" "$work/bal/$name.list" >"$work/bal/$name.stale"
    if [ -s "$work/bal/$name.stale" ]; then
      fail "$file lists crates the tree of $pkg no longer contains; remove them:"
      sed 's/^/  - /' "$work/bal/$name.stale"
    fi
    comm -12 "$work/bal/$name.list" "$work/allowed" >"$work/bal/$name.dups"
    if [ -s "$work/bal/$name.dups" ]; then
      fail "$file lists crates that deps-allowlist.txt already allows; list only what $pkg adds:"
      sed 's/^/  - /' "$work/bal/$name.dups"
    fi
  done
  while read -r dir pkg; do
    case $dir in !*) continue ;; esac
    awk -v d="$dir" '$1 == d { found = 1 } END { exit !found }' "$work/bal-checked" \
      || fail "$pkg (bindings/$dir) has no $binding_allowlist_dir/$dir.txt; every binding's tree is allowlisted (ADR 0030 §1)"
  done <"$work/binding-pkgs"
}

# 14. No serde in the bindings (ADR 0030 §1: "No serde anywhere, including framework serde
#     features"; ADR 0016 §6). Fails when a serde-family crate (serde_family_re) is in the normal
#     tree of a workspace package under bindings/ (`cargo tree -e normal --all-features --target
#     all`), unless every path to it goes through a crate named on the `# serde-only-below:` line of
#     the package's allowlist. That line exists only for a path that is build-time only, which the
#     comment lines under it must explain (check 13 rejects the line without them): in ffi.txt,
#     UniFFI's proc-macro and its bindgen CLI (feature 0013 T10 moves the CLI into its own package).
#     The line must also stay exact: it fails when the tree has no serde-family crate at all, or
#     when it names a crate the tree does not contain. Each failure prints a shortest offending path.
#     The walk does not enter the core package (polyjose): checks 1-5 govern the core's own tree, in
#     which no serde crate is allowed, and a feature that only a binding's build unifies onto a core
#     crate (uniffi's cargo_metadata turning on `semver/serde` once the core depends on semver) is
#     turned on by a crate of the binding that has its own edge to that crate, so the walk still
#     reaches it outside the core. A change to the core is thus reported once, by the core's checks.
check_no_serde_in_bindings() {
  local dir pkg name below file line crate path
  while read -r dir pkg; do
    case $dir in !*) continue ;; esac
    name=$dir; below="$work/bal/$name.below"
    file="$binding_allowlist_dir/$name.txt"
    # A malformed allowlist is reported by check 13 and not used here.
    if [ -e "$work/bal/$name.bad" ]; then continue; fi
    [ -f "$below" ] || : >"$below"
    cargo tree --color never --locked -p "$pkg" -e normal --all-features --target all --prefix depth </dev/null \
      >"$work/serde.depth" 2>"$work/tree.err" || { cat "$work/tree.err" >&2; die "cargo tree -p $pkg --prefix depth failed"; }
    python3 -I -c '
import re, sys
tree_path, below_path, family, core = sys.argv[1], sys.argv[2], re.compile(sys.argv[3]), sys.argv[4]
def norm(name):
    return name.lower().replace("_", "-")
line_re = re.compile(r"^([0-9]+)([A-Za-z0-9][A-Za-z0-9_-]*) (v[0-9][^ ]*)")
edges, stack, root, spelled, present = {}, [], None, {}, set()
with open(tree_path, encoding="utf-8") as f:
    for number, line in enumerate(f, 1):
        m = line_re.match(line.rstrip("\r\n"))
        if m is None:
            sys.exit("unexpected cargo tree line %d: %s" % (number, line.rstrip()))
        depth, node = int(m.group(1)), (norm(m.group(2)), m.group(3))
        spelled[node] = m.group(2)
        present.add(node[0])
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
with open(below_path, encoding="utf-8") as f:
    below = set(line.strip() for line in f if line.strip())
for name in sorted(below - present):
    print("OUTSIDE %s" % name)
if below and not any(family.match(name) for name in present):
    print("UNNEEDED")
# Breadth-first from the package, never entering a crate of the serde-only-below line or the core.
prev, todo = {root: None}, [root]
while todo:
    nxt = []
    for node in todo:
        for dep in sorted(edges.get(node, ())):
            if dep in prev or dep[0] in below or dep[0] == core:
                continue
            prev[dep] = node
            nxt.append(dep)
    todo = nxt
for node in sorted(prev):
    if family.match(node[0]):
        path, cur = [], node
        while cur is not None:
            path.append(spelled[cur])
            cur = prev[cur]
        print("HIT %s %s" % (spelled[node], " -> ".join(reversed(path))))
' "$work/serde.depth" "$below" "$serde_family_re" "$core_pkg" </dev/null >"$work/serde.hits" \
      || die "could not read the dependency graph of $pkg for serde (see above)"
    while read -r line; do
      case $line in
        "OUTSIDE "*) fail "$file: serde-only-below names ${line#OUTSIDE }, which is not in the tree of $pkg; remove it from the line" ;;
        UNNEEDED) fail "$file: serde-only-below is not needed: no serde-family crate in the tree of $pkg; remove the line and its explanation" ;;
        "HIT "*)
          line=${line#HIT }; crate=${line%% *}; path=${line#* }
          if [ -s "$below" ]; then
            fail "$crate is in the normal tree of $pkg (bindings/$name) (ADR 0030 §1: no serde in the bindings): $path"
            echo "  Not through any crate of the serde-only-below line of $file: $(tr '\n' ' ' <"$below")"
          else
            fail "$crate is in the normal tree of $pkg (bindings/$name) (ADR 0030 §1: no serde in the bindings): $path"
          fi
          echo "  Every path to it: cargo tree -p $pkg -e normal --all-features --target all -i $crate" ;;
      esac
    done <"$work/serde.hits"
  done <"$work/binding-pkgs"
}

check_tree_allowlisted
check_allowlist_not_stale
check_default_features_off
check_credits_match
check_group_rules
check_sources_crates_io
check_no_patch_or_replace
check_core_no_build_script
check_bindings_no_build_script
check_rsa_public_only
check_no_sha1
check_rsa_no_features
check_rsa_not_renamed
check_binding_allowlists
check_no_serde_in_bindings

if [ "$failed" -ne 0 ]; then
  echo "check-deps: FAILED"
  exit 1
fi

echo "ok: the core's tree ($(wc -l <"$work/tree" | tr -d ' ') crates, normal and build) matches $allowlist, all with default features off, all credited in $credits, all from crates.io; RSA private-key use only as ADR 0067 allows, no sha1, rsa with pkcs1v15 only and under its own name (ADR 0067, ADR 0022)"
# One line per group, in allowlist order.
awk '$1 != last { if (NR > 1) printf "\n"; printf "  %s:", $1; last = $1 } { printf " %s", $2 } END { printf "\n" }' "$work/groups"
echo "ok: no build script in $nbs_checked; bindings/node keeps napi-build's build.rs (ADR 0031)"
echo "ok: the binding trees match $binding_allowlist_dir ($(awk '{ printf "%s%s", (NR > 1 ? ", " : ""), $2 }' "$work/bal-checked")), with serde-family crates only below each file's serde-only-below crates (ADR 0030 §1)"
completed=1; exit 0
