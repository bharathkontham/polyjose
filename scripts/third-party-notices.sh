#!/usr/bin/env bash
# Writes THIRD-PARTY-NOTICES.txt for one binary artifact: one workspace package built for one
# target (ADR 0020 §4). MIT, Apache-2.0 and BSD-3-Clause require their notices to be reproduced
# in binary distributions, so every binary package (the npm tarballs, the AAR, the XCFramework
# zip) ships this file. Packaging calls this script; nobody edits a notices file by hand.
#
# Usage: scripts/third-party-notices.sh -p <package> --target <triple> -o <file>
#                                       [--manifest-path <Cargo.toml>]
#
# The crates listed are exactly those compiled into the artifact:
#   cargo tree -p <package> --target <triple> -e normal,no-proc-macro --prefix none
# deduplicated. `-e normal` leaves out dev-dependencies (they never ship) and build-dependencies
# (they run on the builder's machine; nothing of them is linked). `no-proc-macro` leaves out
# procedural macros and the crates only they use, which also run only inside the compiler.
# Target-specific dependencies of other targets are left out by --target.
#
# Features: `cargo tree -p <package>` resolves the package's default features only, and the
# script takes no --features argument. The artifact must therefore be built with
# `-p <package>` and default features, the 0.1.0 configuration of every binding (ADR 0030 §4).
# A build with other features, or `cargo build --workspace` (which unifies features such as
# uniffi's `cli` into the shipped library, see bindings/ffi/Cargo.toml), links crates these
# notices would not list.
#
# For each crate: name, version, the SPDX license expression from `cargo metadata`, the
# repository URL, and the full text of every license or notice file in the crate's source
# directory (LICENSE*, LICENCE*, COPYING*, NOTICE*, matched case-insensitively, including the
# files of a directory with such a name, e.g. LICENSES/). The workspace's own crates (polyjose and
# the binding) come first, under polyjose's MIT LICENSE (ADR 0015).
#
# License policy (fails the run, naming every offending crate, and writes nothing):
#   - every crate needs a `license` expression (`license-file` alone is not enough);
#   - every license the expression names must be in ALLOWED below, whatever its operators: an
#     alternative outside the list (`MIT OR GPL-2.0-only`) fails too. ALLOWED is deny.toml's
#     [licenses].allow, so the notices never accept a license cargo deny rejects (security audit
#     I6). The one exception is Unlicense, which deny.toml does not list: it is accepted only as
#     an OR alternative whose other branch is wholly allowed (memchr's `Unlicense OR MIT`; memchr
#     ships in polyjose-node through napi -> futures -> futures-util), never alone, under an AND
#     or next to a license outside the list. Operators are OR, AND and
#     `WITH LLVM-exception` (on Apache-2.0 only), with parentheses; the deprecated `/` separator
#     counts as OR (Cargo reference, manifest `license` field). Identifiers match
#     case-insensitively, operators case-sensitively (SPDX 2.3 Annex D.2);
#   - a crate that ships no license file must be licensed exactly MIT, Apache-2.0 or MPL-2.0, and
#     gets that license's standard text from scripts/licenses/; any other crate needs its own
#     files (e.g. BSD's copyright line exists only there);
#   - the workspace's own crates must be MIT (ADR 0015).
# MPL-2.0 is allowed, as in deny.toml, for UniFFI (uniffi, uniffi_core, ...), which the Kotlin
# and Swift bindings link (ADR 0032, ADR 0033).
#
# Output is deterministic: crates sorted by name, then SemVer version; license files sorted by
# name; LF line endings; no timestamps and no local paths. Two runs give byte-identical files.
#
# Offline: it runs only `cargo tree` and `cargo metadata`, both with --locked --offline, and reads
# crate sources from the local registry cache. Run `cargo fetch --locked` first on a cold cache.
# It writes nothing but the -o file, and that only on success.
#
# Exit status: 0 written; 1 a crate breaks the license policy (each offender is named) or a
# command failed; 2 usage error.
# Runs on macOS /bin/bash 3.2 and on Linux bash.
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: $0 -p <package> --target <triple> -o <file> [--manifest-path <Cargo.toml>]" >&2
  exit 2
}
die() { echo "third-party-notices: $*" >&2; exit 1; }

repo=$(cd "$(dirname "$0")/.." && pwd -P)
pkg="" target="" out="" manifest="$repo/Cargo.toml"
while [ $# -gt 0 ]; do
  case $1 in
    -p | --package) [ $# -ge 2 ] || usage; pkg=$2; shift 2 ;;
    --target) [ $# -ge 2 ] || usage; target=$2; shift 2 ;;
    -o | --output) [ $# -ge 2 ] || usage; out=$2; shift 2 ;;
    --manifest-path) [ $# -ge 2 ] || usage; manifest=$2; shift 2 ;;
    -h | --help) usage ;;
    *) echo "third-party-notices: unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$pkg" ] && [ -n "$target" ] && [ -n "$out" ] || usage
case $target in all) die "--target all is not one artifact; name its target triple" ;; esac
[ -f "$manifest" ] || die "no manifest at $manifest"
out_dir=$(dirname "$out")
[ -d "$out_dir" ] || die "output directory $out_dir does not exist"

command -v cargo >/dev/null 2>&1 || die "cargo not found on PATH"
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"

work=$(mktemp -d "${TMPDIR:-/tmp}/third-party-notices.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$work"' EXIT

offline_hint="(offline: run \`cargo fetch --locked\` first if the registry cache lacks a crate)"
cargo tree --manifest-path "$manifest" --locked --offline -p "$pkg" --target "$target" \
  -e normal,no-proc-macro --prefix none -f '{p}' >"$work/tree.txt" 2>"$work/tree.err" \
  || { cat "$work/tree.err" >&2; die "cargo tree failed $offline_hint"; }
cargo metadata --manifest-path "$manifest" --locked --offline --format-version 1 \
  >"$work/metadata.json" 2>"$work/metadata.err" \
  || { cat "$work/metadata.err" >&2; die "cargo metadata failed $offline_hint"; }

python3 -I - "$work/tree.txt" "$work/metadata.json" "$repo/scripts/licenses" "$pkg" "$target" \
  "$work/notices.txt" <<'PY' || exit 1
import json
import os
import re
import sys

tree_path, metadata_path, licenses_dir, root_name, target, out_path = sys.argv[1:7]
RULE = "=" * 80
errors = []
offenders = set()  # the "<name> <version>" of every crate that breaks the policy


def reject(label, reason):
    errors.append("%s: %s" % (label, reason))
    offenders.add(label)

with open(metadata_path, encoding="utf-8") as f:
    metadata = json.load(f)
packages = metadata["packages"]
members = set(metadata["workspace_members"])
by_name_version = {}
for p in packages:
    by_name_version.setdefault((p["name"], p["version"]), []).append(p)


def fail(msg):
    sys.stderr.write("third-party-notices: %s\n" % msg)
    sys.exit(1)


# --- The crates of the artifact: `cargo tree -f {p}` lines ------------------------------------
# A line is "<name> v<version>", plus " (<path or source>)" for a non-crates.io package, plus
# " (proc-macro)" for a procedural macro, plus " (*)" when the package was printed before.
LINE = re.compile(r"^(?P<name>[A-Za-z0-9_-]+) v(?P<version>[^ ]+)(?: \((?P<source>.*)\))?$")
selected = {}
with open(tree_path, encoding="utf-8") as f:
    for raw in f.read().splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.endswith(" (*)"):
            line = line[: -len(" (*)")]
        if line.endswith(" (proc-macro)"):
            # Never linked. `-e no-proc-macro` already leaves these out.
            continue
        m = LINE.match(line)
        if not m:
            fail("cannot read cargo tree line: %r" % raw)
        candidates = by_name_version.get((m.group("name"), m.group("version")), [])
        if len(candidates) > 1 and m.group("source"):
            src = m.group("source")
            candidates = [p for p in candidates
                          if os.path.dirname(p["manifest_path"]) == src
                          or (p.get("source") or "").startswith(src)]
        elif len(candidates) > 1:
            candidates = [p for p in candidates
                          if (p.get("source") or "").startswith("registry+")]
        if len(candidates) != 1:
            fail("cannot match cargo tree line %r to exactly one cargo metadata package" % raw)
        selected[candidates[0]["id"]] = candidates[0]

root = [p for p in selected.values() if p["name"] == root_name and p["id"] in members]
if not root:
    fail("-p %s must name a workspace member" % root_name)
root = root[0]


# --- Sorting --------------------------------------------------------------------------------
def version_key(v):
    """SemVer 2.0.0 §11 precedence: numeric core, then a pre-release sorts before the release;
    pre-release identifiers compare numerically when numeric. Build metadata breaks ties so the
    order stays total and stable."""
    core, _, build = v.partition("+")
    core, _, pre = core.partition("-")
    nums = tuple(int(x) if x.isdigit() else 0 for x in core.split("."))
    pre_key = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")) if pre else ()
    return (nums, 0 if pre else 1, pre_key, build)


def crate_key(p):
    return (p["name"], version_key(p["version"]))


# --- License texts --------------------------------------------------------------------------
NOTICE_FILE = re.compile(r"^(licen[cs]e|copying|notice)", re.IGNORECASE)


def read_text(path):
    with open(path, "rb") as f:
        data = f.read()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    text = data.decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.rstrip() + "\n"


def license_files(p):
    """Every LICENSE*/LICENCE*/COPYING*/NOTICE* file in the crate's source directory, and the
    files of a directory so named (e.g. LICENSES/MIT.txt), sorted by relative path."""
    crate_dir = os.path.dirname(p["manifest_path"])
    found = []
    for entry in sorted(os.listdir(crate_dir)):
        if not NOTICE_FILE.match(entry):
            continue
        path = os.path.join(crate_dir, entry)
        if os.path.isfile(path):
            found.append((entry, path))
        elif os.path.isdir(path):
            for sub in sorted(os.listdir(path)):
                if os.path.isfile(os.path.join(path, sub)):
                    found.append((entry + "/" + sub, os.path.join(path, sub)))
    lf = p.get("license_file")
    if lf:
        path = os.path.normpath(os.path.join(crate_dir, lf))
        rel = os.path.relpath(path, crate_dir)
        if os.path.isfile(path) and rel not in [r for r, _ in found]:
            found.append((rel, path))
            found.sort()
    return [(rel, read_text(path)) for rel, path in found]


# Single-license expressions whose standard text scripts/licenses/ ships, for a crate that has
# no license file of its own.
STANDARD_TEXTS = {"MIT": "MIT.txt", "Apache-2.0": "Apache-2.0.txt", "MPL-2.0": "MPL-2.0.txt"}


def standard_text(single):
    name = STANDARD_TEXTS.get(single or "")
    if not name:
        return None
    return read_text(os.path.join(licenses_dir, name))


def source_line(p):
    src = p.get("source") or ""
    if src == "registry+https://github.com/rust-lang/crates.io-index":
        return "https://crates.io/crates/%s/%s" % (p["name"], p["version"])
    if src.startswith("git+"):
        return src.split("#", 1)[0][len("git+"):]
    if not src:
        return "local path crate (not published)"
    return src


# --- License policy -------------------------------------------------------------------------
# The allowlist (ADR 0020 §4; all compatible with polyjose's MIT, ADR 0015): deny.toml's
# [licenses].allow, and the one exception with the only license it may modify.
ALLOWED = ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "Unicode-3.0", "Zlib",
           "MPL-2.0"]
EXCEPTIONS = {"LLVM-exception": "Apache-2.0"}
# Licenses deny.toml does not allow, accepted only as a direct OR alternative to a wholly allowed
# branch, so the allowed license can always be chosen (security audit I6; memchr).
OR_ONLY = ["Unlicense"]
CANONICAL = dict((x.lower(), x) for x in ALLOWED)
CANONICAL_EXC = dict((x.lower(), x) for x in EXCEPTIONS)
CANONICAL_OR_ONLY = dict((x.lower(), x) for x in OR_ONLY)


class BadExpression(Exception):
    pass


def check_expression(expr):
    """Checks an SPDX license expression (SPDX 2.3 Annex D) against ALLOWED and OR_ONLY.
    Returns (problems, single): the list of reasons it is rejected (empty if accepted), and the
    canonical identifier when the whole expression is exactly one license without an exception
    (else None).

    The tree's nodes are ("LIC", name, allowed), ("OR_ONLY", name), ("WITH", allowed),
    ("OR", a, b) and ("AND", a, b)."""
    # `/` is Cargo's deprecated alternative to OR.
    tokens = ["OR" if t == "/" else t for t in re.findall(r"[()/]|[^\s()/]+", expr)]
    problems = []
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def take():
        t = peek()
        pos[0] += 1
        return t

    def or_expr():
        n = and_expr()
        while peek() == "OR":
            take()
            n = ("OR", n, and_expr())
        return n

    def and_expr():
        n = atom()
        while peek() == "AND":
            take()
            n = ("AND", n, atom())
        return n

    def atom():
        t = take()
        if t is None:
            raise BadExpression("it ends where a license is expected")
        if t == "(":
            n = or_expr()
            if take() != ")":
                raise BadExpression("unbalanced parentheses")
            return n
        if t in ("AND", "OR", "WITH", ")"):
            raise BadExpression("%r where a license is expected" % t)
        lic = CANONICAL.get(t.lower())
        or_only = CANONICAL_OR_ONLY.get(t.lower())
        if lic is None and or_only is None:
            problems.append("%r is not an allowed license (%s; %s only as an OR alternative)"
                            % (t, ", ".join(ALLOWED), ", ".join(OR_ONLY)))
        if peek() != "WITH":
            if or_only is not None:
                return ("OR_ONLY", or_only)
            return ("LIC", lic or t, lic is not None)
        take()
        if or_only is not None:
            problems.append("%s takes no WITH exception here: it is accepted only as an OR "
                            "alternative" % or_only)
        e = take()
        if e is None:
            raise BadExpression("WITH without an exception")
        exc = CANONICAL_EXC.get(e.lower())
        if exc is None:
            problems.append("exception %r is not allowed (only %s)" % (e, ", ".join(sorted(EXCEPTIONS))))
        elif lic is not None and EXCEPTIONS[exc] != lic:
            problems.append("%s applies only to %s, not %s" % (exc, EXCEPTIONS[exc], lic))
        return ("WITH", lic is not None and exc is not None and EXCEPTIONS[exc] == lic)

    def wholly_allowed(n):
        if n[0] == "LIC":
            return n[2]
        if n[0] == "WITH":
            return n[1]
        if n[0] == "OR_ONLY":
            return False
        return wholly_allowed(n[1]) and wholly_allowed(n[2])

    def check_or_only(n, alternative_allowed):
        """An OR_ONLY license passes only as a direct operand of an OR whose other operand is
        wholly allowed (alternative_allowed)."""
        if n[0] == "OR_ONLY":
            if not alternative_allowed:
                problems.append("%s is accepted only as an OR alternative to an allowed license "
                                "(deny.toml does not allow it)" % n[1])
        elif n[0] == "OR":
            check_or_only(n[1], wholly_allowed(n[2]))
            check_or_only(n[2], wholly_allowed(n[1]))
        elif n[0] == "AND":
            check_or_only(n[1], False)
            check_or_only(n[2], False)

    try:
        node = or_expr()
        if peek() is not None:
            raise BadExpression("unexpected %r" % peek())
    except BadExpression as e:
        return (["malformed expression: %s" % e], None)
    check_or_only(node, False)
    single = node[1] if node[0] == "LIC" and node[2] and not problems else None
    return (problems, single)


single_license = {}
for p in sorted(selected.values(), key=crate_key):
    label = "%s %s" % (p["name"], p["version"])
    expr = (p.get("license") or "").strip()
    if not expr:
        reject(label, "no license expression in its Cargo.toml (`license-file` alone is not accepted)")
        continue
    problems, single = check_expression(expr)
    for problem in problems:
        reject(label, "license %r: %s" % (expr, problem))
    single_license[p["id"]] = single


# --- The workspace's own crates -------------------------------------------------------------
own = sorted((p for p in selected.values() if p["id"] in members), key=crate_key)
third = sorted((p for p in selected.values() if p["id"] not in members), key=crate_key)

polyjose_license = os.path.join(metadata["workspace_root"], "LICENSE")
if not os.path.isfile(polyjose_license):
    fail("no LICENSE at the workspace root (%s)" % polyjose_license)
for p in own:
    if (p.get("license") or "").strip() != "MIT":
        reject("%s %s" % (p["name"], p["version"]),
               "a workspace crate must be licensed MIT (ADR 0015), not %r" % p.get("license"))

out = []
w = out.append
w("THIRD-PARTY NOTICES")
w("")
w("Artifact: %s %s" % (root["name"], root["version"]))
w("Target: %s" % target)
w("")
w("This artifact is polyjose, MIT licensed. It contains the Rust crates listed below: exactly the")
w("crates compiled into it for this target (cargo tree -p %s --target %s" % (root["name"], target))
w("-e normal,no-proc-macro). Build-time-only crates (build-dependencies and procedural macros) and")
w("dev-dependencies are not part of the artifact. For each crate: its license (SPDX expression from")
w("its Cargo.toml), its repository and source, and the license and notice files it ships.")
w("Generated by scripts/third-party-notices.sh; do not edit.")
w("")
w(RULE)
w("polyjose")
w(RULE)
w("Crates: %s" % ", ".join("%s %s" % (p["name"], p["version"]) for p in own))
w("License: MIT")
repos = sorted(set(p["repository"] for p in own if p.get("repository")))
w("Repository: %s" % (", ".join(repos) if repos else "not stated"))
w("")
w("--- License text: LICENSE ---")
w(read_text(polyjose_license).rstrip("\n"))
w("")
w(RULE)
w("Third-party crates (%d)" % len(third))
w(RULE)
for p in third:
    w("%s %s  %s" % (p["name"], p["version"], p.get("license") or "(no license expression)"))
w("")

for p in third:
    label = "%s %s" % (p["name"], p["version"])
    texts = license_files(p)
    w(RULE)
    w(label)
    w(RULE)
    w("License: %s" % (p.get("license") or "(none)"))
    w("Repository: %s" % (p.get("repository") or p.get("homepage") or "not stated"))
    w("Source: %s" % source_line(p))
    if p.get("authors"):
        w("Authors: %s" % ", ".join(p["authors"]))
    w("")
    if texts:
        for rel, text in texts:
            w("--- License text: %s ---" % rel)
            w(text.rstrip("\n"))
            w("")
        continue
    if label in offenders:
        continue  # its expression is already rejected
    std = standard_text(single_license[p["id"]])
    if std is None:
        reject(label, "ships no license file (LICENSE*, COPYING*, NOTICE*) and its license %r is "
               "not one with a standard text in scripts/licenses/ (%s)"
               % (p.get("license"), ", ".join(sorted(STANDARD_TEXTS))))
        continue
    w("--- License text: standard %s (the crate ships no license file; copyright: its authors) ---"
      % single_license[p["id"]])
    w(std.rstrip("\n"))
    w("")

if errors:
    for e in errors:
        sys.stderr.write("third-party-notices: %s\n" % e)
    fail("%d crate(s) of %s for %s break the license policy (ADR 0020 §4); no file written"
         % (len(offenders), root_name, target))

with open(out_path, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(out).rstrip("\n") + "\n")
PY

# Replace the -o file only now, in one step, so a failed run leaves no partial file behind.
tmp_out="$out.tmp.$$"
if ! { cp "$work/notices.txt" "$tmp_out" && mv -f "$tmp_out" "$out"; }; then
  rm -f "$tmp_out"
  die "could not write $out"
fi
echo "third-party-notices: wrote $out ($pkg, $target)"
