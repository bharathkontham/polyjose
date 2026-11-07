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
# For each crate: name, version, the SPDX license expression from `cargo metadata`, the
# repository URL, and the full text of every license or notice file in the crate's source
# directory (LICENSE*, LICENCE*, COPYING*, NOTICE*, matched case-insensitively, including the
# files of a directory with such a name, e.g. LICENSES/). The workspace's own crates (polyjose and
# the binding) come first, under polyjose's MIT LICENSE (ADR 0015).
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


def standard_text(expr):
    name = STANDARD_TEXTS.get((expr or "").strip())
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


# --- The workspace's own crates -------------------------------------------------------------
own = sorted((p for p in selected.values() if p["id"] in members), key=crate_key)
third = sorted((p for p in selected.values() if p["id"] not in members), key=crate_key)

polyjose_license = os.path.join(metadata["workspace_root"], "LICENSE")
if not os.path.isfile(polyjose_license):
    fail("no LICENSE at the workspace root (%s)" % polyjose_license)
for p in own:
    if (p.get("license") or "").strip() != "MIT":
        errors.append("%s %s: a workspace crate must be licensed MIT (ADR 0015), not %r"
                      % (p["name"], p["version"], p.get("license")))

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
    std = standard_text(p.get("license"))
    if std is None:
        errors.append("%s: ships no license file (LICENSE*, COPYING*, NOTICE*) and its license %r "
                      "is not one with a standard text in scripts/licenses/ (%s)"
                      % (label, p.get("license"), ", ".join(sorted(STANDARD_TEXTS))))
        continue
    w("--- License text: standard %s (the crate ships no license file; copyright: its authors) ---"
      % p["license"].strip())
    w(std.rstrip("\n"))
    w("")

if errors:
    for e in errors:
        sys.stderr.write("third-party-notices: %s\n" % e)
    fail("%d crate(s) of %s for %s break the license policy (ADR 0020 §4); no file written"
         % (len(errors), root_name, target))

with open(out_path, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(out).rstrip("\n") + "\n")
PY

# Replace the -o file only now, in one step, so a failed run leaves no partial file behind.
tmp_out="$out.tmp.$$"
cp "$work/notices.txt" "$tmp_out" && mv -f "$tmp_out" "$out" || { rm -f "$tmp_out"; die "could not write $out"; }
echo "third-party-notices: wrote $out ($pkg, $target)"
