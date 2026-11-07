#!/usr/bin/env bash
# Builds the @polyjose/wasm package (feature 0006 T03; ADR 0031 §3, §4; ADR 0047) and stops at the
# tarball. Publishing is Gate 3 (ADR 0011); this script never publishes.
#
#   bindings/wasm/scripts/build-package.sh [--no-pack]
#
#   1. guards: no publish command in the package sources, no hand-written JavaScript or
#      declarations under bindings/wasm (ADR 0047), the exports conditions in ADR 0031 §3 order;
#   2. one `wasm-pack build --release --target web --no-pack` (wasm-opt -Oz through
#      [package.metadata.wasm-pack.profile.release] in bindings/wasm/Cargo.toml), into a staging
#      directory under the workspace target/; prints the .wasm's raw, gzip -9 and brotli -q 11
#      sizes. The budget is 1 MiB raw (ADR 0031 §3);
#   3. the shared facade, built in bindings/js as bindings/js/test.sh does (npm ci, generate
#      src/error-codes.ts, tsc -p .); its sources are never edited;
#   4. this package's TypeScript (bindings/wasm/js/*.ts, *.mts), compiled with bindings/js's
#      pinned tsc and the ADR 0047 options (extending bindings/js/tsconfig.json), in a staging
#      copy laid out like the package so its imports resolve. With them, the machine-generated
#      integrity.ts (0006 F05, audit L1): the package version, read back from the generated
#      package.json, and the SHA-384 of the final (post-wasm-opt) .wasm, which the entries check
#      before the module is instantiated;
#   5. bindings/wasm/pkg/: the .wasm and its `web` glue, the facade's compiled .js and .d.ts
#      unchanged in facade/, backend.js, integrity.js, index.js and index.d.ts, the entries node.mjs,
#      browser.mjs and workerd.mjs, LICENSE, README.md, THIRD-PARTY-NOTICES.txt (from
#      scripts/third-party-notices.sh, ADR 0020 §4) and package.json from package.template.json.
#      No .ts source and no source map is shipped. It checks that no entry uses top-level await
#      and that the directory holds exactly the template's `files` (plus package.json);
#   6. the size budget: over 1 MiB raw fails here (exit 3), with pkg/ assembled for inspection;
#   7. unless --no-pack: `npm pack` into dist/npm/ at the repository root, and a check that the
#      tarball holds exactly pkg/.
#
# Exit status: 0 done; 1 a step failed; 2 usage error; 3 the package is assembled but the .wasm
# is over the size budget (no tarball is written). Runs on macOS /bin/bash 3.2 and Linux bash 5.
# Needs cargo with the wasm32-unknown-unknown target, wasm-pack 0.15.1, node (>= 22.18, for the
# facade's error-code generator; it also hashes the .wasm), npm, gzip and brotli.
set -euo pipefail
export LC_ALL=C

# Extra `cargo build` arguments for the wasm build, passed after `--` to wasm-pack. ADR 0059
# (superseding ADR 0031 §3 in part): this one invocation overrides the workspace release profile's
# opt-level to "z"; the rest of the profile (fat LTO, one codegen unit, stripped) is used as it is,
# and the native release builds keep opt-level 3, since the override exists only on this command
# line. Measured in 0006 T03: a [profile.release.package.polyjose-wasm] override does not reach
# the budget under fat LTO (1,178,395 bytes raw), because every dependency is optimized at
# opt-level 3 before the link. It is not a named profile because wasm-pack 0.15.1's
# `--profile <name>` hard-codes wasm-opt `-O` and ignores the wasm-opt arguments of the package
# metadata (`-Oz` and the feature flags), so wasm-opt then rejects the stripped module.
WASM_CARGO_ARGS=(--config 'profile.release.opt-level="z"')

# The size budget of the .wasm, in bytes (ADR 0031 §3: 1 MiB raw).
SIZE_BUDGET=1048576

me=build-package
die() { echo "$me: $*" >&2; exit 1; }

pack=1
for arg in "$@"; do
  case $arg in
    --no-pack) pack=0 ;;
    *) echo "usage: $0 [--no-pack]" >&2; exit 2 ;;
  esac
done

wasm=$(cd "$(dirname "$0")/.." && pwd -P) || exit 1
repo=$(cd "$wasm/../.." && pwd -P) || exit 1
js=$repo/bindings/js
stage=$repo/target/wasm-package
pkg=$wasm/pkg
dist=$repo/dist/npm
template=$wasm/package.template.json

# --- 1. Guards ---------------------------------------------------------------------------------

# No rustflags from the environment (0006 review N2, ADR 0005). getrandom 0.4.3 selects a
# `getrandom_backend` cfg (`custom`, `unsupported`, `extern_impl`) before `wasm_js`, so one
# `--cfg getrandom_backend=…` here would silently change the RNG of the shipped .wasm. Cargo
# reads rustflags from these four variables, ahead of any config file (CARGO_ENCODED_RUSTFLAGS,
# then RUSTFLAGS, then target.<triple>.rustflags, then build.rustflags); the shipped build takes
# its only Cargo override from WASM_CARGO_ARGS above (ADR 0059). An empty variable is no flag.
for var in RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS; do
  [ -z "${!var:-}" ] || die "$var is set; unset it: the shipped .wasm is built without environment rustflags (0006 review N2, ADR 0005)"
done

for tool in cargo wasm-pack node npm gzip brotli; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"
done

echo "==> $me: no publish command (publishing is Gate 3, ADR 0011)"
publish_re='(npm|pnpm|yarn|wasm-pack)[[:space:]]+publish|napi[[:space:]]+pre-?publish|"(pre|post)?publish(Only)?"[[:space:]]*:'
if hits=$(grep -nE "$publish_re" "$0" "$template" "$wasm"/js/* 2>/dev/null); then
  echo "$hits"; die "a publish command or publish hook in the package sources"
fi
grep -q '"scripts"' "$template" && die "package.template.json must have no \"scripts\" (npm pack would run them)"

echo "==> $me: TypeScript only (ADR 0047)"
# find, not only git ls-files: an untracked file must fail too. pkg/ is this script's output.
stray=$(cd "$wasm" && find . -path ./pkg -prune -o -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \
  -o -name '*.d.ts' -o -name '*.d.mts' -o -name '*.d.cts' \) -print)
[ -z "$stray" ] || { echo "$stray"; die "hand-written JavaScript or declarations under bindings/wasm (ADR 0047)"; }
if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  tracked=$(git -C "$repo" ls-files -- 'bindings/wasm/*.js' 'bindings/wasm/*.mjs' 'bindings/wasm/*.cjs' \
    'bindings/wasm/*.d.ts' 'bindings/wasm/*.d.mts' 'bindings/wasm/*.d.cts')
  [ -z "$tracked" ] || die "tracked JavaScript or declarations under bindings/wasm: $tracked"
fi

echo "==> $me: exports conditions in ADR 0031 §3 order"
order=$(awk '/"exports"/ { inside = 1 } inside && /^    }/ { exit }
  inside && /^      "[a-z]+":/ { c = $1; gsub(/[":]/, "", c); printf "%s ", c }' "$template")
[ "$order" = "types workerd worker node browser import default " ] \
  || die "package.template.json exports conditions are '$order', expected: types workerd worker node browser import default"

# --- 2. The wasm build -------------------------------------------------------------------------

echo "==> $me: wasm-pack build --release --target web --no-pack"
rm -rf "$stage"
mkdir -p "$stage" || die "could not create $stage"
cargo_extra=()
if [ ${#WASM_CARGO_ARGS[@]} -gt 0 ]; then cargo_extra=(-- "${WASM_CARGO_ARGS[@]}"); fi
(cd "$repo" && wasm-pack build --release --target web --no-pack --no-gitignore \
  --out-dir "$stage/glue" "$wasm" ${cargo_extra[@]+"${cargo_extra[@]}"}) || die "wasm-pack build failed"
glue=$stage/glue
for f in polyjose_wasm_bg.wasm polyjose_wasm.js polyjose_wasm.d.ts; do
  [ -f "$glue/$f" ] || die "wasm-pack did not produce $f"
done

raw=$(wc -c <"$glue/polyjose_wasm_bg.wasm" | tr -d ' ')
gz=$(gzip -9 -c "$glue/polyjose_wasm_bg.wasm" | wc -c | tr -d ' ')
br=$(brotli -q 11 -c "$glue/polyjose_wasm_bg.wasm" | wc -c | tr -d ' ')
echo "$me: polyjose_wasm_bg.wasm: raw $raw bytes, gzip -9 $gz bytes, brotli -q 11 $br bytes (budget $SIZE_BUDGET raw)"

# --- 3. The shared facade ----------------------------------------------------------------------

echo "==> $me: bindings/js facade (npm ci, generate ErrorCode, tsc)"
(cd "$js" && npm ci --no-audit --no-fund --loglevel=error) || die "npm ci failed in bindings/js"
(cd "$js" && node tools/gen-error-codes.ts) || die "node tools/gen-error-codes.ts failed in bindings/js"
rm -rf "$js/dist"
(cd "$js" && ./node_modules/.bin/tsc -p .) || die "tsc failed in bindings/js"
facade=$js/dist/src
[ -f "$facade/api.js" ] && [ -f "$facade/api.d.ts" ] || die "tsc did not generate bindings/js/dist/src/api.js(.d.ts)"

# --- 4. This package's TypeScript --------------------------------------------------------------

version=$(awk '/^\[workspace\.package\]/ { inside = 1; next } /^\[/ { inside = 0 }
  inside && /^version[[:space:]]*=/ { v = $0; sub(/^[^"]*"/, "", v); sub(/".*/, "", v); print v; exit }' "$repo/Cargo.toml")
[ -n "$version" ] || die "no [workspace.package] version in Cargo.toml"
sed "s/@VERSION@/$version/" "$template" >"$stage/package.json"
grep -q '@VERSION@' "$stage/package.json" && die "package.json still has a @VERSION@ placeholder"

# The values the entries check at load time (0006 F05, audit L1), baked in now and never read at
# run time from a mutable place: the version from the package.json just generated, and the
# SHA-384 of the .wasm exactly as it is shipped (wasm-opt has run), in base64 as W3C Subresource
# Integrity metadata writes it, for fetch's `integrity` and node:crypto alike.
# sha384_b64 <file>: the SHA-384 (FIPS 180-4) of the file, base64, with node:crypto; node is
# already required (tsc, the error-code generator), so the build needs no other hasher.
sha384_b64() {
  node -e 'process.stdout.write(require("node:crypto").createHash("sha384").update(require("node:fs").readFileSync(process.argv[1])).digest("base64"))' "$1"
}
pkg_version=$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$stage/package.json")
[ "$pkg_version" = "$version" ] || die "the generated package.json has version '$pkg_version', expected '$version'"
wasm_sha384=$(sha384_b64 "$glue/polyjose_wasm_bg.wasm") || die "node could not hash polyjose_wasm_bg.wasm"
[ ${#wasm_sha384} -eq 64 ] || die "the SHA-384 of polyjose_wasm_bg.wasm is not 64 base64 characters: '$wasm_sha384'"
echo "$me: polyjose_wasm_bg.wasm: sha384-$wasm_sha384"

echo "==> $me: tsc (bindings/wasm/js, ADR 0047 options)"
ts=$stage/ts
mkdir -p "$ts/facade" || die "could not create $ts"
# The staging copy is laid out like the package: package.json ("type": "module") makes the .ts
# files ES modules under nodenext, and ./facade/ and the glue resolve next to them.
cp "$stage/package.json" "$ts/"
(cd "$facade" && find . -type f \( -name '*.js' -o -name '*.d.ts' \) -exec cp {} "$ts/facade/" \;)
cp "$glue/polyjose_wasm.js" "$glue/polyjose_wasm.d.ts" "$ts/"
sources=()
for f in "$wasm"/js/*.ts "$wasm"/js/*.mts; do
  [ -e "$f" ] || continue
  cp "$f" "$ts/" && sources+=("${f##*/}")
done
[ ${#sources[@]} -gt 0 ] || die "no TypeScript sources in bindings/wasm/js"
[ ! -e "$wasm/js/integrity.ts" ] || die "bindings/wasm/js/integrity.ts must not exist: this script generates it"
cat >"$ts/integrity.ts" <<EOF
// Generated by bindings/wasm/scripts/build-package.sh (feature 0006 F05, audit L1). Do not edit.

/** The version of this package, from its package.json; the module's version() must equal it. */
export const PACKAGE_VERSION = "$pkg_version";

/**
 * The SHA-384 of polyjose_wasm_bg.wasm as shipped, base64 (W3C Subresource Integrity): the
 * browser entry fetches the module with this integrity, the Node entry hashes what it reads.
 */
export const WASM_SHA384 = "$wasm_sha384";
EOF
sources+=(integrity.ts)
files_json=$(printf '"%s", ' "${sources[@]}"); files_json=${files_json%, }
# The ADR 0047 options come from bindings/js/tsconfig.json. Added here: the DOM library, which
# the generated glue's declarations use (RequestInfo, Response, URL, BufferSource, WebAssembly),
# and legacy module detection, so wasm-import.ts (no import or export) is a script whose ambient
# module types the workerd entry's static .wasm import.
cat >"$ts/tsconfig.json" <<EOF
{
  "extends": "$js/tsconfig.json",
  "compilerOptions": {
    "rootDir": ".",
    "outDir": "out",
    "lib": ["es2022", "dom"],
    "moduleDetection": "legacy"
  },
  "include": [],
  "files": [$files_json]
}
EOF
(cd "$ts" && "$js/node_modules/.bin/tsc" -p .) || die "tsc failed for bindings/wasm/js"
out=$ts/out

# --- 5. Assemble pkg/ --------------------------------------------------------------------------

echo "==> $me: assemble bindings/wasm/pkg"
rm -rf "$pkg"
mkdir -p "$pkg/facade" || die "could not create $pkg"
cp "$glue/polyjose_wasm_bg.wasm" "$glue/polyjose_wasm.js" "$glue/polyjose_wasm.d.ts" "$pkg/"
(cd "$facade" && find . -type f \( -name '*.js' -o -name '*.d.ts' \) -exec cp {} "$pkg/facade/" \;)
for f in backend.js integrity.js index.js index.d.ts node.mjs browser.mjs workerd.mjs; do
  [ -f "$out/$f" ] || die "tsc did not produce $f"
  cp "$out/$f" "$pkg/"
done
cp "$repo/LICENSE" "$pkg/LICENSE"
cp "$wasm/js/README.md" "$pkg/README.md"
cp "$stage/package.json" "$pkg/package.json"
"$repo/scripts/third-party-notices.sh" -p polyjose-wasm --target wasm32-unknown-unknown \
  -o "$pkg/THIRD-PARTY-NOTICES.txt" || die "scripts/third-party-notices.sh failed"

echo "==> $me: the shipped .wasm has the SHA-384 the entries check (0006 F05)"
shipped=$(sha384_b64 "$pkg/polyjose_wasm_bg.wasm") || die "node could not hash pkg/polyjose_wasm_bg.wasm"
[ "$shipped" = "$wasm_sha384" ] || die "pkg/polyjose_wasm_bg.wasm is sha384-$shipped, integrity.js has sha384-$wasm_sha384"
grep -qF "\"$wasm_sha384\"" "$pkg/integrity.js" || die "integrity.js does not hold sha384-$wasm_sha384"
grep -qF "\"$pkg_version\"" "$pkg/integrity.js" || die "integrity.js does not hold the version $pkg_version"

echo "==> $me: no top-level await in the entries (ADR 0031 §3)"
# tsc output keeps the source layout: top-level statements start in column 0, function bodies
# are indented. A comment line is not code.
for f in backend.js integrity.js index.js node.mjs browser.mjs workerd.mjs; do
  if hits=$(grep -nE '^[^[:space:]/*].*\bawait\b|^await\b' "$pkg/$f"); then
    echo "$f: $hits"; die "$f uses top-level await"
  fi
done

echo "==> $me: pkg/ holds exactly the files list"
(cd "$pkg" && find . -type f | sed 's|^\./||' | sort) >"$stage/pkg.list"
awk '/"files": \[/ { inside = 1; next } inside && /\]/ { exit }
  inside { f = $0; gsub(/[",[:space:]]/, "", f); if (f != "") print f }' "$template" >"$stage/files.list"
echo package.json >>"$stage/files.list"
sort -o "$stage/files.list" "$stage/files.list"
if ! cmp -s "$stage/pkg.list" "$stage/files.list"; then
  echo "in pkg/ only:"; comm -23 "$stage/pkg.list" "$stage/files.list"
  echo "in the files list only:"; comm -13 "$stage/pkg.list" "$stage/files.list"
  die "pkg/ and the files list of package.template.json differ"
fi
if grep -E '\.map$|\.tsx?$|\.mts$|\.cts$' "$stage/pkg.list" | grep -vE '\.d\.ts$'; then
  die "pkg/ holds a TypeScript source or a source map (ADR 0047: compiled output only)"
fi

# --- 6. The size budget ------------------------------------------------------------------------

if [ "$raw" -gt "$SIZE_BUDGET" ]; then
  echo "$me: FAIL: polyjose_wasm_bg.wasm is $raw bytes raw, over the $SIZE_BUDGET-byte budget (ADR 0031 §3); pkg/ is assembled, no tarball written"
  exit 3
fi
echo "$me: size budget: PASS ($raw <= $SIZE_BUDGET bytes raw)"

# --- 7. npm pack -------------------------------------------------------------------------------

if [ "$pack" -eq 0 ]; then
  echo "$me: pkg/ assembled (--no-pack: no tarball)"
  exit 0
fi
echo "==> $me: npm pack into dist/npm/"
mkdir -p "$dist" || die "could not create $dist"
tarball=$dist/polyjose-wasm-$version.tgz
rm -f "$tarball"
(cd "$pkg" && npm pack --ignore-scripts --pack-destination "$dist" --loglevel=error >/dev/null) || die "npm pack failed"
[ -f "$tarball" ] || die "npm pack did not write $tarball"
tar -tzf "$tarball" | sed 's|^package/||' | sort >"$stage/tar.list"
cmp -s "$stage/tar.list" "$stage/pkg.list" || {
  diff "$stage/pkg.list" "$stage/tar.list" || true
  die "the tarball does not hold exactly pkg/"
}
echo "$me: wrote ${tarball#"$repo"/} ($(wc -c <"$tarball" | tr -d ' ') bytes, $(wc -l <"$stage/tar.list" | tr -d ' ') files)"
