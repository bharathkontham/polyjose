# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # sourced by scripts/check-binding-api.sh, which reads MODE_KINDS
# and sets repo, mode_scratch and camel_awk
# Mode "wasm" of scripts/check-binding-api.sh: the @polyjose/wasm package (feature 0006 T03;
# ADR 0031 §3, ADR 0047). It builds the package directory first, with
#   bindings/wasm/scripts/build-package.sh --no-pack
# (wasm-pack, the bindings/js facade, the TypeScript entries; no tarball), and then checks the
# assembled bindings/wasm/pkg/:
#   - operations: every `export function <name>` of the wasm-bindgen glue's generated
#     declarations, pkg/polyjose_wasm.d.ts, except the glue's own `initSync` (the default export,
#     `__wbg_init`, is not a named function export). The adapter exports one camelCase function per
#     inventory operation (ADR 0030 §2), which the shared facade calls through the backend;
#   - byte identity: pkg/facade/ holds exactly the .js and .d.ts files of bindings/js/dist/src/
#     (the tsc output the script copied, ADR 0047), each byte-identical to it, so the package ships
#     the facade unchanged (ADR 0031 §1).
# Records, fields and codes are the facade's (mode "js"), so this mode checks operations only.
#
# The build script exits 3 when the package is assembled but the .wasm is over its size budget
# (ADR 0031 §3). That is the build's failure, reported by the script itself and by the package
# build, not a naming one: the names are still checked, and a note says so. Any other build
# failure fails the mode. Without wasm-pack, cargo, the wasm32-unknown-unknown target, node, npm,
# gzip, brotli or openssl the mode is SKIPPED, never passed.

MODE_KINDS="op"

mode_derive() {
  local out=$1 wasm=$repo/bindings/wasm pkg f tool rc
  pkg=$wasm/pkg
  for f in Cargo.toml scripts/build-package.sh package.template.json; do
    [ -f "$wasm/$f" ] || skip "bindings/wasm/$f missing"
  done
  for tool in cargo wasm-pack node npm gzip brotli openssl; do
    command -v "$tool" >/dev/null 2>&1 || skip "$tool missing"
  done
  if command -v rustup >/dev/null 2>&1; then
    (cd "$repo" && rustup target list --installed) 2>/dev/null | grep -qx wasm32-unknown-unknown \
      || skip "the wasm32-unknown-unknown target is not installed"
  fi
  "$wasm/scripts/build-package.sh" --no-pack >"$mode_scratch/build.log" 2>&1
  rc=$?
  case $rc in
    0) ;;
    3) echo "check-binding-api: wasm: note: the package is over its size budget (build-package.sh exit 3); checking names anyway" ;;
    *) tail -40 "$mode_scratch/build.log"; mode_fail "bindings/wasm/scripts/build-package.sh --no-pack failed (exit $rc)" ;;
  esac
  [ -f "$pkg/polyjose_wasm.d.ts" ] || mode_fail "the build did not assemble pkg/polyjose_wasm.d.ts"

  awk '
    /^export function [A-Za-z_$][A-Za-z0-9_$]*\(/ {
      name = $0; sub(/^export function /, "", name); sub(/\(.*/, "", name)
      if (name != "initSync") print "op " name
    }
  ' "$pkg/polyjose_wasm.d.ts" >"$out" || return 1
  [ -s "$out" ] || mode_fail "no export function found in pkg/polyjose_wasm.d.ts (has the glue changed?)"

  # Byte identity of the copied facade (both directions: nothing missing, nothing extra).
  local src=$repo/bindings/js/dist/src name
  [ -d "$src" ] || mode_fail "bindings/js/dist/src missing after the build"
  [ -d "$pkg/facade" ] || { echo "error pkg/facade/ missing (the facade is copied there, ADR 0031 §1)" >>"$out"; return 0; }
  (cd "$src" && find . -type f \( -name '*.js' -o -name '*.d.ts' \) | sort) >"$mode_scratch/facade.src"
  (cd "$pkg/facade" && find . -type f | sort) >"$mode_scratch/facade.pkg"
  [ -s "$mode_scratch/facade.src" ] || mode_fail "no .js or .d.ts in bindings/js/dist/src"
  {
    comm -23 "$mode_scratch/facade.src" "$mode_scratch/facade.pkg" | while IFS= read -r name; do
      echo "error pkg/facade/${name#./} missing (bindings/js/dist/src/${name#./} is not shipped)"
    done
    comm -13 "$mode_scratch/facade.src" "$mode_scratch/facade.pkg" | while IFS= read -r name; do
      echo "error pkg/facade/${name#./} is not a .js or .d.ts of bindings/js/dist/src"
    done
    comm -12 "$mode_scratch/facade.src" "$mode_scratch/facade.pkg" | while IFS= read -r name; do
      cmp -s "$src/$name" "$pkg/facade/$name" \
        || echo "error pkg/facade/${name#./} differs from bindings/js/dist/src/${name#./} (the facade ships unchanged)"
    done
  } >>"$out"
}
