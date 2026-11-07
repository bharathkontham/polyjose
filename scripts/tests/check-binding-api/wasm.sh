#!/usr/bin/env bash
# Negative tests of the wasm mode of scripts/check-binding-api.sh (feature 0006 T03; ADR 0031 §3,
# ADR 0047). The mode builds the package with bindings/wasm/scripts/build-package.sh --no-pack and
# checks pkg/: the glue's `export function` names must equal the inventory's operations, and
# pkg/facade/ must hold exactly (byte-identical) the .js and .d.ts of bindings/js/dist/src/.
#
# Each case replaces the build script in the copy by a stub that writes a pkg/ and a dist/src/
# from the inventory (so no wasm-pack run is needed), then changes one thing. The stub is a
# fixture of the mode's contract, not of the real build, which build-package.sh itself guards.
# Without cargo, wasm-pack, node, npm, gzip, brotli or the wasm32 target only the SKIPPED case
# runs.
#
# Usage: scripts/tests/check-binding-api/wasm.sh (under /bin/bash 3.2 and bash 5).
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

# new_stub_case <name> <build exit status> [<extra shell run by the stub after writing pkg/>]
new_stub_case() {
  new_case "$1"
  mkdir -p "$case_dir/bindings/wasm/scripts" || lib_die "mkdir"
  : >"$case_dir/bindings/wasm/Cargo.toml"
  : >"$case_dir/bindings/wasm/package.template.json"
  cat >"$case_dir/bindings/wasm/scripts/build-package.sh" <<STUB
#!/usr/bin/env bash
set -e
here=\$(cd "\$(dirname "\$0")/../../.." && pwd -P)
pkg=\$here/bindings/wasm/pkg src=\$here/bindings/js/dist/src
rm -rf "\$pkg" "\$src"; mkdir -p "\$pkg/facade" "\$src"
for f in api types normalize backend error-codes; do
  echo "// \$f" >"\$src/\$f.js"; echo "export {};" >"\$src/\$f.d.ts"
  cp "\$src/\$f.js" "\$src/\$f.d.ts" "\$pkg/facade/"
done
awk '\$1 == "op" { printf "export function %s(): void;\n", \$2 }' "\$here/bindings/api-inventory.txt" >"\$pkg/polyjose_wasm.d.ts"
echo "export function initSync(m: unknown): void;" >>"\$pkg/polyjose_wasm.d.ts"
echo "export default function __wbg_init(): Promise<void>;" >>"\$pkg/polyjose_wasm.d.ts"
${3:-}
exit $2
STUB
  chmod +x "$case_dir/bindings/wasm/scripts/build-package.sh"
}

# --- Missing tools -----------------------------------------------------------------------------------

nobin=$scratch/bin-nowasmpack
mkdir -p "$nobin" || lib_die "mkdir"
for tool in awk cat cmp comm cp dirname grep mkdir mktemp rm sed sort tr uniq cargo node npm gzip brotli; do
  path=$(command -v "$tool") || { echo "note: $tool missing; wasm cases skipped"; echo "0 checks, 0 failed"; exit 0; }
  ln -s "$path" "$nobin/$tool" || lib_die "ln"
done
new_stub_case no-wasm-pack 0
rc=0
(cd "$case_dir" && PATH=$nobin "$BASH" scripts/check-binding-api.sh wasm) </dev/null >"$scratch/out" 2>&1 || rc=$?
check_last_line "without wasm-pack the wasm mode is SKIPPED with the reason" 0 'SKIPPED (wasm: wasm-pack missing)'
check_absent "a skipped wasm mode is not reported as passing" 'PASS'

for tool in wasm-pack cargo node npm gzip brotli; do
  command -v "$tool" >/dev/null 2>&1 || { echo "note: $tool missing; the stubbed-build cases did not run"; finish; exit; }
done
if command -v rustup >/dev/null 2>&1 \
  && ! rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then
  echo "note: wasm32-unknown-unknown not installed; the stubbed-build cases did not run"; finish; exit
fi

new_stub_case no-script 0
rm -f "$case_dir/bindings/wasm/scripts/build-package.sh"
run_check wasm
check_last_line "without the build script the wasm mode is SKIPPED" 0 \
  'SKIPPED (wasm: bindings/wasm/scripts/build-package.sh missing)'

# --- The stub passes, and each change fails with exactly its difference ------------------------------

new_stub_case pass 0
run_check wasm
check "a clean build passes" 0 '^check-binding-api: wasm: PASS'

new_stub_case over-budget 3
run_check wasm
check "build exit 3 (size budget) still checks names, with a note" 0 'over its size budget' '^check-binding-api: wasm: PASS'

new_stub_case build-fails 1
run_check wasm
check "any other build failure fails the mode" 1 'build-package.sh --no-pack failed \(exit 1\)' '^check-binding-api: wasm: FAIL$'

new_stub_case missing-op 0 'sed -i.bak "/^export function jwtVerify(/d" "$pkg/polyjose_wasm.d.ts"; rm -f "$pkg/polyjose_wasm.d.ts.bak"'
run_check wasm
check_diffs "a glue without an inventory operation fails as missing" 'missing from wasm (in the inventory): op jwtVerify'

new_stub_case extra-op 0 'echo "export function jwkPeek(): void;" >>"$pkg/polyjose_wasm.d.ts"'
run_check wasm
check_diffs "a glue with an extra function fails as extra" 'extra in wasm (not in the inventory): op jwkPeek'

new_stub_case facade-modified 0 'echo "// tampered" >>"$pkg/facade/api.js"'
run_check wasm
check "a modified facade file fails" 1 'pkg/facade/api.js differs from bindings/js/dist/src/api.js' '^check-binding-api: wasm: FAIL$'

new_stub_case facade-missing 0 'rm "$pkg/facade/normalize.d.ts"'
run_check wasm
check "a missing facade file fails" 1 'pkg/facade/normalize.d.ts missing' '^check-binding-api: wasm: FAIL$'

new_stub_case facade-extra 0 'echo "// x" >"$pkg/facade/extra.js"'
run_check wasm
check "an extra facade file fails" 1 'pkg/facade/extra.js is not a .js or .d.ts of bindings/js/dist/src' '^check-binding-api: wasm: FAIL$'

new_stub_case no-facade-dir 0 'rm -rf "$pkg/facade"'
run_check wasm
check "a package without facade/ fails" 1 'pkg/facade/ missing' '^check-binding-api: wasm: FAIL$'

finish
