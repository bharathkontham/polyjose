#!/usr/bin/env bash
# Negative tests of the surface mode of scripts/check-binding-api.sh (feature 0013 T13; ADR 0030
# §2, §8): a renamed, missing or extra pub fn, record or field of bindings/surface fails with
# exactly that difference, and items that are not part of the API (methods, pub(crate), private
# fields, the error and secret types) do not count.
#
# Usage: scripts/tests/check-binding-api/surface.sh (under /bin/bash 3.2 and bash 5).
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

src=bindings/surface/src

new_case pass
run_check surface
check_last_line "the surface matches the inventory" 0 \
  "check-binding-api: surface: PASS ($(inventory_count op surface) operations, $(inventory_count record surface) records, $(inventory_count field surface) fields, $(inventory_count interface surface) interfaces, $(inventory_count method surface) methods, $(inventory_count enum surface) enums, $(inventory_count case surface) cases)"

# --- Operations --------------------------------------------------------------------------------------

new_case extra-fn
append $src/jwk.rs '
/// Not in the inventory.
pub fn jwk_peek(jwk: &str) -> SurfaceResult<String> {
    jwk_to_public(jwk)
}'
run_check surface
check_diffs "an extra pub fn fails" 'extra in surface (not in the inventory): op jwkPeek'
check "a failing mode says FAIL and points at the inventory" 1 '^check-binding-api: surface: FAIL '

new_case renamed-fn
edit $src/jws.rs 'pub fn jws_verify_json(' 'pub fn jws_verify_json_serialization('
run_check surface
check_diffs "a renamed pub fn fails as missing and extra" \
  'missing from surface (in the inventory): op jwsVerifyJson' \
  'extra in surface (not in the inventory): op jwsVerifyJsonSerialization'

new_case missing-fn
edit $src/keys.rs 'pub fn jwk_to_der(' 'pub(crate) fn jwk_to_der('
run_check surface
check_diffs "a pub fn that is no longer public is missing" 'missing from surface (in the inventory): op jwkToDer'

new_case duplicate-fn
append $src/keys.rs '
pub fn version() -> &'"'"'static str {
    "0"
}'
run_check surface
check_diffs "a pub fn defined in two modules fails (the bindings are one flat namespace)" \
  'defined twice in surface: op version'

new_case not-operations
append $src/records.rs '
impl JwkSelector {
    /// A method, not an operation.
    pub fn is_empty(&self) -> bool {
        self.kid.is_none() && self.alg.is_none() && self.key_use.is_none()
    }
}

pub(crate) fn crate_only_helper() {}'
append $src/jwk.rs '
#[cfg(test)]
mod more_tests {
    pub fn test_helper() {}
}'
run_check surface
check "methods, pub(crate) fns and test-module fns are not operations" 0 '^check-binding-api: surface: PASS '

# --- Records and fields ------------------------------------------------------------------------------

new_case renamed-field
edit $src/records.rs '    pub key_use: Option<String>,' '    pub key_usage: Option<String>,'
run_check surface
check_diffs "a renamed record field fails as missing and extra" \
  'missing from surface (in the inventory): field JwkSelector.keyUse?' \
  'extra in surface (not in the inventory): field JwkSelector.keyUsage?'

new_case optional-to-required
edit $src/records.rs '    pub max_signatures: Option<u32>,' '    pub max_signatures: u32,'
run_check surface
check_diffs "an optional field made required fails" \
  'missing from surface (in the inventory): field JwsVerifyOptions.maxSignatures?' \
  'extra in surface (not in the inventory): field JwsVerifyOptions.maxSignatures'

new_case flag-to-optional
edit $src/records.rs '    pub compress: bool,' '    pub compress: Option<bool>,'
run_check surface
check_diffs "a flag (bool, absent = false) made Option fails" \
  'missing from surface (in the inventory): field JweEncryptOptions.compress=false' \
  'extra in surface (not in the inventory): field JweEncryptOptions.compress?'

new_case private-field
edit $src/records.rs '    pub max_signatures: Option<u32>,' '    max_signatures: Option<u32>,'
run_check surface
check_diffs "a field that is no longer public is missing" \
  'missing from surface (in the inventory): field JwsVerifyOptions.maxSignatures?'

new_case extra-record
append $src/records.rs '
/// Not in the inventory.
pub struct JwsPeeked {
    /// A field.
    pub alg: String,
    pub protected_header: Option<String>,
}'
run_check surface
check_diffs "an extra pub struct fails with its fields" \
  'extra in surface (not in the inventory): record JwsPeeked' \
  'extra in surface (not in the inventory): field JwsPeeked.alg' \
  'extra in surface (not in the inventory): field JwsPeeked.protectedHeader?'

new_case renamed-record
edit $src/records.rs 'pub struct JwkSelector {' 'pub struct JwkSetSelector {'
run_check surface
check_diffs "a renamed record fails with each of its fields" \
  'missing from surface (in the inventory): record JwkSelector' \
  'missing from surface (in the inventory): field JwkSelector.kid?' \
  'missing from surface (in the inventory): field JwkSelector.alg?' \
  'missing from surface (in the inventory): field JwkSelector.keyUse?' \
  'extra in surface (not in the inventory): record JwkSetSelector' \
  'extra in surface (not in the inventory): field JwkSetSelector.kid?' \
  'extra in surface (not in the inventory): field JwkSetSelector.alg?' \
  'extra in surface (not in the inventory): field JwkSetSelector.keyUse?'

new_case extra-enum
append $src/util.rs '
/// Not in the inventory.
pub enum Form {
    General,
    Flattened,
}'
run_check surface
check_diffs "an extra public enum fails as an enum with its cases" \
  'extra in surface (not in the inventory): enum Form' \
  'extra in surface (not in the inventory): case Form.General' \
  'extra in surface (not in the inventory): case Form.Flattened'

new_case inline-module
append $src/util.rs '
pub mod extra {
    pub fn hidden() {}
}'
run_check surface
check "an inline pub mod fails (its items would not be parsed)" 1 \
  '^check-binding-api: surface: util\.rs:[0-9]+: inline module ' '^check-binding-api: surface: FAIL'

# --- The inventory side ------------------------------------------------------------------------------

new_case inventory-extra-field
edit bindings/api-inventory.txt '  field keyUse?' '  field keyUse?
  field x5tS256?'
run_check surface
check_diffs "a field the inventory lists but the surface lacks fails" \
  'missing from surface (in the inventory): field JwkSelector.x5tS256?'

new_case inventory-missing-op
edit bindings/api-inventory.txt 'op jwksSelect
' ''
run_check surface
check_diffs "an operation the inventory lacks fails" 'extra in surface (not in the inventory): op jwksSelect'

# --- Missing inputs ----------------------------------------------------------------------------------

new_case no-surface
rm -rf "${case_dir:?}/$src"
run_check surface
check_last_line "without bindings/surface/src the mode is SKIPPED with the reason" 0 \
  'SKIPPED (surface: bindings/surface/src missing)'
check_absent "a skipped mode is not reported as passing" 'PASS'

# --- The platform-key trait and its error enum (feature 0025 T02; ADR 0071 §5) ---------------------

new_case renamed-trait-method
edit $src/platform_key.rs '    fn algorithms(&self) -> Result<Vec<String>, PlatformKeyError>;' \
  '    fn algorithm_list(&self) -> Result<Vec<String>, PlatformKeyError>;'
run_check surface
check_diffs "a renamed trait method fails as missing and extra" \
  'missing from surface (in the inventory): method PlatformKey.algorithms' \
  'extra in surface (not in the inventory): method PlatformKey.algorithmList'

new_case enum-variant-payload
edit $src/platform_key.rs '    NotFound,' '    NotFound(u8),'
run_check surface
check "a variant with a payload fails" 1 'enum variant with a payload or value' '^check-binding-api: surface: FAIL$'

new_case extra-trait
append $src/util.rs '
/// Not in the inventory.
pub trait Probe {
    fn probe(&self);
}'
run_check surface
check_diffs "an extra public trait fails as an interface with its methods" \
  'extra in surface (not in the inventory): interface Probe' \
  'extra in surface (not in the inventory): method Probe.probe'

finish
