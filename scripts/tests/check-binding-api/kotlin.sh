#!/usr/bin/env bash
# Negative tests of the kotlin mode of scripts/check-binding-api.sh (feature 0025 T02; ADR 0030
# §2, §8; ADR 0033 §3; ADR 0071 §5): the generated Kotlin's interface and its methods, the
# payload-free error enum and the `<Interface>Impl` companion are read as the inventory says; an
# extra generated public class fails; a hand-written public Kotlin type passes only when it is
# listed, with exactly its public members, in scripts/check-binding-api.d/kotlin.host-types.
#
# The Kotlin is generated once, as the mode does (a debug build of polyjose-ffi, then
# polyjose-uniffi-bindgen), and each case edits its own copy, read through
# CHECK_BINDING_API_KOTLIN_SOURCE, so no case builds. Without cargo the cases do not run.
#
# Usage: scripts/tests/check-binding-api/kotlin.sh (under /bin/bash 3.2 and bash 5).
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

if ! command -v cargo >/dev/null 2>&1; then
  echo "note: cargo missing; the kotlin cases did not run"
  finish
  exit
fi

case $(uname -s) in
  Darwin) lib=libpolyjose_ffi.dylib ;;
  *) lib=libpolyjose_ffi.so ;;
esac
(cd "$repo" && cargo build --quiet --lib -p polyjose-ffi && cargo build --quiet -p polyjose-uniffi-bindgen) \
  >"$scratch/cargo.log" 2>&1 || { cat "$scratch/cargo.log" >&2; lib_die "building polyjose-ffi or the bindgen failed"; }
target=$(cd "$repo" && cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
"$target/debug/uniffi-bindgen" generate "$target/debug/$lib" --language kotlin --no-format \
  --out-dir "$scratch/kotlin" >"$scratch/bindgen.log" 2>&1 || { cat "$scratch/bindgen.log" >&2; lib_die "Kotlin generation failed"; }

# The generated file and the hand-written sources the mode reads join the base copy.
gen=generated/polyjose_ffi.kt
mkdir -p "$base/generated" || lib_die "mkdir"
cp "$scratch/kotlin/dev/polyjose/polyjose_ffi.kt" "$base/$gen" || lib_die "could not copy the generated Kotlin"
(cd "$repo" && tar -cf - platforms/android/src) | (cd "$base" && tar -xf -) || lib_die "could not copy platforms/android/src"
hand=platforms/android/polyjose/src/main/kotlin/dev/polyjose
mkdir -p "$base/$hand" || lib_die "mkdir"
list=scripts/check-binding-api.d/kotlin.host-types

# kotlin_check: run_check kotlin on the case's generated file.
kotlin_check() {
  export CHECK_BINDING_API_KOTLIN_SOURCE=$case_dir/$gen
  run_check kotlin
  unset CHECK_BINDING_API_KOTLIN_SOURCE
}

ops=$(inventory_count op kotlin) records=$(inventory_count record kotlin) fields=$(inventory_count field kotlin)
codes=$(inventory_count code) ifaces=$(inventory_count interface kotlin) methods=$(inventory_count method kotlin)
enums=$(inventory_count enum kotlin) cases=$(inventory_count case kotlin)
counts="$ops operations, $records records, $fields fields, $codes codes, $ifaces interfaces, $methods methods, $enums enums, $cases cases"

new_case pass
kotlin_check
check_last_line "the generated Kotlin and the hand-written sources match the inventory" 0 \
  "check-binding-api: kotlin: PASS ($counts)"

# --- Generated Kotlin ----------------------------------------------------------------------------

new_case renamed-method
edit $gen '    fun `decryptKey`(`alg`: kotlin.String, `encryptedKey`: kotlin.ByteArray): kotlin.ByteArray
' '    fun `decrypt`(`alg`: kotlin.String, `encryptedKey`: kotlin.ByteArray): kotlin.ByteArray
'
kotlin_check
check_diffs "a renamed interface method fails as missing and extra" \
  'missing from kotlin (in the inventory): method PlatformKey.decryptKey' \
  'extra in kotlin (not in the inventory): method PlatformKey.decrypt'

new_case extra-generated-class
append $gen '
open class Extra {
}'
kotlin_check
check_diffs "an extra generated public class fails as an extra record" 'extra in kotlin (not in the inventory): record Extra'

new_case impl-without-interface
append $gen '
open class OtherImpl {
}'
kotlin_check
check_diffs "an Impl class without its interface is not a companion" 'extra in kotlin (not in the inventory): record OtherImpl'

new_case extra-error-case
edit $gen '    class Failed(
        ) : PlatformKeyException() {' '    class Failed(
        ) : PlatformKeyException() {
    }
    class Cancelled(
        ) : PlatformKeyException() {'
kotlin_check
check_diffs "an extra subclass of the interface's error type fails as an extra case" \
  'extra in kotlin (not in the inventory): case PlatformKeyError.Cancelled'

# --- Hand-written host types ---------------------------------------------------------------------

host_type='package dev.polyjose

/** A hand-written host type. */
@Suppress("unused")
class AndroidKeystoreKey private constructor(
    private val alias: String,
    val securityLevel: String,
) : PlatformKey {
    override fun publicJwk(): String = "{}"
    override fun algorithms(): List<String> = listOf()
    override fun sign(alg: String, signingInput: ByteArray): ByteArray = signingInput
    override fun agree(peerPublicKey: ByteArray): ByteArray = peerPublicKey
    override fun decryptKey(alg: String, encryptedKey: ByteArray): ByteArray = encryptedKey
    private fun helper() {}
    internal val internalThing = 1

    companion object {
        fun generate(alias: String): AndroidKeystoreKey = AndroidKeystoreKey(alias, "software")
        @JvmStatic fun delete(alias: String) {}
        private fun secret() {}
    }
}'
host_list='type AndroidKeystoreKey
  member securityLevel
  member publicJwk
  member algorithms
  member sign
  member agree
  member decryptKey
  member generate
  member delete'

new_case host-type-unlisted
append $hand/AndroidKeystoreKey.kt "$host_type"
kotlin_check
check "an extra public Kotlin class that is not listed still fails" 1 \
  'AndroidKeystoreKey\.kt:[0-9]+: a public top-level declaration that is not a listed host type' '^check-binding-api: kotlin: FAIL$'

new_case host-type-listed
append $hand/AndroidKeystoreKey.kt "$host_type"
append $list "$host_list"
kotlin_check
check_last_line "a listed host type with exactly its public members passes" 0 \
  "check-binding-api: kotlin: PASS ($counts, 1 host types, 8 host members)"

new_case host-member-unlisted
append $hand/AndroidKeystoreKey.kt "${host_type/private fun helper/fun helper}"
append $list "$host_list"
kotlin_check
check_diffs "a public member of a listed host type that is not listed fails" \
  'extra in kotlin (not in the inventory): hostmember AndroidKeystoreKey.helper'

new_case host-public-constructor
append $hand/AndroidKeystoreKey.kt "${host_type/class AndroidKeystoreKey private constructor(/class AndroidKeystoreKey(}"
append $list "$host_list"
kotlin_check
check_diffs "a public primary constructor is a member" \
  'extra in kotlin (not in the inventory): hostmember AndroidKeystoreKey.constructor'

new_case host-type-missing
append $list "$host_list"
kotlin_check
check "a listed host type the sources lack fails" 1 \
  '^  missing from kotlin \(in the inventory\): hosttype AndroidKeystoreKey$' '^check-binding-api: kotlin: FAIL '

new_case hand-written-function
append $hand/Helpers.kt 'package dev.polyjose

@JvmName("peek") fun jwkPeek(jwk: String): String = jwk'
kotlin_check
check "a public top-level function in a hand-written file fails" 1 \
  'Helpers\.kt:[0-9]+: a public top-level declaration that is not a listed host type' '^check-binding-api: kotlin: FAIL$'

new_case hand-written-internal
append $hand/Internal.kt 'package dev.polyjose

internal object Hidden { fun shown() {} }
private class Private'
kotlin_check
check_last_line "internal and private hand-written declarations do not count" 0 "check-binding-api: kotlin: PASS ($counts)"

finish
