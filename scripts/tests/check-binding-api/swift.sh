#!/usr/bin/env bash
# Negative tests of the swift mode of scripts/check-binding-api.sh (feature 0009 T02; ADR 0030 §2,
# §3, §5, §8; ADR 0032 §3): a renamed, missing or extra operation, record, field or code of the
# Swift module Polyjose fails with exactly that difference; a default on a required field, a
# hand-written public extension member, another public declaration and a missing code() fail the
# mode; UniFFI's own public plumbing (FfiConverter*, uniffiEnsurePolyjoseFfiInitialized) and
# braces inside comments and strings do not count.
#
# Usage: scripts/tests/check-binding-api/swift.sh (under /bin/bash 3.2 and bash 5).
set -euo pipefail
export LC_ALL=C
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

src=platforms/swift/Sources/Polyjose
gen=$src/Polyjose.swift
# lib.sh copies the inputs of the other modes; this mode also reads the Swift sources.
mkdir -p "$base/$src" || lib_die "could not create $base/$src"
cp "$repo/$src"/*.swift "$base/$src/" || lib_die "could not copy $src"

ops=$(inventory_count op) records=$(inventory_count record) fields=$(inventory_count field) codes=$(inventory_count code)

new_case pass
run_check swift
check_last_line "the Swift API matches the inventory" 0 \
  "check-binding-api: swift: PASS ($ops operations, $records records, $fields fields, $codes codes)"

new_case renamed-op
edit $gen 'public func jwkToPublic(jwk: String)' 'public func jwkToPublicKey(jwk: String)'
run_check swift
check_diffs "a renamed public func fails as missing and extra" \
  'missing from swift (in the inventory): op jwkToPublic' \
  'extra in swift (not in the inventory): op jwkToPublicKey'
check "a failing mode says FAIL and points at the inventory" 1 '^check-binding-api: swift: FAIL '

new_case extra-file-op
append $src/Extra.swift 'public func jwkPeek(jwk: String) -> String { jwk }'
run_check swift
check_diffs "a public func in another source file is an extra operation" \
  'extra in swift (not in the inventory): op jwkPeek'

new_case renamed-field
edit $gen '*/maxSignatures: UInt32? = nil) {' '*/maxSigs: UInt32? = nil) {'
run_check swift
check "an init parameter that is not a public var fails" 1 \
  'init parameter JwsVerifyOptions\.maxSigs is not a public var' \
  'public var JwsVerifyOptions\.maxSignatures is not a parameter of its init'

new_case optional-required
edit $gen '*/signatureIndex: UInt32) {' '*/signatureIndex: UInt32? = nil) {'
run_check swift
check_diffs "a required field that became optional fails" \
  'missing from swift (in the inventory): field JwsVerified.signatureIndex' \
  'extra in swift (not in the inventory): field JwsVerified.signatureIndex?'

new_case default-allow-list
edit $gen '*/allowedEnc: [String], ' '*/allowedEnc: [String] = [], '
run_check swift
check "a default on an allow-list fails (ADR 0030 §3)" 1 \
  'JweDecryptOptions\.allowedEnc has a default other than nil or false'

new_case renamed-code
edit $gen 'case NoMatchingKey(' 'case NoMatchKey('
run_check swift
check "a renamed error case fails the code list" 1 'error codes of swift differ from the inventory'

new_case no-code-accessor
edit $gen 'public func code() -> String  {' 'public func errorCode() -> String  {'
run_check swift
check "PolyjoseError without code() fails (ADR 0030 §5)" 1 'PolyjoseError has no public func code\(\) -> String'

new_case extension-member
append $src/Extra.swift 'extension JwsVerified {
    public var payloadText: String { String(decoding: payload, as: UTF8.self) }
}'
run_check swift
check "a hand-written public extension member fails" 1 'public member payloadText in an extension of JwsVerified'

new_case typealias
append $src/Extra.swift 'public typealias Jwk = String'
run_check swift
check "another public declaration fails" 1 'public typealias Jwk is neither an operation, a record nor the error type'

new_case braces-in-comments-and-strings
append $src/Extra.swift '// A comment with a brace { that must not open a block.
/* A block comment } with braces { /* nested } */ still a comment */
let polyjoseExample = "{ not a block"
public func jwkPeek(jwk: String) -> String { jwk }'
run_check swift
check_diffs "braces in comments and strings do not change the depth" \
  'extra in swift (not in the inventory): op jwkPeek'

finish
