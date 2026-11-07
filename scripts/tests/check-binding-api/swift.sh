#!/usr/bin/env bash
# Negative tests of the swift mode of scripts/check-binding-api.sh (feature 0009 T02; ADR 0030 §2,
# §3, §5, §8; ADR 0032 §3): a renamed, missing or extra operation, record, field or code of the
# Swift module Polyjose fails with exactly that difference; a default on a required field, a
# hand-written public extension member, another public declaration and a missing code() fail the
# mode; UniFFI's own public plumbing (FfiConverter*, uniffiEnsurePolyjoseFfiInitialized) and
# braces inside comments and strings do not count. Hand-written forms the generated code does not
# use are seen too (F01): declarations sharing a line with an extension, a brace or each other,
# declarations with attributes or modifiers (`final`, `nonisolated`, ...) before the access
# keyword, and `open` declarations, read like `public`.
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

# Hand-written forms the generated code does not use (F01): every one must still be seen.

new_case one-line-extension
append $src/Extra.swift 'extension PolyjoseError { public func leak() -> String { "" } }'
run_check swift
check "a public member declared on one line with its extension fails" 1 \
  'public member leak in an extension of PolyjoseError'

new_case declarations-on-one-line
append $src/Extra.swift 'public func jwkPeek(jwk: String) -> String { jwk }; public func jwkPoke() {}'
run_check swift
check_diffs "two declarations on one line are both extra operations" \
  'extra in swift (not in the inventory): op jwkPeek' \
  'extra in swift (not in the inventory): op jwkPoke'

new_case declaration-after-brace
append $src/Extra.swift 'extension JwsVerified {
} public func jwkPoke() {}'
run_check swift
check_diffs "a declaration after a closing brace on the same line is an extra operation" \
  'extra in swift (not in the inventory): op jwkPoke'

new_case attribute-same-line
append $src/Extra.swift '@available(iOS 16, *) public func extra() {}'
run_check swift
check_diffs "a public func with an attribute on the same line is an extra operation" \
  'extra in swift (not in the inventory): op extra'

new_case attributes-same-line
append $src/Extra.swift '@available(*, deprecated, message: "use (jwkParse)") @inlinable public func extra() {}'
run_check swift
check_diffs "a public func after two attributes, one with parentheses in a string, is an extra operation" \
  'extra in swift (not in the inventory): op extra'

new_case attribute-own-line
append $src/Extra.swift '@available(iOS 16, *)
@inlinable
public func extra() {}'
run_check swift
check_diffs "a public func after attributes on their own lines is an extra operation" \
  'extra in swift (not in the inventory): op extra'

new_case attribute-extension-member
append $src/Extra.swift 'extension JwsVerified {
    @discardableResult public static func extra2() -> Int { 0 }
}'
run_check swift
check "a public extension member with an attribute on the same line fails" 1 \
  'public member extra2 in an extension of JwsVerified'

new_case attribute-record-var
edit $gen 'public struct JwsVerified: Equatable, Hashable {' 'public struct JwsVerified: Equatable, Hashable {
    @available(iOS 16, *) public var extraVar: String'
run_check swift
check "a record var with an attribute on the same line is still read as a public var" 1 \
  'public var JwsVerified\.extraVar is not a parameter of its init'

new_case open-class
append $src/Extra.swift 'open class Extra {}'
run_check swift
check "an open class fails like a public one" 1 'open class Extra is neither an operation, a record nor the error type'

new_case open-func
append $src/Extra.swift 'open func extra3() {}'
run_check swift
check_diffs "an open func is an extra operation" \
  'extra in swift (not in the inventory): op extra3'

new_case open-own-line
append $src/Extra.swift 'open
func extra3() {}'
run_check swift
check_diffs "open on its own line before a func is an extra operation" \
  'extra in swift (not in the inventory): op extra3'

new_case open-extension-member
append $src/Extra.swift 'extension JwsVerified {
    open class func extra4() {}
}'
run_check swift
check "an open extension member fails like a public one" 1 'open member extra4 in an extension of JwsVerified'

new_case modifier-final-class
append $src/Extra.swift 'final public class X {}'
run_check swift
check "a public class after a modifier fails" 1 'public class X is neither an operation, a record nor the error type'

new_case modifier-nonisolated-func
append $src/Extra.swift 'nonisolated public func f() {}'
run_check swift
check_diffs "a public func after a modifier is an extra operation" \
  'extra in swift (not in the inventory): op f'

new_case modifier-after-attribute
append $src/Extra.swift '@MainActor final public class Y {}'
run_check swift
check "a public class after an attribute and a modifier fails" 1 'public class Y is neither an operation, a record nor the error type'

new_case modifiers-and-attributes-mixed
append $src/Extra.swift '@MainActor nonisolated @available(iOS 16, *) final dynamic public func h() {}'
run_check swift
check_diffs "a public func after modifiers mixed with attributes is an extra operation" \
  'extra in swift (not in the inventory): op h'

new_case modifier-with-argument
append $src/Extra.swift 'nonisolated(unsafe) public let shared = 1'
run_check swift
check "a public let after a modifier with an argument fails" 1 'public let shared is neither an operation, a record nor the error type'

new_case modifier-public-own-line
append $src/Extra.swift 'final public
class W {}'
run_check swift
check "a modifier and public on their own line apply to the next declaration" 1 \
  'public class W is neither an operation, a record nor the error type'

new_case modifier-extension-member
append $src/Extra.swift 'extension JwsVerified {
    static public func g() {}
}'
run_check swift
check "a public extension member after a modifier fails" 1 'public member g in an extension of JwsVerified'

new_case modifier-open-extension-member
append $src/Extra.swift 'extension JwsVerified {
    @objc final override open func j() {}
}'
run_check swift
check "an open extension member after an attribute and modifiers fails" 1 'open member j in an extension of JwsVerified'

new_case non-public-modifiers
append $src/Extra.swift 'final class Z {}
@MainActor final class Z2 {}
extension JwsVerified { static func helper() {}; final private class Hidden {} }
infix operator <~>: AdditionPrecedence'
run_check swift
check_last_line "declarations with modifiers but no public or open do not count" 0 \
  "check-binding-api: swift: PASS ($ops operations, $records records, $fields fields, $codes codes)"

new_case non-public-forms
append $src/Extra.swift 'extension JwsVerified { func helper() {}; internal var opened: Bool { false } }
@inlinable func internalHelper() {}
private let openSesame = 1
fileprivate struct Plain {}'
run_check swift
check_last_line "internal, private and fileprivate declarations, also on one line, do not count" 0 \
  "check-binding-api: swift: PASS ($ops operations, $records records, $fields fields, $codes codes)"

finish
