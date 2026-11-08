#!/usr/bin/env bash
# Negative tests of the swift mode of scripts/check-binding-api.sh (feature 0009 T02; ADR 0030 §2,
# §3, §5, §8; ADR 0032 §3): a renamed, missing or extra operation, record, field or code of the
# Swift module Polyjose fails with exactly that difference; a default on a required field, a
# hand-written public extension member, another public declaration and a missing code() fail the
# mode; UniFFI's own public plumbing (FfiConverter*, uniffiEnsurePolyjoseFfiInitialized) and
# braces inside comments and strings do not count. Hand-written forms the generated code does not
# use are seen too (F01): declarations sharing a line with an extension, a brace or each other,
# declarations with attributes (also with arguments over several lines) or modifiers (`final`,
# `nonisolated`, ...) before the access keyword, and `open` declarations, read like `public`.
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

# B01: an attribute whose arguments span lines, the declaration on the closing line.

new_case multiline-attribute
append $src/Extra.swift '@available(iOS 16,
  macOS 13,
  *) public func a4() {}'
run_check swift
check_diffs "a public func on the closing line of a multi-line attribute is an extra operation" \
  'extra in swift (not in the inventory): op a4'

new_case multiline-attribute-open-class
append $src/Extra.swift '@available(iOS 16,
  *) open class B2 {}'
run_check swift
check "an open class on the closing line of a multi-line attribute fails" 1 \
  'open class B2 is neither an operation, a record nor the error type'

new_case multiline-attribute-modifier
append $src/Extra.swift '@available(iOS 16,
  *) final public class B3 {}'
run_check swift
check "a modifier and public class on the closing line of a multi-line attribute fail" 1 \
  'public class B3 is neither an operation, a record nor the error type'

new_case multiline-attribute-extension-member
append $src/Extra.swift 'extension Int {
  @available(iOS 16,
    *) public func b4() {}
}'
run_check swift
check "an extension member on the closing line of a multi-line attribute fails" 1 \
  'public member b4 in an extension of Int'

new_case multiline-attribute-one-line-extension
append $src/Extra.swift 'extension Int { @available(iOS 16,
  *) public func b5() {} }'
run_check swift
check "a multi-line attribute opened on the line of its extension still hides no member" 1 \
  'public member b5 in an extension of Int'

new_case multiline-attribute-objc
append $src/Extra.swift '@objc(
  x) public func b6() {}'
run_check swift
check_diffs "a public func after a multi-line @objc(...) is an extra operation" \
  'extra in swift (not in the inventory): op b6'

new_case multiline-attribute-open-paren-alone
append $src/Extra.swift '@available(
  iOS 16, *) public func b11() {}'
run_check swift
check_diffs "a public func after an attribute whose ( ends its line is an extra operation" \
  'extra in swift (not in the inventory): op b11'

new_case multiline-attribute-after-attribute
append $src/Extra.swift '@MainActor @available(iOS 16,
  *) public func b10() {}'
run_check swift
check_diffs "a multi-line attribute after another attribute still hides no func" \
  'extra in swift (not in the inventory): op b10'

new_case multiline-attribute-second
append $src/Extra.swift '@available(iOS 16, *) @available(macOS 13,
  *) public func b8() {}'
run_check swift
check_diffs "a second attribute spanning lines still hides no func" \
  'extra in swift (not in the inventory): op b8'

new_case multiline-attribute-close-alone
append $src/Extra.swift '@available(iOS 16,
  *
) public func b12() {}'
run_check swift
check_diffs "a public func after a ) on its own line is an extra operation" \
  'extra in swift (not in the inventory): op b12'

new_case multiline-attribute-public-next-line
append $src/Extra.swift '@available(iOS 16,
  *)
public func b9() {}
@available(iOS 16,
  *) @inlinable
public func b7() {}'
run_check swift
check_diffs "public funcs on the lines after a multi-line attribute are extra operations" \
  'extra in swift (not in the inventory): op b9' \
  'extra in swift (not in the inventory): op b7'

new_case multiline-attribute-string-and-comment
append $src/Extra.swift '@available(iOS 16, message: "a ) and a ( in a string",
  *) public func c1() {}
@available(iOS 16, // a ) in a comment
  /* a ( and ) */ *) public func c2() {}'
run_check swift
check_diffs "parentheses in strings and comments of a multi-line attribute do not count" \
  'extra in swift (not in the inventory): op c1' \
  'extra in swift (not in the inventory): op c2'

new_case unclosed-attribute
append $src/Extra.swift '@available(iOS 16,
public func hidden() {}'
run_check swift
check "an attribute argument list that never closes fails rather than hiding the rest" 1 \
  'Extra\.swift:1: attribute argument list never closed'

new_case non-public-multiline-attribute
append $src/Extra.swift '@available(iOS 16,
  *) final class Z3 {}
@available(iOS 16,
  *)
func internalOne() {}
extension Int { @available(iOS 16,
  *) func internalTwo() {} }'
run_check swift
check_last_line "non-public declarations after multi-line attributes do not count" 0 \
  "check-binding-api: swift: PASS ($ops operations, $records records, $fields fields, $codes codes)"

new_case non-public-forms
append $src/Extra.swift 'extension JwsVerified { func helper() {}; internal var opened: Bool { false } }
@inlinable func internalHelper() {}
private let openSesame = 1
fileprivate struct Plain {}'
run_check swift
check_last_line "internal, private and fileprivate declarations, also on one line, do not count" 0 \
  "check-binding-api: swift: PASS ($ops operations, $records records, $fields fields, $codes codes)"

# F05: a protocol conformance is public API too. Only the generated `Sendable` ones and the three
# printing conformances of Redaction.swift (ADR 0065) are allowed. An extension header may span
# lines.

new_case header-brace-next-line
append $src/Extra.swift 'extension JwsVerified
{
    public var leak: String { "" }
}'
run_check swift
check "a public member of an extension whose { is on the next line fails" 1 \
  'public member leak in an extension of JwsVerified'

new_case conformance-other-file
append $src/Extra.swift 'extension JwtVerified: Error {}'
run_check swift
check "a hand-written conformance without members fails" 1 \
  'Extra\.swift:1: conformance JwtVerified: Error is not allowed'

new_case conformance-sendable-hand-written
append $src/Extra.swift 'extension JwtVerified: @unchecked Sendable {}'
run_check swift
check "a hand-written Sendable conformance fails (only the generated file may declare Sendable)" 1 \
  'Extra\.swift:1: conformance JwtVerified: @unchecked Sendable is not allowed'

new_case conformance-header-over-lines
append $src/Extra.swift 'extension JwtVerified:
    Identifiable
{
    var id: String { kid ?? "" }
}'
run_check swift
check "a conformance on the line after its extension fails" 1 \
  'Extra\.swift:1: conformance JwtVerified: Identifiable is not allowed'

new_case conformance-second-in-list
append $src/Extra.swift 'extension JwtVerified: Identifiable, Comparable where Self: Equatable {}'
run_check swift
check "every conformance of a list is checked, before its where clause" 1 \
  'conformance JwtVerified: Identifiable is not allowed' \
  'conformance JwtVerified: Comparable is not allowed'

new_case conformance-composition
append $src/Extra.swift 'extension JwtVerified: CustomStringConvertible & CustomDebugStringConvertible {}'
run_check swift
check "a protocol composition fails" 1 \
  'conformance JwtVerified: CustomStringConvertible & CustomDebugStringConvertible is not allowed'

new_case conformance-generic-extension
append $src/Extra.swift 'extension Array: CustomReflectable where Element == JwsSigner {}'
run_check swift
check "a conformance of another type fails, also with a where clause" 1 \
  'conformance Array: CustomReflectable is not allowed'

new_case conformance-printing-other-file
append $src/Extra.swift 'extension JwsSigner: CustomStringConvertible {
    public var description: String { "" }
}'
run_check swift
check "a printing conformance outside Redaction.swift fails" 1 \
  'Extra\.swift:1: conformance JwsSigner: CustomStringConvertible is not allowed'

new_case conformance-unlisted-record
append $src/Redaction.swift 'extension JwtVerified: CustomStringConvertible {
    public var description: String { "" }
}'
run_check swift
check "a printing conformance on a record not in the list fails (JWT claims are not redacted, ADR 0058)" 1 \
  'Redaction\.swift:[0-9]+: conformance JwtVerified: CustomStringConvertible is not allowed' \
  'public member description in an extension of JwtVerified'

new_case conformance-other-protocol
append $src/Redaction.swift 'extension JwsSigner: Encodable {}'
run_check swift
check "another protocol on a listed record fails" 1 \
  'Redaction\.swift:[0-9]+: conformance JwsSigner: Encodable is not allowed'

new_case redaction-extension-allowed
edit $src/Redaction.swift \
  'extension JwsSigner: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {' \
  'extension JwsSigner: CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    private var helper: Int { 0 }'
run_check swift
check_last_line "the printing conformances and members on a listed record in Redaction.swift pass, also under a header over lines" 0 \
  "check-binding-api: swift: PASS ($ops operations, $records records, $fields fields, $codes codes)"

new_case redaction-member-other-type
append $src/Redaction.swift 'extension JwsSigner: CustomStringConvertible {
    public var description: Substring { "" }
}'
run_check swift
check "a printing member of another type fails" 1 'public member description in an extension of JwsSigner'

new_case redaction-member-modifier
append $src/Redaction.swift 'extension JwsSigner: CustomStringConvertible {
    @inlinable public var description: String { "" }
    nonisolated public var debugDescription: String { "" }
}'
run_check swift
check "a printing member with an attribute or a modifier fails" 1 \
  'public member description in an extension of JwsSigner' \
  'public member debugDescription in an extension of JwsSigner'

new_case redaction-member-without-conformance
append $src/Redaction.swift 'extension JwsSigner {
    public var description: String { "" }
}'
run_check swift
check "a printing member in an extension without a printing conformance fails" 1 \
  'public member description in an extension of JwsSigner'

new_case redaction-extra-member
edit $src/Redaction.swift \
  'extension JwsSigner: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {' \
  'extension JwsSigner: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public func leak() -> String { key }'
run_check swift
check "another public member in a redaction extension fails" 1 'public member leak in an extension of JwsSigner'

new_case redaction-member-other-protocol
edit $src/Redaction.swift \
  'extension JwsSigner: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {' \
  'extension JwsSigner: CustomReflectable {}
extension JwsSigner: CustomStringConvertible, CustomDebugStringConvertible {'
run_check swift
check "a printing member in an extension without its own protocol fails" 1 \
  'public member customMirror in an extension of JwsSigner'

new_case redaction-missing-conformance
edit $src/Redaction.swift \
  'extension JwsVerifyOptions: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { printed(Self.self, debug: false, printedFields) }
    public var debugDescription: String { printed(Self.self, debug: true, printedFields) }
    public var customMirror: Mirror { mirror(self, printedFields) }' \
  'extension JwsVerifyOptions: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { printed(Self.self, debug: false, printedFields) }
    public var debugDescription: String { printed(Self.self, debug: true, printedFields) }'
run_check swift
check "a listed record without one printing conformance fails (ADR 0065: every path is covered)" 1 \
  'JwsVerifyOptions must conform to CustomReflectable, with public var customMirror: Mirror, exactly once in Redaction\.swift \(conformances 0, members 0\)'

new_case redaction-twice
append $src/Redaction.swift 'extension JwsSigner: CustomStringConvertible {
    public var description: String { "" }
}'
run_check swift
check "a printing conformance declared twice fails" 1 \
  'JwsSigner must conform to CustomStringConvertible, with public var description: String, exactly once in Redaction\.swift \(conformances 2, members 2\)'

new_case redaction-file-missing
rm "$case_dir/$src/Redaction.swift" || lib_die "could not remove Redaction.swift from the copy"
run_check swift
check "without Redaction.swift every listed record fails (ADR 0065)" 1 \
  'JweDecrypted must conform to CustomStringConvertible, with public var description: String, exactly once in Redaction\.swift \(conformances 0, members 0\)' \
  'JwsVerifyOptions must conform to CustomDebugStringConvertible, with public var debugDescription: String, exactly once' \
  'JwsSigner must conform to CustomReflectable, with public var customMirror: Mirror, exactly once'

new_case non-public-conformances
append $src/Extra.swift 'private struct Plain2: CustomStringConvertible { var description: String { "" } }
fileprivate enum Plain3: Error { case a }
extension Int { func internalOnly() {} }'
run_check swift
check_last_line "conformances of non-public types do not count" 0 \
  "check-binding-api: swift: PASS ($ops operations, $records records, $fields fields, $codes codes)"

finish
