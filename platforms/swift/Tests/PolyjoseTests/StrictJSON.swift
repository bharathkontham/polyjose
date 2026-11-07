import Foundation

/// A JSON value (RFC 8259) as the runner compares it: member order ignored, numbers as doubles,
/// strings code point for code point (conformance/README.md: "compared as a JSON value";
/// implementer note 1). Objects keep their members as a list, so two names that Swift `String`
/// would call equal (canonically equivalent) stay distinct, as they are in JSON.
indirect enum JSONValue: CustomStringConvertible, Sendable {
    case object([(String, JSONValue)])
    case array([JSONValue])
    case string(String)
    case number(Double)
    case bool(Bool)
    case null

    /// Parses `data` with Foundation's `JSONSerialization` (fragments allowed). Duplicate member
    /// names are refused by ``JSONScanner`` before this is called (RFC 7493 §2.3).
    static func parse(_ data: Data) throws -> JSONValue {
        try JSONValue(foundation: JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]))
    }

    /// Parses a JSON text returned by the library (a JWK, a JSON JWS or JWE, claims).
    static func parse(_ text: String) throws -> JSONValue {
        try parse(Data(text.utf8))
    }

    /// Converts a `JSONSerialization` result. Booleans are `CFBoolean`s, told apart from numbers
    /// by their type id (an `NSNumber` 1 would otherwise bridge to `true`).
    init(foundation value: Any) throws {
        switch value {
        case let dictionary as NSDictionary:
            var members: [(String, JSONValue)] = []
            for (key, member) in dictionary {
                guard let name = key as? String else { throw JSONError("a member name is not a string") }
                members.append((name, try JSONValue(foundation: member)))
            }
            self = .object(members)
        case let array as NSArray:
            self = .array(try array.map { try JSONValue(foundation: $0) })
        case let string as String:
            self = .string(string)
        case let number as NSNumber:
            if CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID() {
                self = .bool(number.boolValue)
            } else {
                self = .number(number.doubleValue)
            }
        case is NSNull:
            self = .null
        default:
            throw JSONError("unexpected JSONSerialization value of type \(type(of: value))")
        }
    }

    /// The member `name` of an object, or nil (also for a non-object).
    subscript(name: String) -> JSONValue? {
        guard case .object(let members) = self else { return nil }
        return members.first { JSONValue.sameText($0.0, name) }?.1
    }

    func has(_ name: String) -> Bool { self[name] != nil }

    var isObject: Bool {
        if case .object = self { return true }
        return false
    }

    var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    var numberValue: Double? {
        if case .number(let n) = self { return n }
        return nil
    }

    var arrayValue: [JSONValue]? {
        if case .array(let items) = self { return items }
        return nil
    }

    var objectMembers: [(String, JSONValue)]? {
        if case .object(let members) = self { return members }
        return nil
    }

    /// Strings compared code point for code point, never by canonical equivalence.
    static func sameText(_ a: String, _ b: String) -> Bool {
        a.unicodeScalars.elementsEqual(b.unicodeScalars)
    }

    /// Equality of JSON values (RFC 8259): member order ignored, numbers as doubles, strings
    /// code point for code point.
    static func equal(_ a: JSONValue, _ b: JSONValue) -> Bool {
        switch (a, b) {
        case (.object(let x), .object(let y)):
            guard x.count == y.count else { return false }
            return x.allSatisfy { name, value in
                y.contains { sameText($0.0, name) && equal($0.1, value) }
            }
        case (.array(let x), .array(let y)):
            return x.count == y.count && zip(x, y).allSatisfy { equal($0, $1) }
        case (.string(let x), .string(let y)):
            return sameText(x, y)
        case (.number(let x), .number(let y)):
            return x == y
        case (.bool(let x), .bool(let y)):
            return x == y
        case (.null, .null):
            return true
        default:
            return false
        }
    }

    /// Compact JSON text, for messages and the results document. Integral numbers within ±2^53
    /// are written without a fraction.
    var description: String {
        switch self {
        case .object(let members):
            return "{" + members.map { JSONValue.quote($0.0) + ":" + $0.1.description }.joined(separator: ",") + "}"
        case .array(let items):
            return "[" + items.map(\.description).joined(separator: ",") + "]"
        case .string(let s):
            return JSONValue.quote(s)
        case .number(let n):
            if n.rounded() == n, abs(n) <= 9_007_199_254_740_991 { return String(Int64(n)) }
            return String(n)
        case .bool(let b):
            return b ? "true" : "false"
        case .null:
            return "null"
        }
    }

    /// A JSON string literal for `s` (RFC 8259 §7): `"` and `\` escaped, and the control
    /// characters U+0000-U+001F as `\uXXXX` (or their short forms).
    static func quote(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }
}

struct JSONError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// A strict scanner for vector files (conformance/README.md "Rules for every runner"), the Swift
/// form of the JS runner's `json-text.ts`. `JSONSerialization` alone is not enough:
/// - it silently keeps one of duplicate members, while vector files must be I-JSON (RFC 7493
///   §2.3; the Rust runner fails them with polyjose's strict parser);
/// - a Swift dictionary has no member order, so re-serializing a parsed object changes the order
///   of `jwt.issue` claims, which an exact token depends on (ADR 0027 §1; implementer note 4).
///
/// So the runner scans the text's bytes once (RFC 8259 grammar, UTF-8 required by RFC 8259 §8.1
/// and RFC 7493 §2.1), refusing duplicates and lone surrogate escapes, and keeps the byte span of
/// every value; ``JSONText/at(_:)`` then hands the library a value's own text, in file order.
struct JSONScanner {
    /// A scanned value: its byte span in the text, and its members or items.
    final class Node: Sendable {
        enum Kind: Sendable {
            /// Members by the UTF-8 bytes of their decoded name.
            case object([[UInt8]: Node])
            case array([Node])
            case scalar
        }
        let start: Int
        let end: Int
        let kind: Kind
        init(start: Int, end: Int, kind: Kind) {
            self.start = start
            self.end = end
            self.kind = kind
        }
    }

    private let bytes: [UInt8]
    private var pos = 0

    private init(_ bytes: [UInt8]) { self.bytes = bytes }

    /// Scans `bytes` as one JSON text; throws a ``JSONError`` naming the offset.
    static func scan(_ bytes: [UInt8]) throws -> Node {
        guard String(bytes: bytes, encoding: .utf8) != nil else {
            throw JSONError("not UTF-8 (RFC 8259 §8.1)")
        }
        var scanner = JSONScanner(bytes)
        let root = try scanner.value()
        scanner.whitespace()
        guard scanner.pos == bytes.count else { throw scanner.error("trailing characters") }
        return root
    }

    private func error(_ what: String) -> JSONError {
        JSONError("invalid JSON at byte \(pos): \(what)")
    }

    private var current: UInt8? { pos < bytes.count ? bytes[pos] : nil }

    /// RFC 8259 §2: space, tab, LF, CR.
    private mutating func whitespace() {
        while let c = current, c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d { pos += 1 }
    }

    private mutating func expect(_ c: UInt8, _ what: String) throws {
        guard current == c else { throw error(what) }
        pos += 1
    }

    private mutating func value() throws -> Node {
        whitespace()
        let start = pos
        guard let c = current else { throw error("expected a value") }
        switch c {
        case UInt8(ascii: "{"):
            pos += 1
            var members: [[UInt8]: Node] = [:]
            whitespace()
            if current == UInt8(ascii: "}") {
                pos += 1
                return Node(start: start, end: pos, kind: .object(members))
            }
            while true {
                whitespace()
                guard current == UInt8(ascii: "\"") else { throw error("expected a member name") }
                let name = try string()
                if members[name] != nil {
                    throw error("duplicate member \(JSONValue.quote(String(decoding: name, as: UTF8.self))) (RFC 7493 §2.3)")
                }
                whitespace()
                try expect(UInt8(ascii: ":"), "expected ':'")
                members[name] = try value()
                whitespace()
                if current == UInt8(ascii: ",") {
                    pos += 1
                    continue
                }
                try expect(UInt8(ascii: "}"), "expected ',' or '}'")
                return Node(start: start, end: pos, kind: .object(members))
            }
        case UInt8(ascii: "["):
            pos += 1
            var items: [Node] = []
            whitespace()
            if current == UInt8(ascii: "]") {
                pos += 1
                return Node(start: start, end: pos, kind: .array(items))
            }
            while true {
                items.append(try value())
                whitespace()
                if current == UInt8(ascii: ",") {
                    pos += 1
                    continue
                }
                try expect(UInt8(ascii: "]"), "expected ',' or ']'")
                return Node(start: start, end: pos, kind: .array(items))
            }
        case UInt8(ascii: "\""):
            _ = try string()
        case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"):
            try number()
        case UInt8(ascii: "t"):
            try literal("true")
        case UInt8(ascii: "f"):
            try literal("false")
        case UInt8(ascii: "n"):
            try literal("null")
        default:
            throw error("expected a value")
        }
        return Node(start: start, end: pos, kind: .scalar)
    }

    private mutating func literal(_ word: String) throws {
        for c in word.utf8 { try expect(c, "expected \(word)") }
    }

    /// RFC 8259 §6: `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
    private mutating func number() throws {
        func digits(_ scanner: inout JSONScanner) throws {
            guard let c = scanner.current, (0x30...0x39).contains(c) else { throw scanner.error("expected a digit") }
            while let c = scanner.current, (0x30...0x39).contains(c) { scanner.pos += 1 }
        }
        if current == UInt8(ascii: "-") { pos += 1 }
        if current == UInt8(ascii: "0") {
            pos += 1
        } else {
            try digits(&self)
        }
        if current == UInt8(ascii: ".") {
            pos += 1
            try digits(&self)
        }
        if current == UInt8(ascii: "e") || current == UInt8(ascii: "E") {
            pos += 1
            if current == UInt8(ascii: "+") || current == UInt8(ascii: "-") { pos += 1 }
            try digits(&self)
        }
    }

    /// RFC 8259 §7. Returns the decoded string's UTF-8 bytes. Unescaped characters are U+0020 and
    /// above except `"` and `\`; a `\u` escape of a lone surrogate is refused (RFC 7493 §2.1).
    private mutating func string() throws -> [UInt8] {
        try expect(UInt8(ascii: "\""), "expected '\"'")
        var out: [UInt8] = []
        while true {
            guard let c = current else { throw error("unterminated string") }
            pos += 1
            switch c {
            case UInt8(ascii: "\""):
                return out
            case UInt8(ascii: "\\"):
                guard let e = current else { throw error("unterminated escape") }
                pos += 1
                switch e {
                case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"): out.append(e)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0c)
                case UInt8(ascii: "n"): out.append(0x0a)
                case UInt8(ascii: "r"): out.append(0x0d)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "u"):
                    var scalar = try hex4()
                    if (0xD800...0xDBFF).contains(scalar) {
                        guard current == UInt8(ascii: "\\"), pos + 1 < bytes.count, bytes[pos + 1] == UInt8(ascii: "u")
                        else { throw error("lone surrogate escape (RFC 7493 §2.1)") }
                        pos += 2
                        let low = try hex4()
                        guard (0xDC00...0xDFFF).contains(low) else { throw error("lone surrogate escape (RFC 7493 §2.1)") }
                        scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00)
                    } else if (0xDC00...0xDFFF).contains(scalar) {
                        throw error("lone surrogate escape (RFC 7493 §2.1)")
                    }
                    guard let u = Unicode.Scalar(scalar) else { throw error("invalid escape") }
                    out.append(contentsOf: Array(String(Character(u)).utf8))
                default:
                    throw error("invalid escape")
                }
            case 0x00..<0x20:
                throw error("unescaped control character")
            default:
                out.append(c)
            }
        }
    }

    private mutating func hex4() throws -> UInt32 {
        var value: UInt32 = 0
        for _ in 0..<4 {
            guard let c = current else { throw error("short \\u escape") }
            let digit: UInt32
            switch c {
            case 0x30...0x39: digit = UInt32(c - 0x30)
            case 0x41...0x46: digit = UInt32(c - 0x41 + 10)
            case 0x61...0x66: digit = UInt32(c - 0x61 + 10)
            default: throw error("invalid \\u escape")
            }
            value = value << 4 | digit
            pos += 1
        }
        return value
    }
}

/// One step of a path into a vector: a member name or an array index.
enum PathStep: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral, CustomStringConvertible, Sendable {
    case member(String)
    case index(Int)

    init(stringLiteral value: String) { self = .member(value) }
    init(integerLiteral value: Int) { self = .index(value) }

    var description: String {
        switch self {
        case .member(let name): return name
        case .index(let i): return String(i)
        }
    }
}

/// A vector file's bytes and scan: inputs go to the library as their own text, in file order.
struct JSONText: Sendable {
    let bytes: [UInt8]
    let root: JSONScanner.Node

    /// The node at `path`, if any.
    func node(_ path: [PathStep]) -> JSONScanner.Node? {
        var node: JSONScanner.Node? = root
        for step in path {
            guard let current = node else { return nil }
            switch (step, current.kind) {
            case (.member(let name), .object(let members)): node = members[Array(name.utf8)]
            case (.index(let i), .array(let items)): node = items.indices.contains(i) ? items[i] : nil
            default: node = nil
            }
        }
        return node
    }

    /// The compact text of the value at `path`, in file order, or nil when it is absent.
    func text(_ path: [PathStep]) -> String? {
        guard let node = node(path) else { return nil }
        return JSONText.compact(bytes[node.start..<node.end])
    }

    /// `text` without insignificant whitespace (outside strings); order and spelling unchanged.
    static func compact(_ text: ArraySlice<UInt8>) -> String {
        var out: [UInt8] = []
        out.reserveCapacity(text.count)
        var inString = false
        var escaped = false
        for c in text {
            if inString {
                out.append(c)
                if escaped {
                    escaped = false
                } else if c == UInt8(ascii: "\\") {
                    escaped = true
                } else if c == UInt8(ascii: "\"") {
                    inString = false
                }
            } else if c == UInt8(ascii: "\"") {
                inString = true
                out.append(c)
            } else if c != 0x20, c != 0x09, c != 0x0a, c != 0x0d {
                out.append(c)
            }
        }
        return String(decoding: out, as: UTF8.self)
    }
}
