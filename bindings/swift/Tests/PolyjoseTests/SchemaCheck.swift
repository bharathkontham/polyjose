import Foundation

/// Checks a parsed vector against `conformance/schema.json` (JSON Schema draft 2020-12), as every
/// runner must (conformance/README.md "Rules for every runner": a file that is not schema-valid
/// fails, including a misspelled member anywhere). The Swift form of the JS runner's `schema.ts`.
///
/// The test target has no dependencies, so this is a small checker of exactly the keywords
/// schema.json uses: `$ref` (local `#/$defs/...`), `type`, `enum`, `const`, `properties`,
/// `required`, `additionalProperties` (boolean or schema), `items`, `minItems`, `maxItems`,
/// `uniqueItems`, `minimum`, `maximum`, `minLength`, `pattern`, `allOf`, `oneOf`,
/// `if`/`then`/`else`, and the annotations `$schema`, `title`, `description`. Any other keyword
/// throws, so a schema change can't be silently ignored by this runner.
///
/// `JSONSerialization` reads `1300819439.0` as a double equal to 1300819439, so
/// `"type": "integer"` can't tell them apart here; the Rust runner's
/// `jwt_vectors_are_binding_ready` keeps such spellings out of the vector files
/// (conformance/README.md "Binding readiness").
final class SchemaChecker {
    private static let annotations: Set<String> = ["$schema", "title", "description"]
    private static let keywords: Set<String> = [
        "$ref", "$defs", "type", "enum", "const", "properties", "required", "additionalProperties", "items",
        "minItems", "maxItems", "uniqueItems", "minimum", "maximum", "minLength", "pattern", "allOf", "oneOf",
        "if", "then", "else",
    ]

    struct Unsupported: Error, CustomStringConvertible {
        let description: String
    }

    private let root: JSONValue
    private let defs: [(String, JSONValue)]
    private var regexes: [String: NSRegularExpression] = [:]

    init(schema: JSONValue) throws {
        guard schema.isObject else { throw Unsupported(description: "schema: the root is not a schema") }
        root = schema
        defs = schema["$defs"]?.objectMembers ?? []
    }

    /// The first violation by `value`, as `<JSON pointer>: <problem>`, or nil when it is valid.
    /// Throws on a schema construct this checker does not implement.
    func violation(_ value: JSONValue) throws -> String? {
        try check(root, value, "")
    }

    private func regex(_ pattern: String) throws -> NSRegularExpression {
        if let re = regexes[pattern] { return re }
        let re = try NSRegularExpression(pattern: pattern)
        regexes[pattern] = re
        return re
    }

    private func hasType(_ v: JSONValue, _ type: String) throws -> Bool {
        switch (type, v) {
        case ("object", .object), ("array", .array), ("string", .string), ("boolean", .bool), ("null", .null),
            ("number", .number):
            return true
        case ("integer", .number(let n)):
            return n.isFinite && n.rounded() == n
        case ("object", _), ("array", _), ("string", _), ("boolean", _), ("null", _), ("number", _), ("integer", _):
            return false
        default:
            throw Unsupported(description: "schema: unknown type \(type)")
        }
    }

    private func check(_ schema: JSONValue, _ v: JSONValue, _ ptr: String) throws -> String? {
        let at = ptr.isEmpty ? "(root)" : ptr
        if case .bool(let allowed) = schema { return allowed ? nil : "\(at): not allowed" }
        guard let members = schema.objectMembers else { throw Unsupported(description: "schema: not a schema at \(at)") }
        for (k, _) in members where !Self.keywords.contains(k) && !Self.annotations.contains(k) {
            throw Unsupported(description: "schema: unsupported keyword \(k)")
        }

        if let ref = schema["$ref"] {
            let prefix = "#/$defs/"
            guard let text = ref.stringValue, text.hasPrefix(prefix),
                let target = defs.first(where: { $0.0 == String(text.dropFirst(prefix.count)) })?.1
            else { throw Unsupported(description: "schema: unresolvable $ref \(ref)") }
            if let bad = try check(target, v, ptr) { return bad }
        }
        if let type = schema["type"] {
            let types = type.arrayValue?.compactMap(\.stringValue) ?? [type.stringValue ?? ""]
            if try !types.contains(where: { try hasType(v, $0) }) {
                return "\(at): must be of type \(types.joined(separator: " or "))"
            }
        }
        if let options = schema["enum"] {
            guard let list = options.arrayValue else { throw Unsupported(description: "schema: enum is not an array") }
            if !list.contains(where: { JSONValue.equal($0, v) }) { return "\(at): must be one of \(options)" }
        }
        if let constant = schema["const"], !JSONValue.equal(constant, v) { return "\(at): must be \(constant)" }

        if let object = v.objectMembers {
            let props = schema["properties"]?.objectMembers ?? []
            for name in schema["required"]?.arrayValue?.compactMap(\.stringValue) ?? [] where !v.has(name) {
                return "\(ptr)/\(name): required member is missing"
            }
            for (name, sub) in props {
                if let member = v[name], let bad = try check(sub, member, "\(ptr)/\(name)") { return bad }
            }
            if let additional = schema["additionalProperties"] {
                for (name, member) in object where !props.contains(where: { JSONValue.sameText($0.0, name) }) {
                    if case .bool(false) = additional { return "\(ptr)/\(name): unknown member (additionalProperties is false)" }
                    if let bad = try check(additional, member, "\(ptr)/\(name)") { return bad }
                }
            }
        }
        if let items = v.arrayValue {
            if let min = schema["minItems"]?.numberValue, Double(items.count) < min { return "\(at): at least \(Int(min)) item(s)" }
            if let max = schema["maxItems"]?.numberValue, Double(items.count) > max { return "\(at): at most \(Int(max)) item(s)" }
            if case .bool(true) = schema["uniqueItems"] ?? .null {
                for (i, x) in items.enumerated() where items.prefix(i).contains(where: { JSONValue.equal($0, x) }) {
                    return "\(at): items must be unique"
                }
            }
            if let itemSchema = schema["items"] {
                for (i, item) in items.enumerated() {
                    if let bad = try check(itemSchema, item, "\(ptr)/\(i)") { return bad }
                }
            }
        }
        if let n = v.numberValue {
            if let min = schema["minimum"]?.numberValue, n < min { return "\(at): at least \(min)" }
            if let max = schema["maximum"]?.numberValue, n > max { return "\(at): at most \(max)" }
        }
        if let s = v.stringValue {
            // JSON Schema counts characters as code points.
            if let min = schema["minLength"]?.numberValue, Double(s.unicodeScalars.count) < min {
                return "\(at): at least \(Int(min)) character(s)"
            }
            if let pattern = schema["pattern"]?.stringValue {
                let re = try regex(pattern)
                if re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) == nil { return "\(at): must match \(pattern)" }
            }
        }

        if let all = schema["allOf"]?.arrayValue {
            for sub in all {
                if let bad = try check(sub, v, ptr) { return bad }
            }
        }
        if let one = schema["oneOf"]?.arrayValue {
            let results = try one.map { try check($0, v, ptr) }
            let passing = results.filter { $0 == nil }.count
            if passing != 1 {
                return passing == 0
                    ? "\(at): matches none of oneOf (\(results.compactMap { $0 }.joined(separator: "; ")))"
                    : "\(at): matches more than one of oneOf"
            }
        }
        if let condition = schema["if"] {
            let branch = try check(condition, v, ptr) == nil ? schema["then"] : schema["else"]
            if let branch, let bad = try check(branch, v, ptr) { return bad }
        }
        return nil
    }
}
