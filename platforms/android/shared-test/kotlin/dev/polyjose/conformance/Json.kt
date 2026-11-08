package dev.polyjose.conformance

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

/**
 * JSON for the conformance runner: values come from `org.json` (the JVM's `org.json:json` test
 * dependency, and Android's built-in copy, ADR 0033 §5), and a strict scanner of our own adds what
 * `org.json` lacks.
 *
 * - `org.json` is lenient (single quotes, unquoted names, comments), and Android's copy keeps the
 *   last of duplicate members silently. Vector files must be I-JSON (RFC 7493 §2.3, RFC 8259), as
 *   the Rust runner's strict parser and the JS runner's scanner require, so every text is first
 *   scanned by the RFC 8259 grammar, refusing duplicate members.
 * - A `JSONObject` does not keep member order, but `jwt.issue` claims must reach the library in
 *   file order, which an exact token depends on (ADR 0027 §1; conformance/README.md implementer
 *   note 4). The scanner keeps every value's span, so the runner hands JSON-valued inputs to the
 *   library as their own text ([JsonText.at]), never re-serialized.
 *
 * The value model the runner compares: a JSON object is a `Map<String, Any?>`, an array a
 * `List<Any?>`, and a string, number or boolean the Kotlin value; JSON `null` is Kotlin `null`
 * (presence is `Map.containsKey`, so `"typ": null` and an absent `typ` stay apart, implementer
 * note 3). Numbers are whatever `org.json` produces (`Int`, `Long`, `BigInteger`, `Double`,
 * `BigDecimal`), and compare as doubles ([jsonEqual], implementer note 1).
 */
internal object Json {
    /** Scans [text] as one JSON value (RFC 8259) and parses it with `org.json`. */
    fun parse(text: String): JsonText {
        val root = Scanner(text).scanDocument()
        val value = fromOrgJson(JSONTokener(text).nextValue())
        return JsonText(text, root, value)
    }

    /** [parse]'s value only, for library outputs (a JWK, claims, a JSON JWS or JWE). */
    fun parseValue(text: String): Any? = parse(text).value

    /** `org.json` values to the model above. */
    private fun fromOrgJson(v: Any?): Any? = when (v) {
        null, JSONObject.NULL -> null
        is JSONObject -> {
            val out = LinkedHashMap<String, Any?>()
            val names = v.keys()
            while (names.hasNext()) {
                val name = names.next()
                out[name] = fromOrgJson(v.opt(name))
            }
            out
        }
        is JSONArray -> (0 until v.length()).map { fromOrgJson(v.opt(it)) }
        is String, is Boolean, is Number -> v
        else -> throw IllegalStateException("org.json returned an unexpected ${v.javaClass.name}")
    }
}

/** A vector or output text with its scanned tree and its value. */
internal class JsonText(private val text: String, private val root: JsonNode, val value: Any?) {
    /** The compact text of the value at [path] (member names and array indices), or null when absent. */
    fun opt(vararg path: Any): String? {
        var node: JsonNode? = root
        for (step in path) {
            node = when {
                node is JsonNode.Obj && step is String -> node.members[step]
                node is JsonNode.Arr && step is Int -> node.items.getOrNull(step)
                else -> null
            }
            if (node == null) return null
        }
        return node?.let { compact(text.substring(it.start, it.end)) }
    }

    /** As [opt]; an absent value is a broken vector. */
    fun at(vararg path: Any): String =
        opt(*path) ?: throw HarnessError("no value at /${path.joinToString("/")}")

    /** [text] without insignificant whitespace (outside strings); order and spelling unchanged. */
    private fun compact(text: String): String {
        val out = StringBuilder(text.length)
        var inString = false
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (inString) {
                out.append(c)
                if (c == '\\' && i + 1 < text.length) out.append(text[++i]) else if (c == '"') inString = false
            } else if (c == '"') {
                inString = true
                out.append(c)
            } else if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                out.append(c)
            }
            i++
        }
        return out.toString()
    }
}

/** A scanned value and its span `[start, end)` in the text. */
internal sealed class JsonNode(val start: Int, val end: Int) {
    class Obj(start: Int, end: Int, val members: Map<String, JsonNode>) : JsonNode(start, end)

    class Arr(start: Int, end: Int, val items: List<JsonNode>) : JsonNode(start, end)

    class Scalar(start: Int, end: Int) : JsonNode(start, end)
}

/** Thrown for a text that is not one strict JSON value; the message names the offset. */
internal class JsonSyntaxError(message: String) : Exception(message)

/** The RFC 8259 grammar, refusing duplicate member names (RFC 7493 §2.3). */
private class Scanner(private val text: String) {
    private var pos = 0

    fun scanDocument(): JsonNode {
        val root = value()
        ws()
        if (pos != text.length) fail("trailing characters")
        return root
    }

    private fun fail(what: String): Nothing = throw JsonSyntaxError("invalid JSON at offset $pos: $what")

    private fun ws() {
        while (pos < text.length && text[pos].let { it == ' ' || it == '\t' || it == '\n' || it == '\r' }) pos++
    }

    private fun peek(): Char? = if (pos < text.length) text[pos] else null

    private fun value(): JsonNode {
        ws()
        val start = pos
        return when (peek()) {
            '{' -> obj(start)
            '[' -> arr(start)
            '"' -> {
                string()
                JsonNode.Scalar(start, pos)
            }
            else -> {
                if (!number() && !literal()) fail("expected a value")
                JsonNode.Scalar(start, pos)
            }
        }
    }

    private fun obj(start: Int): JsonNode {
        pos++ // {
        val members = LinkedHashMap<String, JsonNode>()
        ws()
        if (peek() == '}') {
            pos++
            return JsonNode.Obj(start, pos, members)
        }
        while (true) {
            ws()
            if (peek() != '"') fail("expected a member name")
            val name = string()
            if (members.containsKey(name)) fail("duplicate member ${quote(name)} (RFC 7493 §2.3)")
            ws()
            if (peek() != ':') fail("expected ':'")
            pos++
            members[name] = value()
            ws()
            when (peek()) {
                ',' -> pos++
                '}' -> {
                    pos++
                    return JsonNode.Obj(start, pos, members)
                }
                else -> fail("expected ',' or '}'")
            }
        }
    }

    private fun arr(start: Int): JsonNode {
        pos++ // [
        val items = mutableListOf<JsonNode>()
        ws()
        if (peek() == ']') {
            pos++
            return JsonNode.Arr(start, pos, items)
        }
        while (true) {
            items += value()
            ws()
            when (peek()) {
                ',' -> pos++
                ']' -> {
                    pos++
                    return JsonNode.Arr(start, pos, items)
                }
                else -> fail("expected ',' or ']'")
            }
        }
    }

    /** RFC 8259 §7: returns the decoded string; unescaped characters are U+0020 and up except `"` and `\`. */
    private fun string(): String {
        pos++ // "
        val out = StringBuilder()
        while (true) {
            val c = peek() ?: fail("unterminated string")
            pos++
            when {
                c == '"' -> return out.toString()
                c == '\\' -> {
                    val e = peek() ?: fail("unterminated escape")
                    pos++
                    when (e) {
                        '"', '\\', '/' -> out.append(e)
                        'b' -> out.append('\b')
                        'f' -> out.append('\u000c')
                        'n' -> out.append('\n')
                        'r' -> out.append('\r')
                        't' -> out.append('\t')
                        'u' -> {
                            if (pos + 4 > text.length) fail("short \\u escape")
                            val hex = text.substring(pos, pos + 4)
                            if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) fail("bad \\u escape")
                            out.append(hex.toInt(16).toChar())
                            pos += 4
                        }
                        else -> fail("bad escape")
                    }
                }
                c < ' ' -> fail("unescaped control character in a string")
                else -> out.append(c)
            }
        }
    }

    /** RFC 8259 §6: `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`. */
    private fun number(): Boolean {
        val start = pos
        fun digits(): Int {
            val from = pos
            while (peek()?.let { it in '0'..'9' } == true) pos++
            return pos - from
        }
        if (peek() == '-') pos++
        when (peek()) {
            '0' -> pos++
            in '1'..'9' -> digits()
            else -> {
                pos = start
                return false
            }
        }
        if (peek() == '.') {
            pos++
            if (digits() == 0) fail("expected a digit after '.'")
        }
        if (peek() == 'e' || peek() == 'E') {
            pos++
            if (peek() == '+' || peek() == '-') pos++
            if (digits() == 0) fail("expected a digit in the exponent")
        }
        return true
    }

    private fun literal(): Boolean {
        for (word in arrayOf("true", "false", "null")) {
            if (text.startsWith(word, pos)) {
                pos += word.length
                return true
            }
        }
        return false
    }
}

/** Equality of JSON values (RFC 8259): member order ignored, numbers as doubles (implementer note 1). */
internal fun jsonEqual(a: Any?, b: Any?): Boolean = when {
    a is List<*> || b is List<*> ->
        a is List<*> && b is List<*> && a.size == b.size && a.indices.all { jsonEqual(a[it], b[it]) }
    a is Map<*, *> || b is Map<*, *> ->
        a is Map<*, *> && b is Map<*, *> && a.size == b.size &&
            a.keys.all { b.containsKey(it) && jsonEqual(a[it], b[it]) }
    a is Number && b is Number -> {
        val x: Double = a.toDouble()
        val y: Double = b.toDouble()
        x == y
    }
    a is Number || b is Number -> false
    else -> a == b
}

/** True for a number with no fractional part (JSON Schema's `integer`). */
internal fun isIntegral(n: Number): Boolean = when (n) {
    is Int, is Long, is Short, is Byte, is java.math.BigInteger -> true
    is java.math.BigDecimal -> n.signum() == 0 || n.stripTrailingZeros().scale() <= 0
    else -> n.toDouble().let { !it.isInfinite() && !it.isNaN() && it == Math.floor(it) }
}

/** A JSON string literal for [s] (RFC 8259 §7), for the results document and runner-built JSON. */
internal fun quote(s: String): String {
    val out = StringBuilder(s.length + 2).append('"')
    for (c in s) {
        when (c) {
            '"' -> out.append("\\\"")
            '\\' -> out.append("\\\\")
            '\n' -> out.append("\\n")
            '\r' -> out.append("\\r")
            '\t' -> out.append("\\t")
            else -> if (c < ' ') out.append("\\u").append(String.format("%04x", c.code)) else out.append(c)
        }
    }
    return out.append('"').toString()
}

/** Writes a model value as JSON text, for messages and the results document. */
internal fun toJson(v: Any?): String = when (v) {
    null -> "null"
    is String -> quote(v)
    is Boolean -> v.toString()
    is Number -> v.toString()
    is Map<*, *> -> v.entries.joinToString(",", "{", "}") { (k, x) -> "${quote(k.toString())}:${toJson(x)}" }
    is List<*> -> v.joinToString(",", "[", "]") { toJson(it) }
    else -> quote(v.toString())
}
