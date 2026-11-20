package dev.polyjose.conformance

/**
 * Checks a parsed vector against `conformance/schema.json` (JSON Schema draft 2020-12), as every
 * runner must: a file that is not schema-valid fails, a misspelled member anywhere included
 * (conformance/README.md "Rules for every runner").
 *
 * The same small checker as the JS runner's `bindings/js/conformance/schema.ts`, of exactly the
 * keywords schema.json uses: `$ref` (local `#/$defs/...`), `type`, `enum`, `const`, `properties`,
 * `required`, `additionalProperties` (boolean or schema), `items`, `minItems`, `maxItems`,
 * `uniqueItems`, `minimum`, `maximum`, `minLength`, `pattern`, `allOf`, `oneOf`,
 * `if`/`then`/`else`, and the annotations `$schema`, `title`, `description`. Any other keyword
 * fails the run ([IllegalStateException]), so a schema change can't be silently ignored here.
 */
internal class Schema(private val root: Any?) {
    private val defs: Map<*, *> = ((root as? Map<*, *>)?.get("\$defs") as? Map<*, *>) ?: emptyMap<String, Any?>()
    private val regexes = HashMap<String, Regex>()

    init {
        check(root is Map<*, *> || root is Boolean) { "schema: the root is not a schema" }
    }

    /** The first violation of the schema by [value], as `<JSON pointer>: <problem>`, or null when valid. */
    fun violation(value: Any?): String? = check(root, value, "")

    private fun check(schema: Any?, v: Any?, ptr: String): String? {
        val at = if (ptr == "") "(root)" else ptr
        if (schema == true) return null
        if (schema == false) return "$at: not allowed"
        val s = schema as? Map<*, *> ?: error("schema: not a schema at $at")
        for (k in s.keys) check(k in KEYWORDS || k in ANNOTATIONS) { "schema: unsupported keyword $k" }

        s["\$ref"]?.let { ref ->
            val name = Regex("^#/\\\$defs/([^/]+)$").find(ref.toString())?.groupValues?.get(1)
            val target = if (name != null && defs.containsKey(name)) defs[name] else error("schema: unresolvable \$ref $ref")
            check(target, v, ptr)?.let { return it }
        }
        s["type"]?.let { type ->
            val types = type as? List<*> ?: listOf(type)
            if (types.none { hasType(v, it) }) return "$at: must be of type ${types.joinToString(" or ")}"
        }
        s["enum"]?.let { options ->
            val list = options as? List<*> ?: error("schema: enum is not an array")
            if (list.none { jsonEqual(it, v) }) return "$at: must be one of ${toJson(list)}"
        }
        if (s.containsKey("const") && !jsonEqual(s["const"], v)) return "$at: must be ${toJson(s["const"])}"

        if (v is Map<*, *>) {
            val props = s["properties"] as? Map<*, *> ?: emptyMap<String, Any?>()
            (s["required"] as? List<*>)?.forEach { name ->
                if (!v.containsKey(name)) return "$ptr/$name: required member is missing"
            }
            for ((name, sub) in props) {
                if (v.containsKey(name)) check(sub, v[name], "$ptr/$name")?.let { return it }
            }
            if (s.containsKey("additionalProperties")) {
                val extra = s["additionalProperties"]
                for (name in v.keys) {
                    if (props.containsKey(name)) continue
                    if (extra == false) return "$ptr/$name: unknown member (additionalProperties is false)"
                    check(extra, v[name], "$ptr/$name")?.let { return it }
                }
            }
        }
        if (v is List<*>) {
            (s["minItems"] as? Number)?.let { if (v.size < it.toDouble()) return "$at: at least $it item(s)" }
            (s["maxItems"] as? Number)?.let { if (v.size > it.toDouble()) return "$at: at most $it item(s)" }
            if (s["uniqueItems"] == true && v.indices.any { i -> v.indexOfFirst { jsonEqual(it, v[i]) } != i }) {
                return "$at: items must be unique"
            }
            s["items"]?.let { items -> v.forEachIndexed { i, x -> check(items, x, "$ptr/$i")?.let { return it } } }
        }
        if (v is Number) {
            (s["minimum"] as? Number)?.let { if (v.toDouble() < it.toDouble()) return "$at: at least $it" }
            (s["maximum"] as? Number)?.let { if (v.toDouble() > it.toDouble()) return "$at: at most $it" }
        }
        if (v is String) {
            // JSON Schema counts characters as code points.
            (s["minLength"] as? Number)?.let {
                if (v.codePointCount(0, v.length) < it.toDouble()) return "$at: at least $it character(s)"
            }
            (s["pattern"] as? String)?.let { p ->
                if (!regexes.getOrPut(p) { Regex(p) }.containsMatchIn(v)) return "$at: must match $p"
            }
        }

        (s["allOf"] as? List<*>)?.forEach { sub -> check(sub, v, ptr)?.let { return it } }
        (s["oneOf"] as? List<*>)?.let { subs ->
            val results = subs.map { check(it, v, ptr) }
            val passing = results.count { it == null }
            if (passing != 1) {
                return if (passing == 0) "$at: matches none of oneOf (${results.joinToString("; ")})" else "$at: matches more than one of oneOf"
            }
        }
        if (s.containsKey("if")) {
            val branch = if (check(s["if"], v, ptr) == null) s["then"] else s["else"]
            if (branch != null) check(branch, v, ptr)?.let { return it }
        }
        return null
    }

    private fun hasType(v: Any?, type: Any?): Boolean = when (type) {
        "object" -> v is Map<*, *>
        "array" -> v is List<*>
        "string" -> v is String
        "boolean" -> v is Boolean
        "null" -> v == null
        "number" -> v is Number
        "integer" -> v is Number && isIntegral(v)
        else -> error("schema: unknown type $type")
    }

    private companion object {
        val ANNOTATIONS = setOf("\$schema", "title", "description")
        val KEYWORDS = setOf(
            "\$ref", "\$defs", "type", "enum", "const", "properties", "required", "additionalProperties", "items",
            "minItems", "maxItems", "uniqueItems", "minimum", "maximum", "minLength", "pattern", "allOf", "oneOf",
            "if", "then", "else",
        )
    }
}
