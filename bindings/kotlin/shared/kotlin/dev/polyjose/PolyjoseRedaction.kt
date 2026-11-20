package dev.polyjose

/**
 * The printed form of a secret record field (ADR 0065 decision 1, 2; ADR 0030 §7.5): its length
 * only, `<redacted, N bytes>`. Called by the `toString()` the build adds to the ADR 0065 records
 * (feature 0008 F05, `UniffiKotlinPatch`); hand-written per ADR 0030 §1. A `null` field prints
 * `null`, as the generated `data class` does, since it holds no secret.
 */
internal object PolyjoseRedaction {
    /** A secret byte field: its size. */
    fun redact(value: ByteArray?): String = if (value == null) "null" else "<redacted, ${value.size} bytes>"

    /**
     * A secret string field (a JWK as JSON text): its UTF-8 length, the bytes Rust receives
     * (ADR 0030 §2), counted without encoding a copy of the secret.
     */
    fun redact(value: String?): String = if (value == null) "null" else "<redacted, ${utf8Length(value)} bytes>"

    /** UTF-8 length; an unpaired surrogate counts as U+FFFD (3 bytes). */
    private fun utf8Length(s: String): Int {
        var n = 0
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c.code < 0x80 -> n += 1
                c.code < 0x800 -> n += 2
                c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate() -> { n += 4; i++ }
                else -> n += 3
            }
            i++
        }
        return n
    }
}
