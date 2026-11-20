package dev.polyjose.conformance

import java.security.MessageDigest

/**
 * `vectors_digest` of the results document (ADR 0060 §1-§3), which binds the results to the exact
 * vector bytes this run parsed.
 *
 * - One line per vector file read: `<id>` TAB `<lowercase hex SHA-256 of the raw bytes>` LF,
 *   UTF-8 encoded (ADR 0060 §2). Unreadable files and symbolic links have no line.
 * - The lines are sorted by their UTF-8 bytes compared as unsigned, a shorter prefix first, never
 *   by Kotlin `String` order, which is UTF-16 order and differs outside ASCII (ADR 0060 §2).
 * - The digest is the lowercase hex SHA-256 of the sorted lines' concatenation (ADR 0060 §3).
 *
 * SHA-256 is the platform's own, `java.security.MessageDigest`, never polyjose's API under test
 * (ADR 0060 §5). It exists on the JVM and on Android alike.
 */
object VectorsDigest {
    /** The SHA-256 of the empty input, which no valid results file has (ADR 0060 §3). */
    const val EMPTY: String = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    /** The digest line of one file: `<id>\t<sha256 hex>\n` in UTF-8 (ADR 0060 §2). */
    fun line(file: VectorBytes): ByteArray = "${file.id}\t${sha256Hex(file.bytes)}\n".toByteArray(Charsets.UTF_8)

    /** The digest lines of [files], sorted by unsigned UTF-8 bytes (ADR 0060 §2). */
    fun lines(files: List<VectorBytes>): List<ByteArray> = files.map(::line).sortedWith(UNSIGNED_BYTES)

    /** The digest of [files] (ADR 0060 §3). */
    fun of(files: List<VectorBytes>): String {
        val sha256 = MessageDigest.getInstance("SHA-256")
        for (line in lines(files)) sha256.update(line)
        return hex(sha256.digest())
    }

    /** Lexicographic order of unsigned bytes; a proper prefix sorts first (ADR 0060 §2). */
    val UNSIGNED_BYTES: Comparator<ByteArray> = Comparator { a, b ->
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return@Comparator d
        }
        a.size - b.size
    }

    private fun sha256Hex(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun hex(bytes: ByteArray): String {
        val digits = "0123456789abcdef"
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append(digits[v ushr 4]).append(digits[v and 0x0f])
        }
        return out.toString()
    }
}
