package dev.polyjose.conformance

/**
 * `vectors_digest` of the results document (ADR 0060 §1-§3).
 */
object VectorsDigest {
    /** The digest lines of [files], sorted (ADR 0060 §2). */
    fun lines(files: List<VectorBytes>): List<ByteArray> = TODO("ADR 0060 §2")

    /** The digest of [files] (ADR 0060 §3). */
    fun of(files: List<VectorBytes>): String = TODO("ADR 0060 §3")
}
