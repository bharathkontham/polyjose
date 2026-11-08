package dev.polyjose.conformance

/**
 * One file the host found under `conformance/vectors/` (ADR 0034 §1, ADR 0045 §4), handed to
 * [Runner]. The host does the file system work (the JVM test walks a directory, the Android test
 * reads assets); this package uses no JVM-only API, so both hosts share it (feature 0008 T02).
 *
 * [path] is the file's path relative to `conformance/vectors/`, with `/` separators on every
 * platform. The vector id is `<path>#0` (one vector per file, ADR 0045 §4).
 */
sealed class VectorInput {
    abstract val path: String

    /** The vector id of ADR 0034 §1 as amended by ADR 0045 §4. */
    val id: String get() = "$path#0"
}

/**
 * A regular `*.json` file and the raw bytes the host read, exactly once (ADR 0060 §2): the runner
 * hashes these bytes for `vectors_digest` and parses the same bytes, with no conversion.
 */
class VectorBytes(override val path: String, val bytes: ByteArray) : VectorInput()

/**
 * A file the host could not read, or a symbolic link (ADR 0060 §2): a `fail` result
 * (ADR 0034 §3) and no digest line. [problem] says why, without any file content.
 */
class VectorUnreadable(override val path: String, val problem: String) : VectorInput()
