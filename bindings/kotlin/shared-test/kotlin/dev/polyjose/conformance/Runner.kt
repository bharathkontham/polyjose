package dev.polyjose.conformance

import dev.polyjose.errorCodes
import dev.polyjose.version
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * The Kotlin conformance runner (ADR 0008 layer 4, ADR 0033 §5, ADR 0034), shared by the JVM test
 * (`:polyjose-jvm`, runner `jvm`) and the Android instrumented test (`:polyjose`, runner
 * `android-emulator`). It runs every vector file through the **generated Kotlin API** (what users
 * call), mirroring the Rust reference runner `crates/polyjose/tests/conformance.rs` and the shared
 * JS runner `bindings/js/conformance/runner.ts` operation by operation, and returns the ADR 0034 §2
 * results document with the ADR 0060 `vectors_digest`.
 *
 * It uses no JVM-only API (no `java.nio.file`, no `java.io.File`): the host hands it the files'
 * bytes ([VectorInput]) and the text of `conformance/schema.json`, and writes the document.
 *
 * Rules (conformance/README.md "Rules for every runner", "Binding runners"):
 * - a file that isn't strict UTF-8 JSON (duplicate members included, RFC 7493 §2.3) or isn't
 *   valid against `schema.json` fails, whether or not it would be skipped;
 * - a vector whose `features` this build lacks is `skipped` with `feature:<names>` (ADR 0034 §3),
 *   and one whose `features_absent` this build has with `!<name>` after them (ADR 0056 §2). The
 *   binding configuration enables none ([BINDING_FEATURES]); nothing else is ever skipped;
 * - an unknown or unmapped operation, an unreadable file, a broken vector and any exception that
 *   isn't a `PolyjoseException` (a harness bug, an `IllegalArgumentException`) is a `fail`;
 * - a `PolyjoseException` is the library's outcome, compared by `code()`, never by class name or
 *   message (ADR 0030 §5; implementer note 8).
 */
object Runner {
    /** The vector feature names the binding build enables: none, the core defaults (ADR 0034 §3, ADR 0056). */
    val BINDING_FEATURES: List<String> = emptyList()

    /** The runner names of ADR 0034 §2 this runner may write. */
    val RUNNER_NAMES: Set<String> = setOf("jvm", "android-emulator")

    /**
     * Runs every input and returns the results document. Throws [IllegalArgumentException] for an
     * unknown [runner] and [IllegalStateException] when no vector file was read (ADR 0060 §3: an
     * empty corpus fails the run and writes no file) or the schema is unusable.
     */
    fun run(runner: String, inputs: List<VectorInput>, schemaJson: String): ResultsDocument {
        require(runner in RUNNER_NAMES) { "runner must be one of $RUNNER_NAMES (ADR 0034 §2), not $runner" }
        val read = inputs.filterIsInstance<VectorBytes>()
        check(read.isNotEmpty()) { "no vector file was read (${inputs.size} found); an empty corpus fails (ADR 0060 §3)" }
        check(inputs.map { it.path }.toSet().size == inputs.size) { "a vector path was given twice" }
        val schema = Schema(Json.parseValue(schemaJson))
        val results = inputs.map { input ->
            when (input) {
                is VectorBytes -> runOne(input, schema)
                is VectorUnreadable -> VectorResult(input.id, null, null, Status.FAIL, null, "${input.path}: ${input.problem}")
            }
        }.sortedWith(compareBy(VectorsDigest.UNSIGNED_BYTES) { it.id.toByteArray(Charsets.UTF_8) })
        return ResultsDocument(
            runner = runner,
            polyjose = version(),
            features = BINDING_FEATURES,
            errorCodes = errorCodes(),
            vectorsDigest = VectorsDigest.of(read),
            results = results,
        )
    }

    private fun runOne(file: VectorBytes, schema: Schema): VectorResult {
        var op: String? = null
        var source: String? = null
        fun fail(problem: String, actual: Actual? = null) =
            VectorResult(file.id, source, op, Status.FAIL, actual, "${file.path} (source: ${source ?: "<missing>"}): $problem")

        val text: JsonText = try {
            Json.parse(decodeUtf8(file.bytes))
        } catch (e: CharacterCodingException) {
            return fail("not UTF-8 (RFC 8259 §8.1): ${e.javaClass.simpleName}")
        } catch (e: JsonSyntaxError) {
            return fail("not a valid JSON text (${e.message}); see conformance/schema.json")
        } catch (e: Exception) {
            return fail("not a valid JSON text (${e.javaClass.simpleName}: ${e.message}); see conformance/schema.json")
        }
        val value = text.value
        if (value is Map<*, *>) {
            op = value["operation"] as? String
            source = (value["source"] as? String)?.takeIf { it.isNotBlank() }
        }
        return try {
            schema.violation(value)?.let { return fail(it) }
            @Suppress("UNCHECKED_CAST")
            val vector = value as Map<String, Any?>
            Operations.crossMemberRules(vector)
            val features = strList(vector["features"])
            val absent = strList(vector["features_absent"])
            // ADR 0034 §3: the missing `features`, in order; then ADR 0056 §2: each enabled `features_absent` as `!<name>`.
            val skip = features.filter { it !in BINDING_FEATURES } + absent.filter { it in BINDING_FEATURES }.map { "!$it" }
            if (skip.isNotEmpty()) {
                return VectorResult(file.id, source, op, Status.SKIPPED, null, "feature:${skip.joinToString(",")}")
            }
            val outcome = Operations.execute(vector, text)
            val actual = if (outcome is Outcome.Ok) Actual(true, null) else Actual(false, (outcome as Outcome.Err).code)
            val mismatch = Operations.compare(vector["expect"] as Map<*, *>, outcome)
            if (mismatch == null) VectorResult(file.id, source, op, Status.PASS, actual, null) else fail(mismatch, actual)
        } catch (e: HarnessError) {
            fail(e.message ?: "harness error")
        } catch (e: VirtualMachineError) {
            throw e
        } catch (e: Throwable) {
            fail("exception in the runner or the binding: ${e.javaClass.name}: ${e.message}")
        }
    }

    /** Strict UTF-8 (RFC 8259 §8.1): malformed input is an error, never replaced. A BOM is kept, so it fails the scan. */
    private fun decodeUtf8(bytes: ByteArray): String =
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()

    private fun strList(v: Any?): List<String> = (v as? List<*>)?.map { it as String } ?: emptyList()
}

/** The outcome of an operation's library calls. */
internal sealed class Outcome {
    class Ok(val out: Map<String, Any?>) : Outcome()

    class Err(val code: String) : Outcome()
}

enum class Status(val json: String) { PASS("pass"), FAIL("fail"), SKIPPED("skipped") }

/** The observed outcome of an executed vector (ADR 0034 §2): `ok`, and the error code when not ok. */
class Actual(val ok: Boolean, val error: String?)

/** One ADR 0034 §2 result. [reason] is the skip reason, or the failure message. */
class VectorResult(
    val id: String,
    val source: String?,
    val op: String?,
    val status: Status,
    val actual: Actual?,
    val reason: String?,
) {
    fun toJson(): String = buildString {
        append("{\"id\":").append(quote(id))
        source?.let { append(",\"source\":").append(quote(it)) }
        op?.let { append(",\"op\":").append(quote(it)) }
        append(",\"status\":").append(quote(status.json))
        actual?.let {
            append(",\"actual\":{\"ok\":").append(it.ok)
            it.error?.let { code -> append(",\"error\":").append(quote(code)) }
            append('}')
        }
        reason?.let { append(",\"reason\":").append(quote(it)) }
        append('}')
    }
}

/** The ADR 0034 §2 results file, with `vectors_digest` (ADR 0060 §1). */
class ResultsDocument(
    val runner: String,
    val polyjose: String,
    val features: List<String>,
    val errorCodes: List<String>,
    val vectorsDigest: String,
    val results: List<VectorResult>,
) {
    val passed: Int get() = results.count { it.status == Status.PASS }
    val skipped: Int get() = results.count { it.status == Status.SKIPPED }
    val failures: List<VectorResult> get() = results.filter { it.status == Status.FAIL }

    /** The document as JSON text: one result per line, as the Rust reference writes it. */
    fun toJson(): String = buildString {
        append("{\n")
        append("  \"runner\": ").append(quote(runner)).append(",\n")
        append("  \"polyjose\": ").append(quote(polyjose)).append(",\n")
        append("  \"features\": ").append(features.joinToString(",", "[", "]") { quote(it) }).append(",\n")
        append("  \"error_codes\": ").append(errorCodes.joinToString(",", "[", "]") { quote(it) }).append(",\n")
        append("  \"vectors_digest\": ").append(quote(vectorsDigest)).append(",\n")
        append("  \"results\": [\n")
        results.forEachIndexed { i, r ->
            append("    ").append(r.toJson())
            append(if (i < results.size - 1) ",\n" else "\n")
        }
        append("  ]\n}\n")
    }
}
