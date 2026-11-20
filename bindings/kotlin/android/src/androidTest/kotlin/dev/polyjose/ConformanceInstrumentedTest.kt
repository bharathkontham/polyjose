package dev.polyjose

import android.content.res.AssetManager
import android.os.Build
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import dev.polyjose.conformance.ResultsDocument
import dev.polyjose.conformance.Runner
import dev.polyjose.conformance.VectorBytes
import dev.polyjose.conformance.VectorInput
import dev.polyjose.conformance.VectorUnreadable
import dev.polyjose.conformance.VectorsDigest
import java.io.File
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Android host of the shared Kotlin conformance runner (feature 0008 T03; ADR 0033 §5,
 * ADR 0034, ADR 0060): the generated Kotlin API, `libpolyjose_ffi.so` through JNA, on the
 * `polyjose-api36` emulator. AndroidJUnitRunner runs it as a plain JUnit 4 class.
 *
 * The test APK's assets hold everything under `conformance/vectors/`, and `conformance/schema.json`,
 * copied byte for byte from the checkout (`polyjose/build.gradle.kts`), so the asset paths under
 * `conformance/vectors` are the vector ids of ADR 0034 §1 / ADR 0045 §4 and the schema is never
 * listed as a vector.
 */
class ConformanceInstrumentedTest {
    /**
     * Runs every vector file through the generated Kotlin API on the device and writes the
     * ADR 0034 §2 results file, with the `vectors_digest` of the bundled bytes it parsed
     * (ADR 0060 §2, §5: `java.security.MessageDigest`), to the test app's files dir and to AGP's
     * additional test output dir, from which `scripts/run-instrumented.sh` takes it to
     * `target/conformance/android-emulator.json`. Any `fail` entry fails the test, after the file
     * is written; a run that cannot complete leaves no file (ADR 0060 §3).
     */
    @Test
    fun everyVectorRunsOnTheEmulator() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.context
        val outputs = listOfNotNull(
            File(context.filesDir, RESULTS_FILE),
            InstrumentationRegistry.getArguments().getString(ADDITIONAL_OUTPUT_ARG)?.let { File(it, RESULTS_FILE) },
        )
        outputs.forEach { it.delete() }
        val assets = context.assets
        val schema = assets.open(SCHEMA).use { String(it.readBytes(), Charsets.UTF_8) }

        val document = Runner.run("android-emulator", loadVectorAssets(assets, VECTORS), schema)

        val json = document.toJson().toByteArray(Charsets.UTF_8)
        for (file in outputs) {
            file.parentFile?.mkdirs()
            file.writeBytes(json)
        }
        Log.i(TAG, summary(document) + "; wrote " + outputs.joinToString(", "))
        val failures = document.failures
        assertTrue(
            "${failures.size} vector(s) failed on the emulator:\n" + failures.joinToString("\n") { "  FAIL ${it.id}: ${it.reason}" },
            failures.isEmpty(),
        )
        assertNotEquals("the digest of no input (ADR 0060 §3)", VectorsDigest.EMPTY, document.vectorsDigest)
    }

    /**
     * The asset listing finds the vectors with the ids the JVM gives them (`/` separators, `#0`,
     * ADR 0045 §4), never the schema or a non-`*.json` file, and reads each file's bytes (ADR 0060 §2).
     */
    @Test
    fun theAssetListingYieldsVectorIdsOnly() {
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        val inputs = loadVectorAssets(assets, VECTORS)
        assertTrue("no vector assets found under $VECTORS", inputs.isNotEmpty())
        assertTrue(inputs.all { it is VectorBytes })
        assertTrue(inputs.all { it.path.endsWith(".json") && !it.path.startsWith("/") && !it.path.startsWith(VECTORS) })
        assertTrue("the schema is not a vector", inputs.none { it.path.endsWith("schema.json") })
        assertTrue("a nested vector id", inputs.any { it.path.contains('/') })
        assertEquals("ids are unique", inputs.size, inputs.map { it.id }.toSet().size)
        // The schema is an asset next to the vectors, not one of them.
        assertTrue(assets.open(SCHEMA).use { it.read() } >= 0)
    }

    /** ADR 0060 §4, the worked example, through the device's `MessageDigest` (ADR 0060 §5). */
    @Test
    fun vectorsDigestReproducesTheAdr0060WorkedExampleOnTheDevice() {
        val files = listOf(
            VectorBytes("a.json", hex("7b7d")),
            VectorBytes("jws/b.json", hex("7b7d0a")),
            VectorBytes("jws-x/c.json", hex("efbbbf7b7d")),
        )
        assertEquals("9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1", VectorsDigest.of(files))
    }

    private fun summary(document: ResultsDocument): String =
        "conformance (android-emulator, ${Build.SUPPORTED_ABIS.firstOrNull()}, API ${Build.VERSION.SDK_INT}): " +
            "${document.passed} passed, ${document.failures.size} failed, ${document.skipped} skipped of " +
            "${document.results.size}; vectors_digest ${document.vectorsDigest}"

    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private companion object {
        const val TAG = "polyjose-conformance"
        const val VECTORS = "conformance/vectors"
        const val SCHEMA = "conformance/schema.json"
        const val RESULTS_FILE = "android-emulator.json"

        /** The instrumentation argument AGP's connected test sets to the device dir it pulls afterwards. */
        const val ADDITIONAL_OUTPUT_ARG = "additionalTestOutputDir"
    }
}

/**
 * Every vector file under the asset folder [root] (conformance/README.md "Rules for every
 * runner"): the `*.json` assets at any depth, each read once as raw bytes (ADR 0060 §2), with its
 * path relative to [root] and `/` separators, as the JVM host gives it. An asset that cannot be
 * read is a [VectorUnreadable] (a `fail`, no digest line, ADR 0034 §3). Other files (`README.md`,
 * `.jwk` keys) are not vectors.
 *
 * `AssetManager.list` returns a folder's entries and nothing for a file, so an entry with entries
 * of its own is a folder. The test APK has no symbolic links (aapt2 packages regular files only).
 */
internal fun loadVectorAssets(assets: AssetManager, root: String): List<VectorInput> {
    val found = mutableListOf<VectorInput>()
    fun walk(dir: String, relative: String) {
        val names = assets.list(dir) ?: throw IOException("cannot list the asset folder $dir")
        for (name in names.sorted()) {
            val path = "$dir/$name"
            val rel = if (relative.isEmpty()) name else "$relative/$name"
            val children = assets.list(path)
            when {
                !children.isNullOrEmpty() -> walk(path, rel)
                name.endsWith(".json") -> found += try {
                    VectorBytes(rel, assets.open(path, AssetManager.ACCESS_STREAMING).use { it.readBytes() })
                } catch (e: IOException) {
                    VectorUnreadable(rel, "cannot read: ${e.javaClass.simpleName}")
                }
            }
        }
    }
    walk(root, "")
    return found
}
