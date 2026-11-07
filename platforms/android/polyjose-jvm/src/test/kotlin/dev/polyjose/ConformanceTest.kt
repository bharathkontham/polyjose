package dev.polyjose

import dev.polyjose.conformance.Runner
import dev.polyjose.conformance.VectorBytes
import dev.polyjose.conformance.VectorInput
import dev.polyjose.conformance.VectorUnreadable
import dev.polyjose.conformance.VectorsDigest
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

/**
 * The JVM host of the shared Kotlin conformance runner (feature 0008 T02; ADR 0033 §5, ADR 0034,
 * ADR 0060). The runner itself is in `shared-test/kotlin` and uses no JVM-only API; this file does
 * the file system work for the JVM.
 */
class ConformanceTest {
    /**
     * Runs every vector file under `polyjose.vectors` through the generated Kotlin API and writes
     * the ADR 0034 §2 results file (with the ADR 0060 digest) to `polyjose.conformanceResults`
     * (`target/conformance/jvm.json`), which scripts/conformance-parity.sh compares with
     * `rust-core.json`. Any `fail` entry fails the test, after the file is written. A stale file is
     * removed first, so a run that cannot complete (no vectors, an unusable schema) leaves none.
     */
    @Test
    fun everyVectorRunsOnTheJvm() {
        val results = pathProperty("polyjose.conformanceResults")
        Files.deleteIfExists(results)
        val vectors = pathProperty("polyjose.vectors")
        val schema = String(Files.readAllBytes(vectors.resolveSibling("schema.json")), Charsets.UTF_8)

        val document = Runner.run("jvm", loadVectorFiles(vectors), schema)

        Files.createDirectories(results.parent)
        Files.write(results, document.toJson().toByteArray(Charsets.UTF_8))
        val failures = document.failures
        println(
            "conformance (jvm): ${document.passed} passed, ${failures.size} failed, ${document.skipped} skipped " +
                "of ${document.results.size}; vectors_digest ${document.vectorsDigest}; wrote $results",
        )
        assertTrue(failures.isEmpty()) {
            "${failures.size} vector(s) failed on the JVM:\n" + failures.joinToString("\n") { "  FAIL ${it.id}: ${it.reason}" }
        }
        assertFalse(document.vectorsDigest == VectorsDigest.EMPTY, "the digest of no input (ADR 0060 §3)")
    }

    /**
     * ADR 0060 §4, the worked example every implementation checks: three vector files, one
     * `README.md` that is not a vector, sorted by UTF-8 bytes (`-` before `/`), and the digest.
     */
    @Test
    fun vectorsDigestReproducesTheAdr0060WorkedExample(@TempDir dir: Path) {
        write(dir, "a.json", "7b7d")
        write(dir, "jws/b.json", "7b7d0a")
        write(dir, "jws-x/c.json", "efbbbf7b7d")
        write(dir, "README.md", "6e6f746573")

        val inputs = loadVectorFiles(dir)
        assertEquals(listOf("a.json", "jws-x/c.json", "jws/b.json"), inputs.map { it.path }.sorted())
        val files = inputs.filterIsInstance<VectorBytes>()
        assertEquals(
            listOf(
                "a.json#0\t44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\n",
                "jws-x/c.json#0\taa25e978046d680ef8740d837e6de5bc1e2a2dc6089dbda1012544b538d53f65\n",
                "jws/b.json#0\tca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356\n",
            ),
            VectorsDigest.lines(files).map { String(it, Charsets.UTF_8) },
        )
        assertEquals("9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1", VectorsDigest.of(files))
    }

    private fun pathProperty(name: String): Path = Paths.get(
        System.getProperty(name) ?: error("system property $name is not set (platforms/android/polyjose-jvm/build.gradle.kts)"),
    )

    private fun write(dir: Path, path: String, hex: String) {
        val file = dir.resolve(path)
        Files.createDirectories(file.parent)
        Files.write(file, hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
    }
}

/**
 * Every vector file under [root] (conformance/README.md "Rules for every runner"): the regular
 * `*.json` files at any depth, each read once as raw bytes (ADR 0060 §2), with its path relative to
 * [root] and `/` separators. A symbolic link (whatever its name) or an unreadable file is a
 * [VectorUnreadable], which the runner reports as a `fail` without a digest line (ADR 0034 §3,
 * ADR 0060 §2). Other files (`README.md`, `NOTICE.md`, `.jwk` keys, `generate.mjs`) are not
 * vectors. Links are never followed.
 */
internal fun loadVectorFiles(root: Path): List<VectorInput> {
    val found = mutableListOf<VectorInput>()
    fun relative(p: Path): String = root.relativize(p).joinToString("/") { it.toString() }
    fun walk(dir: Path) {
        val entries = Files.newDirectoryStream(dir).use { stream -> stream.sortedBy { it.fileName.toString() } }
        for (entry in entries) {
            when {
                Files.isSymbolicLink(entry) ->
                    found += VectorUnreadable(relative(entry), "a symbolic link; vector files must be regular files (ADR 0060 §2)")
                Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS) -> walk(entry)
                Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS) && entry.fileName.toString().endsWith(".json") ->
                    found += try {
                        VectorBytes(relative(entry), Files.readAllBytes(entry))
                    } catch (e: IOException) {
                        VectorUnreadable(relative(entry), "cannot read: ${e.javaClass.simpleName}")
                    }
            }
        }
    }
    walk(root)
    return found
}
