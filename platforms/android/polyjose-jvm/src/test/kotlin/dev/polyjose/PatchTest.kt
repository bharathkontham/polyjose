package dev.polyjose

import java.io.File
import java.lang.reflect.InvocationTargetException
import java.net.URLClassLoader
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail

/**
 * The build's patch of the generated Kotlin, `UniffiKotlinPatch` in build-logic (feature 0008 F05;
 * security audit M1, L1; ADR 0065), loaded from build-logic's jar on its own and fed the
 * generator's unpatched output (`build/generated/uniffi/raw`).
 *
 * - It is deterministic, and its output is exactly the file the module compiled.
 * - It fails closed: a missing, doubled or changed loader hook, an extra load path, or a change
 *   to the fields records.rs documents as secret (ADR 0030 §7) throws, so the build stops.
 * - Its redaction list is exactly ADR 0065 decision 1's.
 */
class PatchTest {
    @Test
    fun thePatchIsDeterministicAndIsWhatTheModuleCompiled() {
        val raw = raw()
        val once = patch(raw)
        assertEquals(once, patch(raw), "two runs of the patch differ")
        assertEquals(file("polyjose.uniffiPatched").readText(), once, "the compiled sources are not the patch of the raw ones")
        assertTrue(once.contains("PolyjoseNativeLoader.libraryName(componentName)"), "the loader hook is missing")
        assertTrue(!once.contains("libraryOverride"), "the libraryOverride property survived the patch")
    }

    /** ADR 0065 decision 1, with ADR 0030 §7's other record fields: there are none (records.rs). */
    @Test
    fun theRedactionListIsAdr0065s() {
        assertEquals(ADR_0065, redactedFields(), "UniffiKotlinPatch's records and fields")
        val overridden = Regex("""(?m)^data class (\w+) \(""").findAll(file("polyjose.uniffiPatched").readText())
            .map { it.groupValues[1] }
            .filter { record -> recordBody(file("polyjose.uniffiPatched").readText(), record).contains("override fun toString(): String =") }
            .toSet()
        assertEquals(ADR_0065.keys, overridden, "the records whose toString() the patch overrides")
    }

    @Test
    fun aMissingLoaderHookFailsTheBuild() {
        val raw = raw()
        assertRejected("findLibraryName exactly once") { raw.replace("return \"polyjose_ffi\"\n}", "return \"polyjose_ffi\" \n}") }
        assertRejected("findLibraryName exactly once") { raw.replace(LOADER_FIRST_LINE, "@Synchronized\nprivate fun findLibName(componentName: String): String {") }
    }

    @Test
    fun aDoubledLoaderHookFailsTheBuild() {
        val raw = raw()
        val start = raw.indexOf(LOADER_FIRST_LINE)
        val loader = raw.substring(start, raw.indexOf("\n}\n", start) + 3)
        assertTrue(loader.contains("return \"polyjose_ffi\""), "not the whole loader: $loader")
        assertRejected("findLibraryName exactly once") { raw + "\n" + loader }
    }

    @Test
    fun anotherLoadPathFailsTheBuild() {
        val raw = raw()
        assertRejected("Native.register calls") { "$raw\nfun x() { Native.register(Any::class.java, \"polyjose_ffi\") }\n" }
        assertRejected("System.loadLibrary") { "$raw\nfun x() { System.loadLibrary(\"polyjose_ffi\") }\n" }
        assertRejected("NativeLibrary.getInstance(") { "$raw\nfun x() = com.sun.jna.NativeLibrary.getInstance(\"polyjose_ffi\")\n" }
        assertRejected("findLibraryName to be declared once") { "$raw\nfun x() = findLibraryName(\"polyjose_ffi\")\n" }
    }

    /** A field records.rs calls secret must be redacted: the build stops until ADR 0065's list says so. */
    @Test
    fun aNewSecretFieldFailsTheBuild() {
        val raw = raw()
        val withSecretKid = raw.replaceFirst(
            "data class JwkSelector (\n",
            "data class JwkSelector (\n    /**\n     * A new field. Secret (ADR 0030 §7).\n     */\n    var `token`: kotlin.String\n    , \n",
        )
        assertRejected("documented as secret") { withSecretKid }
    }

    @Test
    fun aSecretFieldNoLongerDocumentedSecretFailsTheBuild() {
        assertRejected("documented as secret") { raw().replace("Treated as secret (ADR 0049 §4).", "(ADR 0049 §4).") }
    }

    @Test
    fun aMissingOrAlreadyPrintedRecordFailsTheBuild() {
        val raw = raw()
        assertRejected("documented as secret") { raw.replace("data class JwsSigner (", "data class JwsSigner2 (") }
        val start = raw.indexOf("data class JwsVerified (")
        val body = raw.indexOf("\n){\n", start) + 4
        assertRejected("already overrides toString") {
            raw.substring(0, body) + "    override fun toString(): String = \"x\"\n" + raw.substring(body)
        }
    }

    private fun assertRejected(expected: String, mutate: () -> String) {
        try {
            patch(mutate())
        } catch (e: IllegalStateException) {
            assertTrue(e.message.orEmpty().contains(expected), "expected a failure about `$expected`, got: ${e.message}")
            return
        }
        fail("the patch accepted input it must reject (`$expected`)")
    }

    private companion object {
        val ADR_0065: Map<String, List<String>> = mapOf(
            "JweDecrypted" to listOf("plaintext", "aad"),
            "JweEncryptOptions" to listOf("aad"),
            "JweRecipient" to listOf("key"),
            "JwsSigner" to listOf("key"),
            "JwsVerified" to listOf("payload"),
            "JwsVerifyOptions" to listOf("detachedPayload"),
        )
        const val LOADER_FIRST_LINE = "@Synchronized\nprivate fun findLibraryName(componentName: String): String {"

        val patchClass: Class<*> by lazy {
            val jar = file("polyjose.buildLogic")
            // No parent but the platform loader: the class must load without Gradle's API.
            URLClassLoader(arrayOf(jar.toURI().toURL()), ClassLoader.getPlatformClassLoader())
                .loadClass("dev.polyjose.gradle.UniffiKotlinPatch")
        }

        fun file(property: String): File =
            File(System.getProperty(property) ?: error("system property $property is not set (polyjose-jvm/build.gradle.kts)"))

        fun raw(): String = file("polyjose.uniffiRaw").readText()

        fun patch(source: String): String = try {
            patchClass.getMethod("patch", String::class.java).invoke(null, source) as String
        } catch (e: InvocationTargetException) {
            throw e.targetException
        }

        @Suppress("UNCHECKED_CAST")
        fun redactedFields(): Map<String, List<String>> =
            patchClass.getMethod("redactedFields").invoke(null) as Map<String, List<String>>

        /** From `data class <record> (` to the end of its body. */
        fun recordBody(source: String, record: String): String {
            val start = source.indexOf("data class $record (")
            return source.substring(start, source.indexOf("\n}\n", source.indexOf("\n){\n", start)))
        }
    }
}
