package dev.polyjose

import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * The JVM smoke test of the generated Kotlin API (feature 0008 T01): the host library loads
 * through JNA from the jar's resources, and one call of each kind crosses the FFI boundary
 * (ADR 0033 §1, §3, §5). The conformance runs are T02's.
 */
class SmokeTest {
    /** `version()` is the crate version, the workspace's `[workspace.package] version` (ADR 0030 §4). */
    @Test
    fun versionIsTheWorkspaceVersion() {
        assertEquals(workspaceVersion(), version())
    }

    /**
     * `errorCodes()` is `polyjose::Error::CODES`, in order (ADR 0030 §5, ADR 0034 §8), as recorded
     * in the API inventory, which scripts/check-binding-api.sh keeps equal to the core's list.
     */
    @Test
    fun errorCodesAreTheInventoryCodes() {
        val expected = inventoryCodes()
        assertFalse(expected.isEmpty(), "no `code` lines read from the API inventory")
        assertEquals(expected, errorCodes())
    }

    /**
     * A JWK that is not JSON fails with the stable code `InvalidJson` (RFC 7517 §4: a JWK is a
     * JSON object), read through the exported `code()`, never the class name (ADR 0033 §3).
     */
    @Test
    fun invalidJsonIsReportedByCode() {
        val error = assertThrows<PolyjoseException> { jwkParse("not json") }
        assertEquals("InvalidJson", error.code())
    }

    private companion object {
        fun pathProperty(name: String): File {
            val value = System.getProperty(name)
                ?: error("system property $name is not set (platforms/android/polyjose-jvm/build.gradle.kts)")
            return File(value)
        }

        /** The `code <Code>` entries of bindings/api-inventory.txt, in file order. */
        fun inventoryCodes(): List<String> =
            pathProperty("polyjose.apiInventory").readLines()
                .map { it.trim() }
                .filter { it.startsWith("code ") }
                .map { it.removePrefix("code ").trim() }

        /** `version = "..."` in the `[workspace.package]` table of the workspace Cargo.toml. */
        fun workspaceVersion(): String {
            var inTable = false
            for (line in pathProperty("polyjose.workspaceManifest").readLines().map { it.trim() }) {
                if (line.startsWith("[")) inTable = line == "[workspace.package]"
                if (inTable) {
                    Regex("""^version\s*=\s*"([^"]+)"$""").find(line)?.let { return it.groupValues[1] }
                }
            }
            error("no version in [workspace.package] of ${System.getProperty("polyjose.workspaceManifest")}")
        }
    }
}
