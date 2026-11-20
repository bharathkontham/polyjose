package dev.polyjose

import com.sun.jna.NativeLibrary
import com.sun.jna.Platform
import java.io.File
import kotlin.system.exitProcess

/**
 * The child JVM of LoaderPocTest (feature 0008 F05; security audit M1 cases A–G): one process per
 * case, started on the built jar's classes. It prints `KEY=value` lines and exits 0, or prints
 * `ERROR=` lines (the cause chain) and exits 3. It uses only the jar's classes, JNA and the
 * Kotlin standard library, the child's whole class path.
 *
 * - `probe`: what an application does. It calls `version()` and verifies the audit's forged
 *   HS256 token (RFC 7515 §5.2: a wrong MAC is rejected), then reports the file the loader
 *   returned, its SHA-256, the compiled-in one and every mapped image whose name contains
 *   `polyjose_ffi` (macOS through dyld, Linux through /proc/self/maps).
 * - `control`: what the generated code did before the patch, the `libraryOverride` property else
 *   the bare name through JNA (audit M1 description), so the parent can show each planted library
 *   would have won. It only opens the library and looks up two symbols; it calls nothing.
 */
object LoaderProbe {
    /** The audit's forged token: `{"alg":"HS256"}`, `{"admin":true}` and a 3-byte "MAC". */
    const val FORGED = "eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZX0.AAAA"

    /** RFC 7515 Appendix A.1's HMAC key. */
    private const val KEY =
        """{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"""

    @JvmStatic
    fun main(args: Array<String>) {
        try {
            when (args.singleOrNull()) {
                "probe" -> probe()
                "control" -> control()
                else -> throw IllegalArgumentException("usage: LoaderProbe probe|control")
            }
        } catch (t: Throwable) {
            var c: Throwable? = t
            while (c != null) {
                println("ERROR=${c.javaClass.name}: ${c.message}")
                c = c.cause
            }
            System.out.flush()
            exitProcess(3)
        }
        System.out.flush()
        exitProcess(0)
    }

    private fun probe() {
        println("VERSION=${version()}")
        val rejected = try {
            jwsVerifyCompact(FORGED, KEY, JwsVerifyOptions(allowedAlgs = listOf("HS256")))
            "accepted"
        } catch (e: PolyjoseException) {
            e.code()
        }
        println("FORGED=$rejected")
        val loaded = PolyjoseNativeLoader.loadedFile ?: error("the loader never ran")
        println("LOADED=${loaded.canonicalPath}")
        println("LOADED_SHA256=${JvmNativeLibrary.sha256Hex(loaded.readBytes())}")
        println("COMPILED_SHA256=${PolyjoseNativeHashes.SHA256[JvmNativeLibrary.resource]}")
        images()?.forEach { println("IMAGE=$it") } ?: println("IMAGES=unsupported")
    }

    private fun control() {
        // The generated findLibraryName before the patch (UniffiKotlinPatch.LOADER_ORIGINAL).
        val name = System.getProperty("uniffi.component.polyjose_ffi.libraryOverride") ?: "polyjose_ffi"
        val library = NativeLibrary.getInstance(name)
        // What JNA opened, by its exports: polyjose's contract function, or JNI_OnLoad of the
        // planted jnidispatch copy (JNA may already have deleted a file it extracted).
        fun has(symbol: String) = runCatching { library.getFunction(symbol) }.isSuccess
        val kind = when {
            has("ffi_polyjose_ffi_uniffi_contract_version") -> "polyjose"
            has("JNI_OnLoad") -> "stub"
            else -> "other"
        }
        println("CONTROL_KIND=$kind")
        println("CONTROL_FILE=${library.file?.path}")
    }

    /** The canonical paths of the mapped images named `*polyjose_ffi*`, or null where unsupported. */
    private fun images(): List<String>? {
        val all: List<String> = when {
            Platform.isMac() -> {
                val process = NativeLibrary.getProcess()
                val count = process.getFunction("_dyld_image_count").invokeInt(arrayOf())
                val name = process.getFunction("_dyld_get_image_name")
                (0 until count).mapNotNull { name.invokeString(arrayOf(it), false) }
            }
            Platform.isLinux() -> File("/proc/self/maps").readLines().mapNotNull { line ->
                line.indexOf('/').takeIf { it >= 0 }?.let { line.substring(it).removeSuffix(" (deleted)") }
            }
            else -> return null
        }
        return all.filter { File(it).name.contains("polyjose_ffi") }.map { File(it).canonicalPath }.distinct()
    }
}
