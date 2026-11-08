package dev.polyjose

import com.sun.jna.Platform
import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest

/**
 * Where the generated code loads `polyjose_ffi` from: the build patches UniFFI's
 * `findLibraryName` to call [libraryName] (feature 0008 F05, `UniffiKotlinPatch`; hand-written
 * per ADR 0030 §1). It closes security audit M1, I3 and I4.
 *
 * - **Desktop JVM:** the library is the one this artifact packs as the class-path resource
 *   `/<Platform.RESOURCE_PREFIX>/<System.mapLibraryName("polyjose_ffi")>`, and only if its
 *   SHA-256 equals the hash the build compiled into [PolyjoseNativeHashes] from the exact files
 *   the jar packs (ADR 0033 §3a, §4). The resource is read through this class's own class loader
 *   (not the thread's context loader); when several candidates exist (a jar earlier on the class
 *   path shadowing it), only the one with that hash is used. It is copied into a fresh private
 *   directory (`rwx------` where the file system is POSIX), hashed again from disk, and its
 *   **absolute path** is returned, so JNA opens exactly that file and searches no folder.
 *   - `jna.library.path`, `uniffi.component.polyjose_ffi.libraryOverride`, the working directory,
 *     `DYLD_*`/`LD_LIBRARY_PATH`/`PATH` and the system library folders are never consulted.
 *   - A mismatch, or no matching resource, throws [UnsatisfiedLinkError] naming the resource and
 *     both hashes; it never falls back to the bare name.
 *   - The base directory is `java.io.tmpdir` (set `-Djava.io.tmpdir` where that is mounted
 *     `noexec`). The copy is deleted when the JVM exits (on Windows a loaded DLL stays behind,
 *     as with JNA's own extraction).
 * - **Android:** the bare name `polyjose_ffi`, which JNA opens from the APK's `lib/<abi>/` in the
 *   app's linker namespace (audit I2). No property is read there either.
 */
internal object PolyjoseNativeLoader {
    /** The UniFFI component, and the bare library name on Android. */
    const val LIBRARY: String = "polyjose_ffi"

    @Volatile
    private var loaded: File? = null

    /**
     * The name or path JNA's `Native.register` gets for [componentName]; called by the patched
     * `findLibraryName`, once per generated library object, under its `@Synchronized` lock.
     */
    @Synchronized
    fun libraryName(componentName: String): String {
        if (componentName != LIBRARY) throw UnsatisfiedLinkError("polyjose: unknown native component $componentName")
        if (Platform.isAndroid()) return LIBRARY
        loaded?.let { return it.absolutePath }
        val file = JvmNativeLibrary.extract()
        loaded = file
        return file.absolutePath
    }

    /** The file the JVM loaded, once [libraryName] has run there (null on Android or before). */
    val loadedFile: File?
        get() = loaded
}

/**
 * The JVM side of [PolyjoseNativeLoader]: never initialised on Android, so its `java.nio.file`
 * calls (API 26) never run on the AAR's minSdk 23.
 */
@Suppress("NewApi")
internal object JvmNativeLibrary {
    /** `<Platform.RESOURCE_PREFIX>/<mapped name>`, the jar's resource path for this platform. */
    val resource: String
        get() = "${Platform.RESOURCE_PREFIX}/${System.mapLibraryName(PolyjoseNativeLoader.LIBRARY)}"

    fun extract(): File {
        val resource = resource
        val expected = PolyjoseNativeHashes.SHA256[resource]
            ?: throw UnsatisfiedLinkError(
                "polyjose-jvm: this jar carries no native library for ${Platform.RESOURCE_PREFIX} " +
                    "(it carries ${PolyjoseNativeHashes.SHA256.keys.sorted()}); refusing to search for one",
            )
        val classLoader = PolyjoseNativeLoader::class.java.classLoader
            ?: throw UnsatisfiedLinkError("polyjose-jvm: no class loader to read $resource from")
        val candidates = classLoader.getResources(resource).toList()
        if (candidates.isEmpty()) {
            throw UnsatisfiedLinkError("polyjose-jvm: no $resource on the class path (expected SHA-256 $expected)")
        }
        val found = ArrayList<String>()
        for (url in candidates) {
            val bytes = url.openStream().use { it.readBytes() }
            val actual = sha256Hex(bytes)
            if (actual == expected) return write(bytes, expected)
            found += actual
        }
        throw UnsatisfiedLinkError(
            "polyjose-jvm: $resource has SHA-256 ${found.joinToString(", ")}, but this jar was built with $expected; " +
                "refusing to load it (security audit M1)",
        )
    }

    private fun write(bytes: ByteArray, expected: String): File {
        val posix = "posix" in FileSystems.getDefault().supportedFileAttributeViews()
        val dir: Path = if (posix) {
            Files.createTempDirectory("polyjose-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        } else {
            Files.createTempDirectory("polyjose-")
        }
        val path = dir.resolve(System.mapLibraryName(PolyjoseNativeLoader.LIBRARY))
        // Registered before the file: deleteOnExit deletes in reverse order, the file first.
        dir.toFile().deleteOnExit()
        path.toFile().deleteOnExit()
        if (posix) {
            Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        } else {
            Files.createFile(path)
        }
        Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING).use { it.write(bytes) }
        val onDisk = sha256Hex(Files.readAllBytes(path))
        if (onDisk != expected) {
            Files.deleteIfExists(path)
            throw UnsatisfiedLinkError("polyjose-jvm: the copy at $path has SHA-256 $onDisk, expected $expected; refusing to load it")
        }
        return path.toFile().absoluteFile
    }

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
