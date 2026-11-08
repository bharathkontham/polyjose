package dev.polyjose

import com.sun.jna.NativeLibrary
import com.sun.jna.Platform
import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail

/**
 * The JVM loader in this test JVM (feature 0008 F05; security audit M1, review S3): the module's
 * tests load the library the build produced, through the patched `findLibraryName`, from a
 * private copy whose hash the build compiled in. The forked-JVM attack cases are LoaderPocTest.
 */
class LoaderTest {
    /**
     * The loaded file is the host library the build produced (`build/jvm-natives/<prefix>/`),
     * byte for byte, at an absolute path that JNA opened, with the hash in PolyjoseNativeHashes.
     */
    @Test
    fun theTestsLoadTheLibraryTheBuildProduced() {
        version()
        val loaded = PolyjoseNativeLoader.loadedFile ?: fail("the patched findLibraryName never called the loader")
        assertTrue(loaded.isAbsolute, "not an absolute path: $loaded")
        val built = File(System.getProperty("polyjose.hostNatives"), JvmNativeLibrary.resource)
        assertTrue(built.isFile, "no library at $built")
        val hash = JvmNativeLibrary.sha256Hex(loaded.readBytes())
        assertEquals(JvmNativeLibrary.sha256Hex(built.readBytes()), hash, "the loaded library is not the one the build produced")
        assertEquals(PolyjoseNativeHashes.SHA256[JvmNativeLibrary.resource], hash, "the loaded library's hash is not the compiled-in one")
        assertEquals(
            loaded.canonicalFile,
            NativeLibrary.getInstance(loaded.path).file.canonicalFile,
            "JNA's polyjose_ffi is not the loader's file",
        )
        assertEquals(loaded.path, PolyjoseNativeLoader.libraryName("polyjose_ffi"), "a second call extracted again")
    }

    /** The private copy: a fresh `rwx------` directory and an `rw-------` file (where POSIX). */
    @Test
    fun theCopyIsPrivate() {
        version()
        val loaded = PolyjoseNativeLoader.loadedFile!!
        if ("posix" !in FileSystems.getDefault().supportedFileAttributeViews()) return
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(loaded.parentFile.toPath())))
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(loaded.toPath())))
        assertTrue(loaded.parentFile.name.startsWith("polyjose-"), "not the loader's directory: ${loaded.parentFile}")
        // A random leaf name, so dyld's DYLD_LIBRARY_PATH leaf-name lookup cannot match it.
        assertTrue(loaded.name != System.mapLibraryName("polyjose_ffi"), "the copy has the predictable name ${loaded.name}")
    }

    /**
     * The compiled classes call the patched loader: the generated file's class references
     * PolyjoseNativeLoader, and no compiled class names the override property (security audit
     * M1, I4).
     */
    @Test
    fun theCompiledClassesCallThePatchedLoader() {
        val dirs = System.getProperty("polyjose.mainClasses").split(File.pathSeparator).map(::File)
        val classes = dirs.flatMap { dir -> dir.walkTopDown().filter { it.isFile && it.extension == "class" }.toList() }
        assertTrue(classes.isNotEmpty(), "no compiled classes in $dirs")
        val generated = classes.single { it.name == "Polyjose_ffiKt.class" }
        assertTrue(generated.readBytes().latin1().contains("dev/polyjose/PolyjoseNativeLoader"), "findLibraryName does not call PolyjoseNativeLoader")
        for (c in classes) {
            val text = c.readBytes().latin1()
            assertFalse(text.contains("libraryOverride"), "$c names libraryOverride")
            assertFalse(text.contains("jna.library.path"), "$c names jna.library.path")
        }
    }

    /** The loader serves only the polyjose_ffi component, and it is not Android here. */
    @Test
    fun theLoaderServesOnlyItsComponent() {
        assertFalse(Platform.isAndroid())
        val e = runCatching { PolyjoseNativeLoader.libraryName("other") }.exceptionOrNull()
        assertTrue(e is UnsatisfiedLinkError, "an unknown component was not refused: $e")
    }

    private fun ByteArray.latin1(): String = String(this, Charsets.ISO_8859_1)
}
