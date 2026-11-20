package dev.polyjose

import com.sun.jna.Native
import com.sun.jna.Platform
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

/**
 * The security audit's M1 proof of concept, as regression tests (feature 0008 F05; audit M1 cases
 * A–G, I3, I4). Each case starts a child JVM ([LoaderProbe]) on `loaderTestJar`, the jar's own
 * classes and `<prefix>/<library>` files, with a library planted where JNA's bare-name search
 * would have found it before the jar:
 *
 * - B the working directory, C `-Djna.library.path`, D
 *   `-Duniffi.component.polyjose_ffi.libraryOverride`, E `DYLD_LIBRARY_PATH` (`LD_LIBRARY_PATH` on
 *   Linux, `PATH` on Windows), G a jar earlier on the class path carrying `<prefix>/<library>`.
 * - In each, the application still gets the genuine library: `version()` is the workspace
 *   version, the audit's forged token is rejected (`InvalidSignature`, RFC 7515 §5.2), the loaded
 *   file is the loader's private copy with the compiled-in SHA-256, and no other `polyjose_ffi`
 *   image is mapped (macOS, Linux).
 * - A tampered resource in the jar fails to load with [UnsatisfiedLinkError] naming the resource
 *   and both hashes, even with every plant in place: the loader never falls back (case T).
 *
 * The planted library is a copy of JNA's own `jnidispatch` under polyjose's file name: a real
 * shared library without polyjose's functions, so loading it would fail every case. The `control`
 * runs show, with the unpatched loader's logic, that the plants of C, D and G would have been
 * loaded; B and E depend on the OS loader and on whether the JVM honours `DYLD_*` (a hardened
 * runtime strips them), so their controls are printed, not asserted.
 */
class LoaderPocTest {
    @Test
    fun aCleanStartLoadsTheJarsLibrary(@TempDir dir: File) {
        assertGenuine(probe(genuine(), workDir = dir.sub("work")))
    }

    @Test
    fun aLibraryInTheWorkingDirectoryIsNotLoaded(@TempDir dir: File) {
        val work = dir.sub("work").also { plant(it) }
        report("B working directory", control(genuine(), workDir = work))
        assertGenuine(probe(genuine(), workDir = work), work)
    }

    @Test
    fun jnaLibraryPathIsIgnored(@TempDir dir: File) {
        val plants = dir.sub("plants").also { plant(it) }
        val props = mapOf("jna.library.path" to plants.path)
        assertPlanted(control(genuine(), dir.sub("work"), props))
        assertGenuine(probe(genuine(), dir.sub("work"), props), plants)
    }

    @Test
    fun theLibraryOverridePropertyIsIgnored(@TempDir dir: File) {
        val plants = dir.sub("plants").also { plant(it) }
        val props = mapOf("uniffi.component.polyjose_ffi.libraryOverride" to File(plants, LIBRARY).path)
        assertPlanted(control(genuine(), dir.sub("work"), props))
        assertGenuine(probe(genuine(), dir.sub("work"), props), plants)
    }

    @Test
    fun theOsLibrarySearchPathIsIgnored(@TempDir dir: File) {
        val plants = dir.sub("plants").also { plant(it) }
        val env = searchPathEnv(plants)
        report("E ${env.keys.single()}", control(genuine(), dir.sub("work"), env = env))
        assertGenuine(probe(genuine(), dir.sub("work"), env = env), plants)
    }

    @Test
    fun aShadowingJarEarlierOnTheClassPathIsNotLoaded(@TempDir dir: File) {
        val shadow = File(dir, "shadow.jar")
        ZipOutputStream(shadow.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry(RESOURCE))
            zip.write(STUB)
            zip.closeEntry()
        }
        val classpath = listOf(shadow) + genuine()
        assertPlanted(control(classpath, dir.sub("work")))
        assertGenuine(probe(classpath, dir.sub("work")), dir)
    }

    @Test
    fun aTamperedResourceFailsToLoadAndNothingElseIsTried(@TempDir dir: File) {
        val tampered = File(dir, "tampered.jar")
        var tamperedHash = ""
        ZipInputStream(GENUINE_JAR.inputStream()).use { input ->
            ZipOutputStream(tampered.outputStream()).use { output ->
                generateSequence { input.nextEntry }.forEach { entry ->
                    var bytes = input.readBytes()
                    if (entry.name == RESOURCE) {
                        bytes = bytes.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() }
                        tamperedHash = JvmNativeLibrary.sha256Hex(bytes)
                    }
                    output.putNextEntry(ZipEntry(entry.name))
                    output.write(bytes)
                    output.closeEntry()
                }
            }
        }
        assertTrue(tamperedHash.isNotEmpty(), "the jar has no $RESOURCE")
        // Every plant at once: the loader must fail, not fall back to one of them.
        val work = dir.sub("work").also { plant(it) }
        val plants = dir.sub("plants").also { plant(it) }
        val props = mapOf(
            "jna.library.path" to plants.path,
            "uniffi.component.polyjose_ffi.libraryOverride" to File(plants, LIBRARY).path,
        )
        val child = probe(listOf(tampered) + CHILD_CLASSPATH + CHILD_TEST_CLASSES, work, props, searchPathEnv(plants))
        assertEquals(3, child.exit, "a tampered jar loaded:\n${child.text}")
        assertFalse(child.text.contains("VERSION="), "version() returned:\n${child.text}")
        val errors = child.values("ERROR").joinToString("\n")
        assertTrue(errors.contains("UnsatisfiedLinkError"), "not an UnsatisfiedLinkError:\n$errors")
        for (expected in listOf(RESOURCE, Platform.RESOURCE_PREFIX, GENUINE_HASH, tamperedHash)) {
            assertTrue(errors.contains(expected), "the error does not name $expected:\n$errors")
        }
    }

    /** The child's `KEY=value` lines and its whole output. */
    private class Child(val exit: Int, val text: String) {
        fun values(key: String): List<String> = text.lines().filter { it.startsWith("$key=") }.map { it.substringAfter('=') }
        fun value(key: String): String? = values(key).singleOrNull()
    }

    private fun assertGenuine(child: Child, vararg plantDirs: File) {
        assertEquals(0, child.exit, "the child failed:\n${child.text}")
        assertEquals(WORKSPACE_VERSION, child.value("VERSION"), child.text)
        assertEquals("InvalidSignature", child.value("FORGED"), "the forged token was not rejected:\n${child.text}")
        val loaded = File(child.value("LOADED") ?: error(child.text))
        assertEquals(GENUINE_HASH, child.value("LOADED_SHA256"), "the loaded file is not the jar's library:\n${child.text}")
        assertEquals(GENUINE_HASH, child.value("COMPILED_SHA256"), "the compiled-in hash is not the jar's library's:\n${child.text}")
        assertTrue(loaded.parentFile.name.startsWith("polyjose-"), "not the loader's private copy: $loaded")
        for (d in plantDirs) {
            assertFalse(loaded.path.startsWith(d.canonicalPath), "loaded from the plant folder $d: $loaded")
        }
        if (child.value("IMAGES") == null) {
            assertEquals(listOf(loaded.path), child.values("IMAGE"), "other polyjose_ffi images are mapped:\n${child.text}")
        }
    }

    /** The unpatched logic loaded the planted library: the plant is effective. */
    private fun assertPlanted(child: Child) {
        assertEquals(0, child.exit, "the control failed:\n${child.text}")
        assertEquals("stub", child.value("CONTROL_KIND"), "the control did not load the plant, so the case proves nothing:\n${child.text}")
    }

    private fun report(case: String, child: Child) {
        val planted = child.exit == 0 && child.value("CONTROL_KIND") == "stub"
        println("LoaderPocTest control $case: the unpatched loader ${if (planted) "loads the plant" else "does not load the plant on this host"}")
    }

    private fun probe(classpath: List<File>, workDir: File, props: Map<String, String> = emptyMap(), env: Map<String, String> = emptyMap()) =
        run("probe", classpath, workDir, props, env)

    private fun control(classpath: List<File>, workDir: File, props: Map<String, String> = emptyMap(), env: Map<String, String> = emptyMap()) =
        run("control", classpath, workDir, props, env)

    private fun run(mode: String, classpath: List<File>, workDir: File, props: Map<String, String>, env: Map<String, String>): Child {
        val java = File(System.getProperty("java.home"), if (Platform.isWindows()) "bin/java.exe" else "bin/java")
        val command = listOf(java.path, "-cp", classpath.joinToString(File.pathSeparator)) +
            props.map { (k, v) -> "-D$k=$v" } + listOf(LoaderProbe::class.java.name, mode)
        val process = ProcessBuilder(command).directory(workDir).redirectErrorStream(true)
            .also { it.environment().putAll(env) }
            .start()
        val text = process.inputStream.bufferedReader().readText()
        // A hang guard, not a timing assertion.
        if (!process.waitFor(5, TimeUnit.MINUTES)) {
            process.destroyForcibly()
            error("the child JVM did not exit:\n$text")
        }
        return Child(process.exitValue(), text)
    }

    private fun File.sub(name: String): File = File(this, name).also { it.mkdirs() }

    private companion object {
        val LIBRARY: String = System.mapLibraryName("polyjose_ffi")
        val RESOURCE: String = JvmNativeLibrary.resource

        fun paths(property: String): List<File> =
            (System.getProperty(property) ?: error("system property $property is not set (polyjose-jvm/build.gradle.kts)"))
                .split(File.pathSeparator).filter { it.isNotEmpty() }.map(::File)

        val GENUINE_JAR: File = paths("polyjose.loaderTestJar").single()
        val CHILD_CLASSPATH: List<File> = paths("polyjose.childClasspath")
        val CHILD_TEST_CLASSES: List<File> = paths("polyjose.childTestClasses")

        fun genuine(): List<File> = listOf(GENUINE_JAR) + CHILD_CLASSPATH + CHILD_TEST_CLASSES

        val GENUINE_HASH: String = ZipFile(GENUINE_JAR).use { zip ->
            val entry = zip.getEntry(RESOURCE) ?: error("$GENUINE_JAR has no $RESOURCE")
            JvmNativeLibrary.sha256Hex(zip.getInputStream(entry).use { it.readBytes() })
        }

        /** JNA's own dispatch library for this platform: a valid shared library that is not polyjose. */
        val STUB: ByteArray = run {
            val name = when {
                Platform.isMac() -> "libjnidispatch.jnilib"
                Platform.isWindows() -> "jnidispatch.dll"
                else -> "libjnidispatch.so"
            }
            val path = "com/sun/jna/${Platform.RESOURCE_PREFIX}/$name"
            (Native::class.java.classLoader.getResourceAsStream(path) ?: error("no $path in JNA")).use { it.readBytes() }
        }

        fun plant(dir: File) = File(dir, LIBRARY).writeBytes(STUB)

        /** The OS library search path variable, with the plant folder first. */
        fun searchPathEnv(dir: File): Map<String, String> = when {
            Platform.isMac() -> mapOf("DYLD_LIBRARY_PATH" to dir.path)
            Platform.isWindows() -> mapOf("PATH" to dir.path + File.pathSeparator + System.getenv("PATH").orEmpty())
            else -> mapOf("LD_LIBRARY_PATH" to dir.path)
        }

        /** `version = "..."` in the `[workspace.package]` table of the workspace Cargo.toml. */
        val WORKSPACE_VERSION: String = run {
            var inTable = false
            for (line in paths("polyjose.workspaceManifest").single().readLines().map { it.trim() }) {
                if (line.startsWith("[")) inTable = line == "[workspace.package]"
                if (inTable) Regex("""^version\s*=\s*"([^"]+)"$""").find(line)?.let { return@run it.groupValues[1] }
            }
            error("no [workspace.package] version")
        }
    }
}
