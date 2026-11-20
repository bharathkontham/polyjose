// `:polyjose-jvm`, the desktop JVM jar dev.polyjose:polyjose-jvm (ADR 0011, ADR 0033 §1, §4): the
// UniFFI-generated Kotlin (shared with `:polyjose`) plus the host libraries as JNA resources.

import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import com.vanniktech.maven.publish.SourcesJar
import dev.polyjose.gradle.NativeHashes
import dev.polyjose.gradle.PackagingPlugin
import dev.polyjose.gradle.ThirdPartyNotices
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    // Group, workspace version, thirdPartyNotices and the POM (build-logic).
    id("polyjose.packaging")
    // vanniktech 0.37.0's base plugin; see polyjose/build.gradle.kts.
    id("com.vanniktech.maven.publish.base")
}

/** The polyjose repository root (the cargo workspace). */
val repoRoot: File = rootDir.resolve("../..").canonicalFile

/** The root project's build directory, where its Rust tasks write (root build.gradle.kts). */
val sharedBuild: Directory = isolated.rootProject.projectDirectory.dir("build")

/**
 * The four host platforms of the release jar: JNA resource prefix to Rust target triple
 * (ADR 0033 §3a, §4; ADR 0073 §2). macOS is Apple silicon only: no x86_64 macOS library is built
 * or packed, and a `polyjose.jvmNativesDir` folder for any prefix not listed here is refused below.
 */
val jnaPlatforms: Map<String, String> = sortedMapOf(
    "darwin-aarch64" to "aarch64-apple-darwin",
    "linux-aarch64" to "aarch64-unknown-linux-gnu",
    "linux-x86-64" to "x86_64-unknown-linux-gnu",
    "win32-x86-64" to "x86_64-pc-windows-msvc",
)

/** The library file name cargo gives polyjose-ffi for a JNA prefix. */
fun libraryName(prefix: String): String = when {
    prefix.startsWith("darwin-") -> "libpolyjose_ffi.dylib"
    prefix.startsWith("win32-") -> "polyjose_ffi.dll"
    else -> "libpolyjose_ffi.so"
}

val osName: String = System.getProperty("os.name").lowercase()
val osArch: String = System.getProperty("os.arch").lowercase()

/**
 * This host's JNA prefix (the root project's assembleJvmNatives copies its library), or null.
 * Every platform of the jar builds on its own native host; nothing is cross-built (ADR 0073 §2).
 */
val hostPrefix: String? = run {
    val os = when {
        osName.startsWith("mac") -> "darwin"
        osName.startsWith("windows") -> "win32"
        osName.startsWith("linux") -> "linux"
        else -> null
    }
    val arch = when (osArch) {
        "aarch64", "arm64" -> "aarch64"
        "x86_64", "amd64" -> "x86-64"
        else -> null
    }
    "$os-$arch".takeIf { os != null && arch != null && it in jnaPlatforms }
}

/**
 * Libraries built elsewhere (the CI host-natives matrix, feature 0008 T05): `-Ppolyjose.jvmNativesDir=<dir>`
 * with one `<jna-prefix>/<library>` folder per platform. A platform that this host also builds is
 * an error (the jar would carry two libraries for it).
 */
val extraNativesDir: File? = providers.gradleProperty("polyjose.jvmNativesDir").orNull?.let { file(it) }
val extraPrefixes: List<String> = extraNativesDir?.let { dir ->
    if (!dir.isDirectory) throw GradleException("polyjose.jvmNativesDir: $dir is not a directory")
    dir.listFiles().orEmpty().filter { it.isDirectory }.map { it.name }.sorted().onEach { prefix ->
        if (prefix !in jnaPlatforms) throw GradleException("polyjose.jvmNativesDir: $prefix is not a JNA prefix of ${jnaPlatforms.keys}")
        if (!dir.resolve("$prefix/${libraryName(prefix)}").isFile) {
            throw GradleException("polyjose.jvmNativesDir: no $prefix/${libraryName(prefix)} in $dir")
        }
    }
}.orEmpty()

/** Every platform the jar carries, sorted: the Polyjose-Native-Platforms manifest attribute. */
val jarPlatforms: List<String> = run {
    val all = listOfNotNull(hostPrefix) + extraPrefixes
    val twice = all.groupBy { it }.filterValues { it.size > 1 }.keys
    if (twice.isNotEmpty()) throw GradleException("polyjose.jvmNativesDir: $twice are built on this host as well")
    all.sorted()
}

/** The jar's native libraries in JNA's layout, `build/jar-natives/<prefix>/<library>`. */
val assembleJarNatives = tasks.register<Sync>("assembleJarNatives") {
    description = "Lays out every host library the jar carries under its JNA prefix (ADR 0033 §4)."
    duplicatesStrategy = DuplicatesStrategy.FAIL
    from(files(sharedBuild.dir("jvm-natives")).builtBy(":assembleJvmNatives"))
    extraPrefixes.forEach { prefix -> from(extraNativesDir!!.resolve(prefix)) { into(prefix) } }
    into(layout.buildDirectory.dir("jar-natives"))
}

// dev.polyjose.PolyjoseNativeHashes: the SHA-256 of each library in build/jar-natives, the exact
// files the jar packs, compiled into the jar's classes; PolyjoseNativeLoader loads a library only
// when its hash matches (feature 0008 F05, security audit M1). So the classes, and the tests that
// run them, depend on every library the jar carries.
val nativeHashes = tasks.register<NativeHashes>("nativeHashes") {
    description = "Generates PolyjoseNativeHashes from the libraries the jar packs (feature 0008 F05)."
    natives.from(assembleJarNatives)
    outputDir = layout.buildDirectory.dir("generated/polyjose/native-hashes")
}

// META-INF/polyjose/THIRD-PARTY-NOTICES.txt (ADR 0020 §4, ADR 0033 §4): one file over the union of
// the crate trees of every platform in the jar (header `Targets:`; 75 crates for all four; feature
// 0008 F01). The task fails closed, naming them, if the header does not name exactly the jar's
// targets, a platform's library compiles a crate the file does not list, or the file lists a crate
// no platform compiles (ThirdPartyNotices).
val thirdPartyNotices = tasks.named<ThirdPartyNotices>("thirdPartyNotices") {
    hostPrefix?.let { primaryTarget = jnaPlatforms.getValue(it) }
    targets.addAll(jarPlatforms.map { jnaPlatforms.getValue(it) })
}

// Java 17 bytecode (class-file major version 61), like the AAR (polyjose/build.gradle.kts), so the
// jar loads on Java 17 and newer; the compiler itself runs on the JDK 21 toolchain (ADR 0033 §1).
// `-Xjdk-release=17` compiles against the Java 17 class library, so no Java 18+ API can be called.
// Orchestrator decision 2026-11-07 (feature 0008 F04, review S7). check-artifacts.sh asserts 61.
kotlin {
    jvmToolchain(21)
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
        freeCompilerArgs.add("-Xjdk-release=17")
    }
}

java {
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 17
}

sourceSets {
    main {
        // The generated sources, written once by the root project (ADR 0033 §1a). The native
        // libraries and the notices are added to the jar task, not to the resources, so the
        // sources jar carries sources only.
        kotlin.srcDir(files(sharedBuild.dir("generated/uniffi/kotlin")).builtBy(":uniffiGenerate"))
        // The hand-written loader and redaction helpers the patched sources call (ADR 0030 §1,
        // feature 0008 F05), shared with `:polyjose`, and this jar's native hashes.
        kotlin.srcDir(rootDir.resolve("shared/kotlin"))
        kotlin.srcDir(nativeHashes.flatMap { it.outputDir })
    }
    test {
        // The conformance runner shared with the Android instrumented tests (feature 0008 T02).
        kotlin.srcDir(rootDir.resolve("shared-test/kotlin"))
    }
}

dependencies {
    // `api`: the generated public API mentions JNA types (Structure, Pointer in FfiConverter).
    api(libs.jna)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    // The host library under its JNA prefix (<prefix>/libpolyjose_ffi.*), which JNA loads from the
    // classpath (ADR 0033 §3a).
    testRuntimeOnly(files(sharedBuild.dir("jvm-natives")).builtBy(":assembleJvmNatives"))
    // Parses the conformance vectors (0008 research §3); test only, never in the jar.
    testImplementation(libs.org.json)
}

/**
 * The jar's payload for the forked child JVMs of LoaderPocTest (feature 0008 F05): the same
 * classes and `<prefix>/<library>` files as [tasks.jar], without the notices and the manifest
 * attributes. The notices run bash and cargo, which the Windows host-natives runner's
 * `:polyjose-jvm:test` should not need; the loader reads neither.
 */
val loaderTestJar = tasks.register<Jar>("loaderTestJar") {
    description = "The jar's classes and native libraries, for the loader's child-JVM tests (feature 0008 F05)."
    archiveFileName = "polyjose-jvm-loader-test.jar"
    destinationDirectory = layout.buildDirectory.dir("loader-test")
    from(sourceSets.main.get().output)
    from(assembleJarNatives)
}

tasks.test {
    useJUnitPlatform()

    // Absolute paths for the tests (ADR 0033 §5), each declared as an input so a change reruns them.
    val vectors = repoRoot.resolve("conformance/vectors")
    val inventory = repoRoot.resolve("bindings/api-inventory.txt")
    val manifest = repoRoot.resolve("Cargo.toml")
    inputs.dir(vectors).withPropertyName("vectors").withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.file(inventory).withPropertyName("apiInventory").withPathSensitivity(PathSensitivity.NONE)
    inputs.file(manifest).withPropertyName("workspaceManifest").withPathSensitivity(PathSensitivity.NONE)
    systemProperty("polyjose.vectors", vectors.path)
    systemProperty("polyjose.apiInventory", inventory.path)
    systemProperty("polyjose.workspaceManifest", manifest.path)

    // The ADR 0034 results file the conformance test writes (T02). Declared as an output, so the
    // tests run again whenever scripts/test-all.sh has cleared target/conformance/.
    val results = repoRoot.resolve("target/conformance/jvm.json")
    outputs.file(results).withPropertyName("conformanceResults")
    systemProperty("polyjose.conformanceResults", results.path)

    // Feature 0008 F05: the patch's input and output, build-logic (UniffiKotlinPatch, loaded on
    // its own by PatchTest), the host library the build produced (LoaderTest), and for the forked
    // child JVMs of LoaderPocTest: loaderTestJar, the jar's runtime class path (JNA, Kotlin) and
    // the test classes (LoaderProbe).
    val uniffiRaw = sharedBuild.file("generated/uniffi/raw/dev/polyjose/polyjose_ffi.kt").asFile
    val uniffiPatched = sharedBuild.file("generated/uniffi/kotlin/dev/polyjose/polyjose_ffi.kt").asFile
    val buildLogic = File(dev.polyjose.gradle.UniffiKotlinPatch::class.java.protectionDomain.codeSource.location.toURI())
    val hostNatives = sharedBuild.dir("jvm-natives").asFile
    val childClasspath = configurations.runtimeClasspath.get()
    val testClasses = sourceSets.test.get().output.classesDirs
    inputs.files(buildLogic).withPropertyName("buildLogic").withPathSensitivity(PathSensitivity.NONE)
    inputs.files(loaderTestJar).withPropertyName("loaderTestJar").withPathSensitivity(PathSensitivity.NONE)
    systemProperty("polyjose.uniffiRaw", uniffiRaw.path)
    systemProperty("polyjose.uniffiPatched", uniffiPatched.path)
    systemProperty("polyjose.buildLogic", buildLogic.path)
    systemProperty("polyjose.hostNatives", hostNatives.path)
    systemProperty("polyjose.mainClasses", sourceSets.main.get().output.classesDirs.asPath)
    jvmArgumentProviders.add(
        CommandLineArgumentProvider {
            listOf(
                "-Dpolyjose.loaderTestJar=${loaderTestJar.get().archiveFile.get().asFile.path}",
                "-Dpolyjose.childClasspath=${childClasspath.asPath}",
                "-Dpolyjose.childTestClasses=${testClasses.asPath}",
            )
        },
    )

    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

tasks.jar {
    // <prefix>/<library> for every platform built (ADR 0033 §4) and the notices.
    from(assembleJarNatives)
    from(thirdPartyNotices)
    manifest {
        attributes(
            "Implementation-Title" to "polyjose-jvm",
            "Implementation-Version" to version,
            // Exactly the platforms whose library is in this jar, comma separated. A jar built on
            // one machine lacks the CI platforms and says so (ADR 0033 §4).
            "Polyjose-Native-Platforms" to jarPlatforms.joinToString(","),
        )
        val missing = jnaPlatforms.keys - jarPlatforms.toSet()
        if (missing.isNotEmpty()) attributes("Polyjose-Native-Platforms-Missing" to missing.joinToString(","))
    }
}

// dev.polyjose:polyjose-jvm, the desktop JVM jar (ADR 0011, ADR 0033 §4), with a sources jar and
// an empty javadoc jar. Feature tasks publish only to the build-local file repository.
mavenPublishing {
    configure(KotlinJvm(JavadocJar.Empty(), SourcesJar.Sources()))
    coordinates(PackagingPlugin.GROUP, "polyjose-jvm", version.toString())
    pom {
        PackagingPlugin.pom(
            this,
            "polyjose-jvm",
            "polyjose for the desktop JVM: JOSE (JWS, JWE, JWK, JWT) in pure Rust, with Kotlin bindings.",
        )
    }
    if (PackagingPlugin.signingKeyPresent(providers)) signAllPublications()
}

publishing {
    repositories {
        maven {
            name = "buildLocal"
            url = uri(isolated.rootProject.projectDirectory.dir("build/repo"))
        }
    }
}
