// `:polyjose-jvm`, the desktop JVM jar dev.polyjose:polyjose-jvm (ADR 0011, ADR 0033 §1, §4): the
// UniFFI-generated Kotlin (shared with `:polyjose`) plus the host libraries as JNA resources.

import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import com.vanniktech.maven.publish.SourcesJar
import dev.polyjose.gradle.PackagingPlugin
import dev.polyjose.gradle.ThirdPartyNotices

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

/** cargo's target directory: `CARGO_TARGET_DIR` when set (relative to the workspace), else `target`. */
val cargoTargetDir: File =
    providers.environmentVariable("CARGO_TARGET_DIR").orNull
        ?.let { repoRoot.resolve(it) }
        ?: repoRoot.resolve("target")

/**
 * The five host platforms of the release jar: JNA resource prefix to Rust target triple
 * (ADR 0033 §3a, §4).
 */
val jnaPlatforms: Map<String, String> = sortedMapOf(
    "darwin-aarch64" to "aarch64-apple-darwin",
    "darwin-x86-64" to "x86_64-apple-darwin",
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

/** This host's JNA prefix (the root project's assembleJvmNatives copies its library), or null. */
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
 * The other platforms this host cross-builds: on macOS the other darwin architecture (both build
 * on one Mac, ADR 0033 §4). Linux and Windows libraries come from native CI runners.
 */
val crossPrefixes: List<String> =
    if (osName.startsWith("mac")) listOf("darwin-aarch64", "darwin-x86-64").filter { it != hostPrefix } else emptyList()

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
    val all = listOfNotNull(hostPrefix) + crossPrefixes + extraPrefixes
    val twice = all.groupBy { it }.filterValues { it.size > 1 }.keys
    if (twice.isNotEmpty()) throw GradleException("polyjose.jvmNativesDir: $twice are built on this host as well")
    all.sorted()
}

/**
 * Everything cargo reads to build polyjose-ffi (as the root project's rustLibraryInputs): the
 * workspace manifest, lock file and toolchain pin, and the core, surface and adapter crates.
 */
val rustLibraryInputs: FileCollection = files(
    repoRoot.resolve("Cargo.toml"),
    repoRoot.resolve("Cargo.lock"),
    repoRoot.resolve("rust-toolchain.toml"),
    listOf("crates/polyjose", "bindings/surface", "bindings/ffi").map { crate ->
        fileTree(repoRoot.resolve(crate)) { include("Cargo.toml", "build.rs", "src/**") }
    },
)

/** `cargo build --release --lib -p polyjose-ffi --target <triple>` for each cross-built platform. */
val cargoCrossBuilds: Map<String, TaskProvider<Exec>> = crossPrefixes.associateWith { prefix ->
    val triple = jnaPlatforms.getValue(prefix)
    val name = prefix.split("-").joinToString("") { part -> part.replaceFirstChar { it.uppercase() } }
    tasks.register<Exec>("cargoBuild$name") {
        group = "rust"
        description = "Cross-builds the polyjose-ffi cdylib for $triple ($prefix in the jar, ADR 0033 §4)."
        inputs.files(rustLibraryInputs).withPropertyName("rustSources").withPathSensitivity(PathSensitivity.RELATIVE)
        outputs.file(cargoTargetDir.resolve("$triple/release/${libraryName(prefix)}")).withPropertyName("library")
        workingDir(repoRoot)
        // `-p polyjose-ffi` alone, as cargoHostBuild: uniffi's `cli` feature never reaches the
        // library. `--locked`, as cargoHostBuild: a stale Cargo.lock fails instead of re-resolving.
        commandLine("cargo", "build", "--locked", "--release", "--lib", "-p", "polyjose-ffi", "--target", triple)
    }
}

/** The jar's native libraries in JNA's layout, `build/jar-natives/<prefix>/<library>`. */
val assembleJarNatives = tasks.register<Sync>("assembleJarNatives") {
    description = "Lays out every host library the jar carries under its JNA prefix (ADR 0033 §4)."
    duplicatesStrategy = DuplicatesStrategy.FAIL
    from(files(sharedBuild.dir("jvm-natives")).builtBy(":assembleJvmNatives"))
    cargoCrossBuilds.forEach { (prefix, build) -> from(build) { into(prefix) } }
    extraPrefixes.forEach { prefix -> from(extraNativesDir!!.resolve(prefix)) { into(prefix) } }
    into(layout.buildDirectory.dir("jar-natives"))
}

// META-INF/polyjose/THIRD-PARTY-NOTICES.txt (ADR 0020 §4, ADR 0033 §4): one file over the union of
// the crate trees of every platform in the jar (header `Targets:`; 75 crates for all five; feature
// 0008 F01). The task fails closed, naming them, if the header does not name exactly the jar's
// targets, a platform's library compiles a crate the file does not list, or the file lists a crate
// no platform compiles (ThirdPartyNotices).
val thirdPartyNotices = tasks.named<ThirdPartyNotices>("thirdPartyNotices") {
    hostPrefix?.let { primaryTarget = jnaPlatforms.getValue(it) }
    targets.addAll(jarPlatforms.map { jnaPlatforms.getValue(it) })
}

kotlin {
    jvmToolchain(21)
}

sourceSets {
    main {
        // The generated sources, written once by the root project (ADR 0033 §1a). The native
        // libraries and the notices are added to the jar task, not to the resources, so the
        // sources jar carries sources only.
        kotlin.srcDir(files(sharedBuild.dir("generated/uniffi/kotlin")).builtBy(":uniffiGenerate"))
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
    // classpath (ADR 0033 §3a); the tests need no cross-built library.
    testRuntimeOnly(files(sharedBuild.dir("jvm-natives")).builtBy(":assembleJvmNatives"))
    // Parses the conformance vectors (0008 research §3); test only, never in the jar.
    testImplementation(libs.org.json)
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
