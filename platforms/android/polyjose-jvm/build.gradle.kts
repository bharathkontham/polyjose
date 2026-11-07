// `:polyjose-jvm`, the desktop JVM jar dev.polyjose:polyjose-jvm (ADR 0011, ADR 0033 §1, §4): the
// UniFFI-generated Kotlin (shared with `:polyjose`) plus the host libraries as JNA resources.

plugins {
    alias(libs.plugins.kotlin.jvm)
}

/** The polyjose repository root (the cargo workspace). */
val repoRoot: File = rootDir.resolve("../..").canonicalFile

/** The root project's build directory, where its Rust tasks write (root build.gradle.kts). */
val sharedBuild: Directory = isolated.rootProject.projectDirectory.dir("build")

kotlin {
    jvmToolchain(21)
}

sourceSets {
    main {
        // The generated sources, written once by the root project (ADR 0033 §1a).
        kotlin.srcDir(files(sharedBuild.dir("generated/uniffi/kotlin")).builtBy(":uniffiGenerate"))
        // The host libraries under their JNA prefixes (<prefix>/libpolyjose_ffi.*), which JNA
        // loads from the classpath (ADR 0033 §3a, §4).
        resources.srcDir(files(sharedBuild.dir("jvm-natives")).builtBy(":assembleJvmNatives"))
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
