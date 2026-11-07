// Root project: the Rust side of the Kotlin build (ADR 0033 §1). It builds polyjose-ffi with cargo,
// generates the UniFFI Kotlin once, and lays out the native libraries; `:polyjose` (AAR) and
// `:polyjose-jvm` (jar) consume these outputs from build/ and add the task dependencies with
// `builtBy`. Every task declares its inputs and outputs, so a rebuild without changes is up to date.
//
//   cargoHostBuild      polyjose-ffi for this host (release profile) -> target/release/<lib>
//   uniffiGenerate      the Kotlin sources from that library -> build/generated/uniffi/kotlin
//   cargoNdkBuild       the four Android ABIs with cargo-ndk -> build/jniLibs/<abi>/
//   assembleJvmNatives  the host library in JNA's resource layout -> build/jvm-natives/<prefix>/

plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.maven.publish) apply false
}

/** The cargo workspace: the polyjose repository root, two levels above this project. */
val repoRoot: File = rootDir.resolve("../..").canonicalFile

/** cargo's target directory: `CARGO_TARGET_DIR` when set (relative to the workspace), else `target`. */
val cargoTargetDir: File =
    providers.environmentVariable("CARGO_TARGET_DIR").orNull
        ?.let { repoRoot.resolve(it) }
        ?: repoRoot.resolve("target")

val osName: String = System.getProperty("os.name").lowercase()
val osArch: String = System.getProperty("os.arch").lowercase()

/** The file name cargo gives the polyjose-ffi cdylib on this host. */
val hostLibraryName: String = when {
    osName.startsWith("mac") -> "libpolyjose_ffi.dylib"
    osName.startsWith("windows") -> "polyjose_ffi.dll"
    else -> "libpolyjose_ffi.so"
}

/**
 * JNA's resource prefix for this host (`Platform.RESOURCE_PREFIX`), the folder JNA searches on the
 * classpath: `darwin-aarch64`, `darwin-x86-64`, `linux-x86-64`, `linux-aarch64` or `win32-x86-64`
 * (ADR 0033 §3a, confirmed from the JNA jar's own jnidispatch folders). Resolved only when a task
 * needs it, so an unsupported host can still build the AAR.
 */
fun jnaResourcePrefix(): String {
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
    if (os == null || arch == null || (os == "win32" && arch != "x86-64")) {
        throw GradleException("polyjose ships no JVM native library for $osName/$osArch (ADR 0033 §4)")
    }
    return "$os-$arch"
}

/**
 * Everything cargo reads to build polyjose-ffi: the workspace manifest, lock file and toolchain
 * pin, and the sources and manifests of the three crates in the library (core, surface, adapter).
 * Tests and benches are not inputs; a change to them never rebuilds the library.
 */
val rustLibraryInputs: FileCollection = files(
    repoRoot.resolve("Cargo.toml"),
    repoRoot.resolve("Cargo.lock"),
    repoRoot.resolve("rust-toolchain.toml"),
    listOf("crates/polyjose", "bindings/surface", "bindings/ffi").map { crate ->
        fileTree(repoRoot.resolve(crate)) { include("Cargo.toml", "build.rs", "src/**") }
    },
)

val hostLibrary: File = cargoTargetDir.resolve("release/$hostLibraryName")

val cargoHostBuild = tasks.register<Exec>("cargoHostBuild") {
    group = "rust"
    description = "Builds the polyjose-ffi cdylib for this host with the release profile (ADR 0033 §1)."
    inputs.files(rustLibraryInputs).withPropertyName("rustSources").withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.file(hostLibrary).withPropertyName("hostLibrary")
    workingDir(repoRoot)
    // `-p polyjose-ffi` alone, so uniffi's `cli` feature (bindgen only) is never unified into the
    // shipped library (bindings/ffi/Cargo.toml). `--locked`: a Cargo.lock that does not match the
    // manifests fails the build instead of being re-resolved, so the library holds exactly the
    // reviewed crate versions that scripts/third-party-notices.sh (`--locked`) lists.
    commandLine("cargo", "build", "--locked", "--release", "--lib", "-p", "polyjose-ffi")
}

val uniffiKotlinDir: File = layout.buildDirectory.dir("generated/uniffi/kotlin").get().asFile

val uniffiGenerate = tasks.register<Exec>("uniffiGenerate") {
    group = "rust"
    description = "Generates the Kotlin sources (package dev.polyjose) from the host library in UniFFI library mode (ADR 0033 §1a)."
    inputs.files(cargoHostBuild).withPropertyName("hostLibrary").withPathSensitivity(PathSensitivity.NONE)
    // The bindgen CLI and the generator settings (bindings/ffi/uniffi.toml, found through cargo
    // metadata: Kotlin package dev.polyjose).
    inputs.files(
        repoRoot.resolve("bindings/ffi/uniffi.toml"),
        fileTree(repoRoot.resolve("bindings/uniffi-bindgen")) { include("Cargo.toml", "src/**") },
    ).withPropertyName("bindgen").withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.dir(uniffiKotlinDir).withPropertyName("kotlinSources")
    val outDir = uniffiKotlinDir
    // A file the generator no longer writes must not stay behind and compile.
    doFirst { outDir.deleteRecursively() }
    workingDir(repoRoot)
    // `--no-format`: no ktlint (0008 research §1). Library mode is automatic in uniffi 0.32.
    // `--locked`, as cargoHostBuild: the generator is built from the reviewed Cargo.lock only.
    commandLine(
        "cargo", "run", "--locked", "-p", "polyjose-uniffi-bindgen", "--",
        "generate", hostLibrary.path, "--language", "kotlin", "--no-format", "--out-dir", outDir.path,
    )
}

val jniLibsDir: File = layout.buildDirectory.dir("jniLibs").get().asFile

val cargoNdkBuild = tasks.register<Exec>("cargoNdkBuild") {
    group = "rust"
    description = "Builds polyjose-ffi for arm64-v8a, armeabi-v7a, x86_64 and x86 with cargo-ndk (ADR 0033 §2)."
    inputs.files(rustLibraryInputs).withPropertyName("rustSources").withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.dir(jniLibsDir).withPropertyName("jniLibs")
    val outDir = jniLibsDir
    doFirst { outDir.deleteRecursively() }
    workingDir(repoRoot)
    // --platform is the AAR's minSdk (ADR 0033 §2), from the version catalog. cargo-ndk passes
    // everything after `build` to cargo, `--locked` included (as cargoHostBuild).
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a", "-t", "armeabi-v7a", "-t", "x86_64", "-t", "x86",
        "--platform", libs.versions.androidMinSdk.get(),
        "-o", outDir.path,
        "build", "--locked", "--release", "--lib", "-p", "polyjose-ffi",
    )
}

val assembleJvmNatives = tasks.register<Sync>("assembleJvmNatives") {
    group = "rust"
    description = "Copies the host library into build/jvm-natives/<JNA prefix>/ for the JVM jar and tests (ADR 0033 §3a)."
    from(cargoHostBuild)
    into(layout.buildDirectory.dir(providers.provider { "jvm-natives/${jnaResourcePrefix()}" }))
}

tasks.register<Delete>("clean") {
    description = "Deletes the root build directory (generated Kotlin, jniLibs, JVM natives)."
    delete(layout.buildDirectory)
}
