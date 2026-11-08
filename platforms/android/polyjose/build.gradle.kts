// `:polyjose`, the Android library dev.polyjose:polyjose (ADR 0011, ADR 0033 §1, §2): the
// UniFFI-generated Kotlin (shared with `:polyjose-jvm`) plus libpolyjose_ffi.so for the four ABIs
// from cargo-ndk. AGP 9 compiles Kotlin itself, so no Kotlin plugin is applied here.

import com.android.build.api.variant.DeviceTestBuilder
import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.SourcesJar
import dev.polyjose.gradle.NativeHashes
import dev.polyjose.gradle.PackagingPlugin
import dev.polyjose.gradle.ThirdPartyNotices
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.library)
    // Group, workspace version, thirdPartyNotices and the POM (build-logic).
    id("polyjose.packaging")
    // vanniktech 0.37.0's base plugin (same artifact as the catalog's maven-publish alias, on the
    // root classpath): nothing is configured from Gradle properties, so no property can switch
    // on Central publishing (ADR 0011; Central is Gate 3).
    id("com.vanniktech.maven.publish.base")
}

/** The polyjose repository root (the cargo workspace). */
val repoRoot: File = rootDir.resolve("../..").canonicalFile

/** The root project's build directory, where its Rust tasks write (root build.gradle.kts). */
val sharedBuild: Directory = isolated.rootProject.projectDirectory.dir("build")

/** The four ABIs of the AAR (ADR 0033 §2), as `jni/<abi>/` folders. */
val androidAbis: List<String> = listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")

/**
 * `-Ppolyjose.jniLibsDir=<dir>`: package these `<abi>/libpolyjose_ffi.so` files instead of
 * building them with cargoNdkBuild (feature 0008 F05, review S4 option (a)). CI's assemble job
 * passes the emulator job's libraries, the ones its instrumented suite loaded, so the AAR carries
 * exactly what CI tested (ci-assemble-jar.sh --jni-libs compares them). The folder must hold
 * exactly the four ABI folders, each with exactly that one file.
 */
val ciJniLibsDir: File? = providers.gradleProperty("polyjose.jniLibsDir").orNull?.let { file(it) }?.also { dir ->
    if (!dir.isDirectory) throw GradleException("polyjose.jniLibsDir: $dir is not a directory")
    val entries = dir.listFiles().orEmpty().map { it.name }.sorted()
    if (entries != androidAbis) throw GradleException("polyjose.jniLibsDir: $dir must hold exactly $androidAbis, it holds $entries")
    for (abi in androidAbis) {
        val files = dir.resolve(abi).listFiles().orEmpty().map { it.name }
        if (files != listOf("libpolyjose_ffi.so") || !dir.resolve("$abi/libpolyjose_ffi.so").isFile) {
            throw GradleException("polyjose.jniLibsDir: $dir/$abi must hold exactly libpolyjose_ffi.so, it holds $files")
        }
    }
}

android {
    namespace = "dev.polyjose"
    compileSdk = libs.versions.androidCompileSdk.get().toInt()

    defaultConfig {
        // minSdk 23 (ADR 0033 §2); also cargo-ndk's --platform (root build.gradle.kts).
        minSdk = libs.versions.androidMinSdk.get().toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Packaged into the AAR as proguard.txt (ADR 0033 §2).
        consumerProguardFiles("consumer-rules.pro")
    }

    // A library has no targetSdk of its own; these are the test APK's and lint's (ADR 0033 §1).
    testOptions {
        targetSdk = libs.versions.androidTargetSdk.get().toInt()
    }
    lint {
        targetSdk = libs.versions.androidTargetSdk.get().toInt()
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // libpolyjose_ffi.so is packaged as cargo-ndk wrote it (the release profile already strips its
    // symbols): AGP's own strip pass changed 8 bytes, so the AAR's libraries, the test APK's and
    // the build's could not be compared byte for byte (feature 0008 F05, review S4). Apps that
    // use the AAR strip on their own packaging, as before.
    packaging {
        jniLibs {
            keepDebugSymbols += "**/libpolyjose_ffi.so"
        }
    }

    sourceSets {
        named("main") {
            // The hand-written loader and redaction helpers the patched generated sources call
            // (ADR 0030 §1, ADR 0065; feature 0008 F05), shared with `:polyjose-jvm`.
            kotlin.directories.add(rootDir.resolve("src/shared/kotlin").path)
        }
        named("androidTest") {
            // The conformance runner shared with the JVM tests (feature 0008 T02).
            kotlin.directories.add(rootDir.resolve("shared-test/kotlin").path)
            // The conformance vectors and schema are test-APK assets too: see ConformanceAssets.
        }
    }
}

/**
 * The test APK's conformance assets (ADR 0033 §5, ADR 0060 §2), read on the device through
 * `InstrumentationRegistry.getInstrumentation().context.assets`: everything under
 * `conformance/vectors/` at `conformance/vectors/`, and `conformance/schema.json` at
 * `conformance/schema.json`, as in the checkout. The prefix keeps the vectors apart from the
 * framework's own assets and the schema outside the vector listing, so the asset paths under
 * `conformance/vectors` are the vector ids (ADR 0045 §4). Copied without filters, so the bytes stay
 * those of the checkout; the device hashes the bytes it parses, and a bundle that differs fails
 * parity (ADR 0060 §2, §6).
 */
abstract class ConformanceAssets @Inject constructor(private val fs: FileSystemOperations) : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val vectors: DirectoryProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val schema: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun sync() {
        fs.sync {
            from(vectors) { into("conformance/vectors") }
            from(schema) { into("conformance") }
            into(outputDir)
        }
    }
}

val conformanceAssets = tasks.register<ConformanceAssets>("conformanceAssets") {
    vectors = layout.dir(provider { repoRoot.resolve("conformance/vectors") })
    schema = layout.file(provider { repoRoot.resolve("conformance/schema.json") })
}

/**
 * Copies a directory the root project's Rust tasks write into this module's build directory.
 * AGP's variant API takes generated sources only from a task of this project with a
 * [DirectoryProperty] output, which this task provides; [source] carries the dependency on the
 * root task (`builtBy`). The source-set DSL (`srcDir`) is deprecated in AGP 9 and drops it.
 */
abstract class SyncFromRootBuild @Inject constructor(private val fs: FileSystemOperations) : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val source: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun sync() {
        fs.sync {
            from(source)
            into(outputDir)
        }
    }
}

// META-INF/polyjose/THIRD-PARTY-NOTICES.txt inside the AAR's classes.jar (ADR 0020 §4, ADR 0033 §4;
// a subfolder of META-INF, which AGP's packaging does not exclude): one file over the union of the
// four ABIs' crate trees (header `Targets:`; feature 0008 F01). The task fails closed, naming them,
// if the header does not name exactly these four targets, an ABI's library compiles a crate the
// file does not list, or the file lists a crate no ABI compiles (ThirdPartyNotices).
val thirdPartyNotices = tasks.named<ThirdPartyNotices>("thirdPartyNotices") {
    primaryTarget = "aarch64-linux-android"
    targets.addAll("armv7-linux-androideabi", "x86_64-linux-android", "i686-linux-android")
}

// dev.polyjose.PolyjoseNativeHashes with an empty map: the shared loader returns the bare name on
// Android, where the libraries load from the APK (security audit I2), and never reads it.
val nativeHashes = tasks.register<NativeHashes>("nativeHashes") {
    description = "Generates an empty PolyjoseNativeHashes for the AAR (feature 0008 F05)."
    outputDir = layout.buildDirectory.dir("generated/polyjose/native-hashes")
}

androidComponents {
    onVariants { variant ->
        val name = variant.name.replaceFirstChar { it.uppercase() }
        // The generated sources, written once by the root project (ADR 0033 §1a).
        val kotlinSources = tasks.register<SyncFromRootBuild>("sync${name}UniffiKotlin") {
            source.from(files(sharedBuild.dir("generated/uniffi/kotlin")).builtBy(":uniffiGenerate"))
        }
        variant.sources.kotlin?.addGeneratedSourceDirectory(kotlinSources, SyncFromRootBuild::outputDir)
        variant.sources.kotlin?.addGeneratedSourceDirectory(nativeHashes, NativeHashes::getOutputDir)
        // jni/<abi>/libpolyjose_ffi.so for arm64-v8a, armeabi-v7a, x86_64 and x86 (ADR 0033 §2).
        val jniLibs = tasks.register<SyncFromRootBuild>("sync${name}JniLibs") {
            source.from(ciJniLibsDir ?: files(sharedBuild.dir("jniLibs")).builtBy(":cargoNdkBuild"))
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(jniLibs, SyncFromRootBuild::outputDir)
        // Java resources end up in classes.jar.
        variant.sources.resources?.addGeneratedSourceDirectory(thirdPartyNotices, ThirdPartyNotices::getOutputDir)
        // The instrumented test's vectors and schema (ConformanceAssets above).
        variant.deviceTests[DeviceTestBuilder.ANDROID_TEST_TYPE]?.sources?.assets
            ?.addGeneratedSourceDirectory(conformanceAssets, ConformanceAssets::outputDir)
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    // JNA's AAR carries libjnidispatch.so for every Android ABI. `api`: the generated public API
    // mentions JNA types (Structure, Pointer in FfiConverter).
    api(variantOf(libs.jna) { artifactType("aar") })

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.junit4)
}

// dev.polyjose:polyjose, the release AAR (ADR 0011, ADR 0033 §4), with a sources jar and an empty
// javadoc jar (Central requires one; no Dokka, feature 0008 T04). Feature tasks publish only to
// the build-local file repository: `./gradlew publishAllPublicationsToBuildLocalRepository`.
mavenPublishing {
    configure(AndroidSingleVariantLibrary(JavadocJar.Empty(), SourcesJar.Sources(), "release"))
    coordinates(PackagingPlugin.GROUP, "polyjose", version.toString())
    pom {
        PackagingPlugin.pom(
            this,
            "polyjose",
            "polyjose for Android: JOSE (JWS, JWE, JWK, JWT) in pure Rust, with Kotlin bindings.",
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
