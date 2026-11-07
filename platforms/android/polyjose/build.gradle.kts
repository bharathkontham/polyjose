// `:polyjose`, the Android library dev.polyjose:polyjose (ADR 0011, ADR 0033 §1, §2): the
// UniFFI-generated Kotlin (shared with `:polyjose-jvm`) plus libpolyjose_ffi.so for the four ABIs
// from cargo-ndk. AGP 9 compiles Kotlin itself, so no Kotlin plugin is applied here.

import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.SourcesJar
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

    sourceSets {
        named("androidTest") {
            // The conformance runner shared with the JVM tests (feature 0008 T02).
            kotlin.directories.add(rootDir.resolve("shared-test/kotlin").path)
            // The conformance vectors as test-APK assets, read through
            // InstrumentationRegistry.getInstrumentation().context.assets (ADR 0033 §5).
            assets.directories.add(repoRoot.resolve("conformance/vectors").path)
        }
    }
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
// a subfolder of META-INF, which AGP's packaging does not exclude). Generated for arm64-v8a; the
// task fails if the crates of another ABI's library are not all listed in it. armeabi-v7a has one
// crate fewer (no cpufeatures), so the file covers all four (feature 0008 T04).
val thirdPartyNotices = tasks.named<ThirdPartyNotices>("thirdPartyNotices") {
    primaryTarget = "aarch64-linux-android"
    targets.addAll("armv7-linux-androideabi", "x86_64-linux-android", "i686-linux-android")
}

androidComponents {
    onVariants { variant ->
        val name = variant.name.replaceFirstChar { it.uppercase() }
        // The generated sources, written once by the root project (ADR 0033 §1a).
        val kotlinSources = tasks.register<SyncFromRootBuild>("sync${name}UniffiKotlin") {
            source.from(files(sharedBuild.dir("generated/uniffi/kotlin")).builtBy(":uniffiGenerate"))
        }
        variant.sources.kotlin?.addGeneratedSourceDirectory(kotlinSources, SyncFromRootBuild::outputDir)
        // jni/<abi>/libpolyjose_ffi.so for arm64-v8a, armeabi-v7a, x86_64 and x86 (ADR 0033 §2).
        val jniLibs = tasks.register<SyncFromRootBuild>("sync${name}JniLibs") {
            source.from(files(sharedBuild.dir("jniLibs")).builtBy(":cargoNdkBuild"))
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(jniLibs, SyncFromRootBuild::outputDir)
        // Java resources end up in classes.jar.
        variant.sources.resources?.addGeneratedSourceDirectory(thirdPartyNotices, ThirdPartyNotices::getOutputDir)
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
