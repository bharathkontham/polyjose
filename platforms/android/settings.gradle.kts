// The polyjose Kotlin build (ADR 0033 §1): the Android AAR `:polyjose` (dev.polyjose:polyjose) and
// the desktop JVM jar `:polyjose-jvm` (dev.polyjose:polyjose-jvm), both compiled from the one
// UniFFI-generated Kotlin source set that the root project's `uniffiGenerate` task writes.
// Versions live in gradle/libs.versions.toml; the Gradle version in gradle/wrapper.

pluginManagement {
    // `polyjose.packaging` (notices, version, POM) shared by the two published modules; core
    // Gradle plugins only (build-logic/settings.gradle.kts).
    includeBuild("build-logic")
    repositories {
        // Google's repository serves only the Android and AndroidX groups; everything else comes
        // from Maven Central, so no artifact can be shadowed from a second source.
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\.android(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
            }
        }
        // No gradlePluginPortal(): Maven Central serves every plugin marker and plugin module of
        // the build (AGP's from Google above; Kotlin's and vanniktech's from Central), checked with
        // `--refresh-dependencies` and the portal removed. Its open `m2` namespace would otherwise be
        // an unfiltered fallback for any module missing from the two (feature 0008 F04, review S2/M2).
        // A new plugin that only the portal serves gets the portal back with an `exclusiveContent`
        // filter for exactly its groups, in a reviewed diff with gradle/verification-metadata.xml.
        mavenCentral()
    }
}

dependencyResolutionManagement {
    // Modules declare no repositories of their own.
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\.android(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "polyjose-android"

include(":polyjose", ":polyjose-jvm")

// An app that minifies with R8 and runs polyjose calls on the emulator, proving that the AAR's
// consumer-rules.pro keeps what JNA and UniFFI need (ADR 0033 §2). Never published.
include(":sample-minified")
