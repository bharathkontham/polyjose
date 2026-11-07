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
        // from Maven Central or the plugin portal, so no artifact can be shadowed from a second source.
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\.android(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
            }
        }
        mavenCentral()
        gradlePluginPortal()
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
