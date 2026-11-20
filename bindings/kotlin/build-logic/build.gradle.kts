// `polyjose.packaging`: see settings.gradle.kts. Core Gradle plugins only.
plugins {
    `java-gradle-plugin`
}

java {
    // Gradle runs on JDK 21 here (ADR 0033 §1); the plugin classes need nothing newer than 17.
    toolchain.languageVersion = JavaLanguageVersion.of(21)
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 17
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

gradlePlugin {
    plugins {
        create("packaging") {
            id = "polyjose.packaging"
            implementationClass = "dev.polyjose.gradle.PackagingPlugin"
        }
    }
}
