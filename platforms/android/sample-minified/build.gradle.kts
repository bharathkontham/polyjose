// `:sample-minified`: an app that minifies with R8 and calls polyjose, never published (feature
// 0008 T04). Its instrumented test runs on the emulator against the minified release build and
// proves that the AAR's consumer-rules.pro (proguard.txt) keeps what JNA and the UniFFI-generated
// Kotlin find by reflection (ADR 0033 §2). The sample's own rules keep only its entry point,
// R8Probe, as an app's reachable code would be; everything it reaches in polyjose and JNA is
// shrunk under the consumer rules alone.
//
//   ./gradlew :sample-minified:connectedReleaseAndroidTest   (the emulator test)
//   scripts/check-artifacts.sh                               (zipalign -c -P 16 4 on its APK)

plugins {
    // Part of AGP, already on the build classpath with com.android.library (no new dependency).
    id("com.android.application")
}

android {
    namespace = "dev.polyjose.sample"
    compileSdk = libs.versions.androidCompileSdk.get().toInt()

    defaultConfig {
        applicationId = "dev.polyjose.sample.minified"
        minSdk = libs.versions.androidMinSdk.get().toInt()
        targetSdk = libs.versions.androidTargetSdk.get().toInt()
        versionCode = 1
        versionName = "1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // The test APK is minified as well; its rules never apply to the app.
            testProguardFiles("test-proguard-rules.pro")
            // A test app: signed with the debug key so it installs on the emulator.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    // The instrumented test runs against the minified build, not the debug one.
    testBuildType = "release"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation(project(":polyjose"))

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.junit4)
}
