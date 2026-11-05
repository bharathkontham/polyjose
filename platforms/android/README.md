# Android / Kotlin / Java

Gradle library module:
- `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 build --release -p polyjose-ffi` puts the `.so` files into `src/main/jniLibs/`
- `uniffi-bindgen generate --language kotlin` writes the Kotlin sources (JNA-based)
- Tests: JUnit on the JVM host (macOS dylib) for the conformance vectors, plus instrumented tests on an Android emulator
- Publishing: AAR to Maven Central via `com.vanniktech.maven.publish` (Sonatype Central Portal)
