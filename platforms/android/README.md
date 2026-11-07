# Android / Kotlin / JVM

The Gradle build of polyjose's Kotlin binding (ADR 0033). One UniFFI-generated Kotlin source set
(package `dev.polyjose`) is compiled into two artifacts:

| Module | Artifact | Natives |
|---|---|---|
| `:polyjose` | Android AAR `dev.polyjose:polyjose` (minSdk 23, compileSdk 36) | `jni/<abi>/libpolyjose_ffi.so` for arm64-v8a, armeabi-v7a, x86_64, x86 |
| `:polyjose-jvm` | desktop JVM jar `dev.polyjose:polyjose-jvm` | host libraries under JNA's resource prefixes (`darwin-aarch64/`, …) |

The UniFFI adapter itself (`bindings/ffi`, its `uniffi.toml` and the `polyjose-uniffi-bindgen`
package) belongs to feature 0013; nothing here edits it.

## Requirements

JDK 21, the Rust toolchain of `rust-toolchain.toml`, and for the AAR the Android SDK (36), NDK
28.2 and `cargo-ndk`. The Gradle wrapper is committed, so no Gradle install is needed. In this
workspace: `source /Users/bharath/bharathwork/joserust/.toolchain-env.sh`.

## Commands (from this directory)

```sh
./gradlew :polyjose-jvm:test        # JVM tests through JNA and the host library
./gradlew :polyjose:assembleDebug   # the AAR (builds all four ABIs with cargo-ndk)
./test.sh                           # what `scripts/test-all.sh android` runs
```

## Rust tasks (root project)

| Task | Does | Output |
|---|---|---|
| `cargoHostBuild` | `cargo build --release --lib -p polyjose-ffi` | `target/release/libpolyjose_ffi.{dylib,so}` / `polyjose_ffi.dll` |
| `uniffiGenerate` | `cargo run -p polyjose-uniffi-bindgen -- generate <host lib> --language kotlin --no-format` | `build/generated/uniffi/kotlin` |
| `cargoNdkBuild` | `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 --platform 23 build --release --lib -p polyjose-ffi` | `build/jniLibs/<abi>/` |
| `assembleJvmNatives` | copies the host library into JNA's layout | `build/jvm-natives/<jna-prefix>/` |

Each task declares its inputs (the Rust sources and manifests of `polyjose`, `polyjose-surface` and
`polyjose-ffi`, the lock file, the toolchain pin) and outputs, so a rebuild without changes is up to
date. The modules depend on these tasks; nothing generated is committed.

## Tests

- `:polyjose-jvm:test` (JUnit 5) gets absolute paths as system properties: `polyjose.vectors`
  (`conformance/vectors`), `polyjose.apiInventory` (`bindings/api-inventory.txt`),
  `polyjose.workspaceManifest` (`Cargo.toml`) and `polyjose.conformanceResults`
  (`target/conformance/jvm.json`, ADR 0034).
- `:polyjose` androidTest runs on the `polyjose-api36` emulator with the conformance vectors
  packaged as test-APK assets.
- Both test source sets include `shared-test/kotlin`, the conformance runner they share.
