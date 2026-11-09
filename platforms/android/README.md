# polyjose for Android, Kotlin and the JVM

polyjose's Kotlin library: JOSE (JWS, JWE, JWK and JWT; RFC 7515 to 7519) from the pure-Rust
polyjose core, in the package `dev.polyjose`. Verify and decrypt always take an explicit algorithm
allow-list, and `none` is never accepted (RFC 8725).

## Install

```kotlin
dependencies {
    implementation("dev.polyjose:polyjose:0.1.2")      // Android AAR, minSdk 23
    // or, for the desktop and server JVM:
    implementation("dev.polyjose:polyjose-jvm:0.1.2")  // jar with macOS, Linux and Windows natives
}
```

Both are on Maven Central, which shows the latest version:
[dev.polyjose:polyjose](https://central.sonatype.com/artifact/dev.polyjose/polyjose) and
[dev.polyjose:polyjose-jvm](https://central.sonatype.com/artifact/dev.polyjose/polyjose-jvm).
They need a Kotlin 2.4 compiler or newer, and bring in JNA.

## Import

```kotlin
import dev.polyjose.*
```

Calls are synchronous and throw `PolyjoseException`. On Android, call them off the main thread.
Java can call them too, as static methods of `dev.polyjose.Polyjose_ffiKt`, but Kotlin is the
supported language.

## Quick start

Sign a JWT, then verify it with an explicit algorithm allow-list and the issuer and audience you
expect. `exp` is required and checked, with 60 seconds of leeway (RFC 8725 §3.8 to §3.10).

```kotlin
import dev.polyjose.*
import java.time.Instant

// An ES256 key pair. The verifier needs only the public half.
val privateKey = jwkGenerateForAlg("ES256")
val publicKey = jwkToPublic(privateKey)

val now = Instant.now().epochSecond
val token = jwtSign(
    claims = """{"iss":"https://issuer.example","sub":"user-123","aud":"https://api.example","exp":${now + 300}}""",
    key = privateKey,
    options = JwtSignOptions(alg = "ES256"),
)

try {
    val verified = jwtVerify(
        token = token,
        key = publicKey,
        options = JwtVerifyOptions(
            allowedAlgs = listOf("ES256"), // never trust the token's own `alg` (RFC 8725 §3.1)
            issuers = listOf("https://issuer.example"),
            audiences = listOf("https://api.example"),
        ),
    )
    println(verified.claims) // the claims as JSON text, with "sub":"user-123"
} catch (e: PolyjoseException) {
    println(e.code()) // e.g. "TokenExpired"
}
```

Encrypt to a recipient's public key, then decrypt, naming the algorithms you accept:

```kotlin
val recipient = jwkGenerateEc("P-256")
val jwe = jweEncryptCompact(
    plaintext = "top secret".toByteArray(),
    options = JweEncryptOptions(
        enc = "A256GCM",
        recipients = listOf(JweRecipient(alg = "ECDH-ES+A256KW", key = jwkToPublic(recipient))),
    ),
)
val decrypted = jweDecryptCompact(
    jwe,
    recipient,
    JweDecryptOptions(allowedAlgs = listOf("ECDH-ES+A256KW"), allowedEnc = listOf("A256GCM")),
)
try {
    println(decrypted.plaintext.decodeToString()) // "top secret"
} finally {
    decrypted.plaintext.fill(0) // wipe secret bytes when you are done with them
}
```

Printing a result redacts its secret fields, but reading a field gives the secret: never log
`verified.payload`, `decrypted.plaintext` or a key.

## Documentation

- Getting started on Android and the JVM: <https://polyjose.dev/start/android/>
- Secrets in memory and how the desktop JVM loads its native library:
  <https://polyjose.dev/reference/android/>
- Guides (sign and verify, encrypt and decrypt, validate a JWT, keys): <https://polyjose.dev>
- Error codes: <https://polyjose.dev/concepts/errors/>
- Source and issues: <https://github.com/bharathkontham/polyjose>

## Building from source

This directory is the Gradle build of the Kotlin binding (ADR 0033). One UniFFI-generated Kotlin
source set (package `dev.polyjose`) is compiled into two artifacts:

| Module | Artifact | Natives |
|---|---|---|
| `:polyjose` | Android AAR `dev.polyjose:polyjose` (minSdk 23, compileSdk 36) | `jni/<abi>/libpolyjose_ffi.so` for arm64-v8a, armeabi-v7a, x86_64, x86 |
| `:polyjose-jvm` | desktop JVM jar `dev.polyjose:polyjose-jvm` | host libraries under JNA's resource prefixes (`darwin-aarch64/`, …) |

The UniFFI adapter itself (`bindings/ffi`, its `uniffi.toml` and the `polyjose-uniffi-bindgen`
package) belongs to feature 0013; nothing here edits it.

### Requirements

JDK 21, the Rust toolchain of `rust-toolchain.toml`, and for the AAR the Android SDK (36), NDK
28.2 and `cargo-ndk`. The Gradle wrapper is committed, so no Gradle install is needed. In this
workspace: `source /Users/bharath/bharathwork/joserust/.toolchain-env.sh`.

### Commands (from this directory)

```sh
./gradlew :polyjose-jvm:test        # JVM tests through JNA and the host library
./gradlew :polyjose:assembleDebug   # the AAR (builds all four ABIs with cargo-ndk)
scripts/run-instrumented.sh         # the instrumented suite on an emulator (see Tests)
./test.sh                           # what `scripts/test-all.sh android` runs: both of the above
```

From the repository root, `scripts/check-binding-api.sh kotlin` checks the generated Kotlin's
public names against `bindings/api-inventory.txt` (ADR 0030 §2, 0013 T13); it generates the Kotlin
into its own scratch directory, so it needs cargo but not Gradle.

### Rust tasks (root project)

| Task | Does | Output |
|---|---|---|
| `cargoHostBuild` | `cargo build --release --lib -p polyjose-ffi` | `target/release/libpolyjose_ffi.{dylib,so}` / `polyjose_ffi.dll` |
| `cargoBindgenBuild` | `cargo build --profile bindgen --lib -p polyjose-ffi` (release, unstripped; read by `uniffiGenerate` only, never shipped) | `target/bindgen/libpolyjose_ffi.{dylib,so}` / `polyjose_ffi.dll` |
| `uniffiGenerate` | `cargo run -p polyjose-uniffi-bindgen -- generate <unstripped host lib> --language kotlin --no-format`, then `UniffiKotlinPatch` (loader, ADR 0065 redaction) | `build/generated/uniffi/raw` (unpatched), `build/generated/uniffi/kotlin` |
| `cargoNdkBuild` | `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 --platform 23 build --release --lib -p polyjose-ffi` | `build/jniLibs/<abi>/` |
| `assembleJvmNatives` | copies the host library into JNA's layout | `build/jvm-natives/<jna-prefix>/` |

Each task declares its inputs (the Rust sources and manifests of `polyjose`, `polyjose-surface` and
`polyjose-ffi`, the lock file, the toolchain pin) and outputs, so a rebuild without changes is up to
date. The modules depend on these tasks; nothing generated is committed.

### Tests

- `:polyjose-jvm:test` (JUnit 5) gets absolute paths as system properties: `polyjose.vectors`
  (`conformance/vectors`), `polyjose.apiInventory` (`bindings/api-inventory.txt`),
  `polyjose.workspaceManifest` (`Cargo.toml`) and `polyjose.conformanceResults`
  (`target/conformance/jvm.json`, ADR 0034). For feature 0008 F05 it also gets the patch's input
  and output and build-logic's jar (`PatchTest`), the host library the build produced
  (`LoaderTest`), and `loaderTestJar` with the child class path (`LoaderPocTest`, which starts a
  child JVM per planted-library case). `RedactionTest` covers ADR 0065's fields.
- `:polyjose` androidTest (JUnit 4, AndroidJUnitRunner) runs on an emulator:
  `ConformanceInstrumentedTest` (runner `android-emulator`), `SecurityInstrumentedTest` (the
  marker test for the JWS family, ADR 0030 §5; two generated keys differ, ADR 0005) and
  `RedactionInstrumentedTest` (ADR 0065 on the device). The
  `conformanceAssets` task copies `conformance/vectors/` and `conformance/schema.json` byte for byte
  into the test APK's assets under `conformance/`; the device hashes the bytes it parses for
  `vectors_digest` (ADR 0060), so a bundle that differs from the checkout fails parity.
- Both test source sets include `shared-test/kotlin`, the conformance runner they share.

#### The instrumented run (`scripts/run-instrumented.sh`)

1. It uses an emulator that `adb devices` lists as `device` and never stops it. With none, it boots
   `polyjose-api36` headless (`-no-window -no-audio -no-snapshot -gpu swiftshader_indirect`, about
   20 s on this host) and afterwards stops only that emulator, by serial (`adb -s <serial> emu
   kill`), also on an error or Ctrl-C. Either way it waits, at most 300 s in all, until the device
   is ready: `sys.boot_completed` is 1, `init.svc.bootanim` is `stopped` (when the image has it) and
   `pm path android` answers, so a cold boot does not reach Gradle before the package manager.
2. It runs `./gradlew :polyjose:connectedDebugAndroidTest` on that serial and judges the run by the
   JUnit XML under `polyjose/build/outputs/androidTest-results/connected/` (AGP can exit 0 when the
   instrumentation crashed): a failure, an error, a skipped test or a missing file fails it.
3. The test writes the results document to the test app's files dir and to AGP's additional test
   output dir, which AGP pulls before it uninstalls the test APK; the script copies it to
   `target/conformance/android-emulator.json` at the repository root (ADR 0034 §2).

With no SDK, no AVD or a boot that times out, the JVM tests have still run, so the platform is not
SKIPPED: the last line is `SKIPPED-RUNNER (android-emulator: host:<token>)` (`no-android-sdk`,
`no-avd`, `emulator-boot-timeout`, `emulator-exited`), which `scripts/test-all.sh` reports as a
SKIPPED runner under parity, never as passing (0013 F05). Overrides: `POLYJOSE_AVD`,
`POLYJOSE_EMULATOR_BOOT_TIMEOUT` (seconds).

Only arm64-v8a runs (an Apple Silicon host has no x86_64 system image), so x86_64 is NOT RUN. The
AVD has 4 KB pages, so 16 KB page-size runtime testing is SKIPPED with that reason; the 16 KB
alignment of the `.so` files is checked statically (`scripts/check-artifacts.sh`).

## License

MIT; see [LICENSE](https://github.com/bharathkontham/polyjose/blob/main/LICENSE).
