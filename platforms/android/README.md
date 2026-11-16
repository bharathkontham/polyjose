# polyjose for Android, Kotlin and the JVM

polyjose's Kotlin library: JOSE (JWS, JWE, JWK and JWT; RFC 7515 to 7519) from the pure-Rust
polyjose core, in the package `dev.polyjose`. Verify and decrypt always take an explicit algorithm
allow-list, and `none` is never accepted (RFC 8725).

## Install

```kotlin
dependencies {
    implementation("dev.polyjose:polyjose:0.4.0")      // Android AAR, minSdk 23
    // or, for the desktop and server JVM:
    implementation("dev.polyjose:polyjose-jvm:0.4.0")  // jar with macOS, Linux and Windows natives
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

## Platform keys: the Android Keystore (AAR only)

`AndroidKeystoreKey` is a private key held by the Android Keystore (the TEE, or StrongBox), which
signs or decrypts for polyjose and never leaves the platform (ADR 0072 §2). It implements the
`PlatformKey` interface; pass it to the `…WithPlatformKey` operations. Only the private-key step
runs in the Keystore: allow-lists, key binding, `epk` checks, the KDF, content decryption and a
pure-Rust verify of every signature stay in polyjose. The class is in the Android AAR only; the
desktop JVM jar has the `PlatformKey` interface and no key class.

```kotlin
// Off the main thread: a key that needs the user may block while a prompt is up.
val key = AndroidKeystoreKey.generate("signing-key", "ES256")
val token = jwsSignCompactWithPlatformKey(
    "hello".toByteArray(), key, JwsSignOptions(protectedHeader = """{"alg":"ES256"}"""),
)
val again = AndroidKeystoreKey.open("signing-key", "ES256") // same publicJwk(), later or in another process
println(again) // "AndroidKeystoreKey(securityLevel=…)": no alias, no key
AndroidKeystoreKey.delete("signing-key")
```

- `generate(alias, algorithm, strongBox, userAuthentication, keySize, authorizer)` creates the key;
  it refuses an alias that already holds one (`PlatformKeyFailed`; delete it first) and leaves no
  key behind when it fails. `open(alias, algorithm, authorizer)` finds it again and checks through
  `KeyInfo` that it permits the algorithm. `delete(alias)` removes it.
- `publicJwk()` returns the public JWK as JSON text (encrypt to it, verify with it);
  `algorithms()` the one algorithm the key serves (for `ECDH-ES`, the whole ECDH-ES family);
  `securityLevel` where the key lives, read from `KeyInfo`, never from the request:
  `StrongBox`, `TrustedEnvironment`, `Software`, `SecureHardware` (below API 31, where the
  platform can't say which) or `Unknown`.
- One algorithm per key: one purpose, exactly that algorithm's digest and padding, never
  `DIGEST_NONE` or raw RSA, RSA public exponent 65537. `keySize` is the RSA modulus (2048, the
  default, 3072 or 4096) or the ECDH-ES curve (256, the default, 384 or 521).

| Algorithm | Keystore (TEE), from API | StrongBox, from API |
|---|---|---|
| ES256 | 23 | 28 |
| ES384, ES512 | 23 | not possible |
| RS256, PS256 | 23 | 28, 2048 bits only |
| RS384, RS512, PS384, PS512 | 23 | not possible |
| `ECDH-ES` (and `+A128KW`, `+A192KW`, `+A256KW`), P-256 | 31 | 31 |
| `ECDH-ES` family, P-384, P-521 | 31 | not possible |
| RSA-OAEP-256 | 34 | 34, 2048 bits; not verified on a StrongBox device |

Below the level, or where the table says "not possible", `generate` and `open` throw
`UnsupportedAlgorithm`; nothing fails later at first use. minSdk stays 23. RSA-OAEP-256 never falls
back to MGF1-SHA-1: on API 35+ its keys are created with `setMgf1Digests(SHA-256)`, and a key
without user authentication is checked before `generate` returns (polyjose encrypts a random
32-byte content key to it and the Keystore decrypts it; on failure the key is deleted and the
result is `UnsupportedAlgorithm`). A key with user authentication can't be checked that way, so
try an unauthenticated key on a device first.

**StrongBox** (`strongBox`), never a silent downgrade:
- `Off` (the default): the TEE; StrongBox is never asked for.
- `Preferred`: StrongBox when the device has it and it can serve the algorithm, else the TEE;
  `securityLevel` says which.
- `Required`: StrongBox or nothing. No StrongBox on the device is `PlatformKeyFailed`; an algorithm
  StrongBox can't serve is `UnsupportedAlgorithm`.

**User authentication** (`userAuthentication`; the device needs a secure lock screen):
- Time-bound, `UserAuthentication(validitySeconds > 0, allowDeviceCredential)`: the app shows its
  own `BiometricPrompt` (or the credential screen); the key then works for that many seconds.
  Outside that window a call fails with `UserAuthenticationRequired`. Every key kind.
- Per use, `UserAuthentication(0, allowDeviceCredential)`: signing and RSA-OAEP-256 keys, API 28+.
  Each operation is handed, initialised, to the `PlatformKeyAuthorizer` passed to `generate` or
  `open`, which returns once the user has authenticated it. polyjose ships
  `BiometricPromptAuthorizer(context, title, negativeButtonText, allowDeviceCredential, subtitle)`,
  on the framework's `android.hardware.biometrics.BiometricPrompt` (no AndroidX); the app declares
  `android.permission.USE_BIOMETRIC`. ECDH-ES keys are time-bound only, so per use on an ECDH-ES key
  is `UnsupportedAlgorithm`.
- `allowDeviceCredential` lets the PIN, pattern or password stand in for a strong biometric. Below
  API 30 the platform decides it (a time-bound key admits the credential, a per-use key doesn't),
  and asking for the other choice there is `UnsupportedAlgorithm`.

**Off the main thread.** A sign or decrypt call on a key that needs the user blocks its thread
while the prompt is up. On the main thread `BiometricPromptAuthorizer.authorize` refuses before
showing anything, because waiting for the prompt there would deadlock. Inside a polyjose call the
app doesn't see that `IllegalStateException`: it gets `PlatformKeyFailed` when signing and
`DecryptionFailed` when decrypting.

**Errors** (`PolyjoseException.code()`):

| Code | When |
|---|---|
| `KeyNotFound` | No key under the alias, the key was deleted, or the platform invalidated it (`KeyPermanentlyInvalidatedException`: the lock screen was removed or reset, or biometrics changed). Create a new key |
| `UserAuthenticationRequired` | The user has not authenticated (outside the time-bound window), or cancelled or failed the prompt. Prompt, then retry |
| `PlatformKeyFailed` | Any other platform failure when generating, opening or signing, including `Required` without StrongBox |
| `DecryptionFailed` | Any other failure while decrypting, a wrong or tampered encrypted key included (RFC 7516 §11.5) |
| `UnsupportedAlgorithm` | The algorithm, key size, backend or authentication mode can't be served at this API level |
| `KeyAlgorithmMismatch` | `open` with an algorithm the key doesn't permit, or the key used for another family |

No platform message, alias or key is ever part of a polyjose error or of the key's printed form.

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
| `:polyjose-jvm` | desktop JVM jar `dev.polyjose:polyjose-jvm` | host libraries under JNA's resource prefixes: `darwin-aarch64/`, `linux-aarch64/`, `linux-x86-64/`, `win32-x86-64/`. The macOS library is Apple silicon only (ADR 0073); a local build packs only this host's library |

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
./gradlew :polyjose:lintRelease     # Android lint at minSdk 23 (NewApi and every other error fails)
scripts/check-artifacts.sh          # AAR, jar, APK and publication checks (16 KB alignment, 5 MB limit)
./test.sh                           # what `scripts/test-all.sh android` runs: all of the above
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
  `RedactionInstrumentedTest` (ADR 0065 on the device), `PlatformKeyInstrumentedTest` (the
  `PlatformKey` callback with software keys), and the Keystore tests of `AndroidKeystoreKey`:
  `AndroidKeystoreKeyTest` (every TEE row of the algorithm table, fixed parameters, reuse,
  StrongBox, the RSA-OAEP-256 self-test, printing), `AndroidKeystoreKeyTableTest` (the API-level
  table, the authentication limits and the error mapping, as pure functions) and
  `AndroidKeystoreKeyAuthTest` (user authentication; it needs a secure lock screen, see below).
  An emulator's Keystore is software: a pass proves function, not hardware. A real device is
  [DEVICE-TESTS.md](DEVICE-TESTS.md). The
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
3. On an emulator it started, and only there, it sets a lock PIN (`adb shell locksettings`) for
   `AndroidKeystoreKeyAuthTest` and clears it on exit, also on failure. On an emulator it didn't
   start, that class is excluded and the live check is reported
   `SKIPPED (no secure lock screen on the AVD)`.
4. The test writes the results document to the test app's files dir and to AGP's additional test
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
