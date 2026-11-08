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
scripts/run-instrumented.sh         # the instrumented suite on an emulator (see Tests)
./test.sh                           # what `scripts/test-all.sh android` runs: both of the above
```

From the repository root, `scripts/check-binding-api.sh kotlin` checks the generated Kotlin's
public names against `bindings/api-inventory.txt` (ADR 0030 §2, 0013 T13); it generates the Kotlin
into its own scratch directory, so it needs cargo but not Gradle.

## Rust tasks (root project)

| Task | Does | Output |
|---|---|---|
| `cargoHostBuild` | `cargo build --release --lib -p polyjose-ffi` | `target/release/libpolyjose_ffi.{dylib,so}` / `polyjose_ffi.dll` |
| `uniffiGenerate` | `cargo run -p polyjose-uniffi-bindgen -- generate <host lib> --language kotlin --no-format`, then `UniffiKotlinPatch` (loader, ADR 0065 redaction) | `build/generated/uniffi/raw` (unpatched), `build/generated/uniffi/kotlin` |
| `cargoNdkBuild` | `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 --platform 23 build --release --lib -p polyjose-ffi` | `build/jniLibs/<abi>/` |
| `assembleJvmNatives` | copies the host library into JNA's layout | `build/jvm-natives/<jna-prefix>/` |

Each task declares its inputs (the Rust sources and manifests of `polyjose`, `polyjose-surface` and
`polyjose-ffi`, the lock file, the toolchain pin) and outputs, so a rebuild without changes is up to
date. The modules depend on these tasks; nothing generated is committed.

## Tests

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

### The instrumented run (`scripts/run-instrumented.sh`)

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

## Secrets

polyjose wipes the secrets it owns in Rust. Some copies are outside its reach: those UniFFI 0.32.2
leaves on the Rust heap, and those on the JVM heap. This section says which ones remain and what
the caller should do. The rules come from ADR 0030 §3 and §7, ADR 0033 §6 and ADR 0058. The module
docs in `bindings/ffi/src/` and the generated KDoc give the same counts per function.

### What the caller should do

- **Wipe the `ByteArray`s you receive** once you are done with them (ADR 0030 §7.4). The secret
  byte outputs are `JwsVerified.payload`, `JweDecrypted.plaintext`, `JweDecrypted.aad` and the
  result of `jwkToDer`. The same applies to `base64urlDecode` when the decoded bytes are secret.
  Wipe the array in place:

  ```kotlin
  val verified = jwsVerifyCompact(token, publicJwk, JwsVerifyOptions(allowedAlgs = listOf("ES256")))
  try {
      process(verified.payload)
  } finally {
      verified.payload.fill(0)
  }
  ```

  Do the same for the secret `ByteArray`s you pass in (the payload to sign, the plaintext to
  encrypt, the DER to import) after the call returns.
- **Printed records redact their secrets (ADR 0065).** The build patches the generated `toString()`
  (feature 0008 F05), so these fields print as `<redacted, N bytes>` (N is the byte length, UTF-8
  for a JWK string) on the JVM and on Android: `JwsSigner.key`, `JweRecipient.key`,
  `JwsVerified.payload`, `JweDecrypted.plaintext`, `JweDecrypted.aad`, `JweEncryptOptions.aad` and
  `JwsVerifyOptions.detachedPayload`. Every other field prints as before. This covers `toString`,
  string templates, `println` and messages built from the records. It does not cover reading a
  field yourself: never log `signer.key`, `verified.payload` and the like, or the JWK strings and
  `ByteArray`s you pass in.
- **Do not put secrets in JWT claims.** `JwtVerified.claims` and the inner claims of
  `JwtNestedVerified` are plain `String` results, outside ADR 0030 §7's secret handling, even when
  they were decrypted from a nested JWT (ADR 0058, owner decision 2), and they print in full
  (ADR 0065 decision 3). Claims are usually not secret. Carry secrets in a JWE payload instead.

### Copies on the JVM heap (ADR 0030 §7.4, ADR 0033 §6)

JVM `String`s are immutable and garbage-collected, so neither polyjose nor the caller can wipe
them. The generated code also makes copies of its own that it does not wipe:

- every `String` argument, and every `String` field of a record argument such as
  `JwsSigner.key`, is encoded into a JVM-heap `ByteBuffer` (`FfiConverterString.toUtf8`) before it
  is copied into Rust memory;
- every `String` result, and every `String` field of a record result, is read into a temporary
  `ByteArray` (`FfiConverterString.lift`/`read`) and then decoded into the `String`.

`ByteArray` arguments are written straight into the Rust-allocated buffer, and `ByteArray` results
are the arrays you receive, which you can wipe. These host-side copies come on top of the Rust-heap
counts below.

### Copies left on the Rust heap (ADR 0058)

UniFFI 0.32.2 copies values in and out of a `RustBuffer` and frees it without wiping. The adapter
cannot reach those copies without `unsafe` (ADR 0058, "Why the adapter cannot fix it"). ADR 0058
measured them:

| Value | Unwiped Rust-heap copies |
|---|---|
| A `String` result (generated, imported, parsed and exported keys, PEM) | exactly 1: the buffer the host frees |
| A `ByteArray` result or secret `ByteArray` record field (`jwkToDer`, `payload`, `plaintext`, `aad`) | at least 2 full copies (the adapter's vector and the buffer the host frees), plus growth copies (below) |
| A secret `ByteArray` argument, or a secret field of a record argument (`JwsSigner.key`, `JweRecipient.key`, `detachedPayload`, `aad`) | 1 each |
| A bare `String` argument (for example a key or a JWK Set) | none |

For byte outputs UniFFI writes into a buffer that grows by doubling. Each move of that buffer after
the secret is fully written adds a full copy, and each move while it is being written adds a
partial copy that holds a prefix of the secret. There are at most log2(C/8) growth steps, where C
is the next power of two at or above the lowered length. Whether a step moves the buffer depends on
the allocator. On macOS arm64 ADR 0058 measured 2 to 5 full copies, depending on the output and
its size. Android's scudo allocator and glibc were not measured, so their counts may differ within
that rule. polyjose does not rely on the allocator scrubbing freed memory.

These copies are freed memory that the process reuses. Reading them takes a memory disclosure in
the host process, such as a core dump, a heap read or swap. The output figure "one per returned
value" in ADR 0030 §7.3, which ADR 0033 §6 restates, is corrected by ADR 0058; the counts above
apply. The planned fix is opaque key handles and caller-provided output buffers in 0.2.0 (ADR 0058,
owner decision 1). A zeroizing global allocator stays in the backlog (owner decision 3).

### Which native library the desktop JVM loads

The build patches the generated Kotlin (`uniffiGenerate`, build-logic `UniffiKotlinPatch`; feature
0008 F05, security audit M1): `findLibraryName` calls the hand-written `PolyjoseNativeLoader` in
`src/shared/kotlin`. The patch fails the build when UniFFI's generated text is not exactly what it
was written against, so a UniFFI upgrade cannot silently drop it.

On the desktop JVM the loader:

1. reads the resource `/<JNA prefix>/<mapped name>` (for example
   `darwin-aarch64/libpolyjose_ffi.dylib`) through its own class's class loader;
2. compares its SHA-256 with the hash compiled into the jar's classes at build time
   (`PolyjoseNativeHashes`, generated from the exact files the jar packs). When a jar earlier on the
   class path carries the same resource, only a copy with the expected hash is used;
3. copies it to a fresh private directory (`rwx------` on POSIX file systems, under
   `java.io.tmpdir`) with a random file name, checks the hash again on disk, and passes JNA the
   copy's **absolute path**. The copy is deleted when the JVM exits (on Windows a loaded DLL stays
   behind, as with JNA's own extraction);
4. throws `UnsatisfiedLinkError`, naming the resource and both hashes, when no copy matches. It
   never falls back to the bare name.

These are **ignored**: `jna.library.path`, `uniffi.component.polyjose_ffi.libraryOverride`, the
working directory, `LD_LIBRARY_PATH`, the `DYLD_*` variables (the random file name defeats dyld's
leaf-name lookup), `PATH` and the system library directories. A library planted in any of them is
not loaded (`LoaderPocTest` runs each case in a child JVM). If `java.io.tmpdir` is mounted `noexec`,
point `-Djava.io.tmpdir` at an executable private directory.

Android is unchanged: the loader returns the bare name `polyjose_ffi`, and the app loads
`libpolyjose_ffi.so` from its own read-only native library directory (audit I2).
