# Contributing

- Branch from `main` and open a PR. Use Conventional Commits (`feat(jws): …`) and keep each commit small and passing.
- Every behaviour change needs tests. Algorithm work needs the RFC test vectors and conformance vectors in `conformance/vectors/`.
- No new crypto dependency without discussion: pure-Rust crates only (see `deny.toml`). Never implement a primitive yourself.
- Run `scripts/test-all.sh rust` before opening a PR (plus the platforms you touched, and `tooling` if you changed `scripts/` or `.github/`).
- No CI runs on pull requests: PRs are verified locally with `scripts/test-all.sh`, and the GitHub workflows are manual-dispatch only.

How the repository is laid out, and which folder holds which binding, is in [ARCHITECTURE.md](ARCHITECTURE.md).

## Toolchains per platform

`scripts/test-all.sh` reports a platform whose toolchain is missing as SKIPPED, never as passing.

| Platform | Needs |
|---|---|
| Rust (`rust`) | the toolchain pinned in `rust-toolchain.toml` (rustup installs it and its targets); `cargo-deny` |
| Node.js (`node`) | Node 24 and npm, plus Rust. The packages support Node 22.12 and later; the build runs TypeScript files directly (type stripping), and the vector tools need Node 24 |
| Web (`wasm`) | wasm-pack 0.15.1 and Google Chrome (the matching chromedriver is fetched by `bindings/wasm/scripts/chromedriver.sh`); without Chrome the browser runners are skipped and reported |
| Android and JVM (`android`) | JDK 21; for the AAR, lint and the emulator: the Android SDK 36, NDK 28.2, `cargo-ndk` and an emulator AVD (`polyjose-api36` by default). The JVM tests need only JDK 21 and Rust |
| Swift (`swift`) | macOS with Xcode and the iOS Simulator runtime; the nightly in `bindings/swift/nightly-toolchain` for the `arm64_32` watchOS library (without it you get a development build, see [bindings/swift/README.md](bindings/swift/README.md)) |
| Scripts and workflows (`tooling`) | `actionlint` (the workflow lint reports SKIPPED without it) |
| Fuzzing | cargo-fuzz 0.13.2 and the nightly in `fuzz/nightly-toolchain` |

## Running tests

- **Each package's `test.sh` is the supported entry point** (`bindings/{ts-common,node,wasm,kotlin,swift}/test.sh`, `interop/node/test.sh`). It builds, generates and tests in the right order, and writes the conformance results file that the parity check needs. With no PR CI, a local run is the gate.
- **`scripts/test-all.sh <keys>`** runs several platforms: `rust wasm node android swift` (the default), plus `tooling` when `scripts/` or `.github/` change. It runs the guards and, at the end, the parity check.
- **One suite or one test, from an IDE or a tool:** the native command behind each wrapper, and what it needs first, is in [ARCHITECTURE.md's test map](ARCHITECTURE.md#6-tests). Rows marked *not standalone* need their wrapper.
- libsignal's TESTING.md lists one native command per language and leaves the run-everything job to CI. polyjose has no PR CI, so it has the wrappers too, and the map shows both.

## Conventions

- Every package has a `test.sh`, and `scripts/test-all.sh <keys>` runs them.
- `scripts/tests/` holds the self-tests of the guard scripts and of `test-all.sh` (key `tooling`), one folder per script. They are not the library's tests.
- One PR per change, with Conventional Commits.

## Walkthrough: add an algorithm to an existing family

Example: RS384, RS512, PS512 and HS512 (JWS, 2026-11-12). Algorithm names are plain strings in every binding, so this touches **no binding code**.

1. **Core** (`crates/polyjose/src/`): the name in `jwa.rs`; the algorithm in its family module (for JWS, `jws/rsa.rs`, `jws/hmac.rs`, `jws/ecdsa.rs`, `jws/eddsa.rs`, dispatched by `jws/alg.rs`; for JWE, `jwe/`); the alg-to-key-family binding in `jwk.rs` and `jwk/set.rs`; key generation for the algorithm in `keys/generate.rs` if it has one. Cite the RFC section in a doc comment for every behaviour.
2. **Rust tests** (`crates/polyjose/tests/`): the RFC's own test vectors, the matching Wycheproof vectors where they exist (`tests/third_party/wycheproof/`), and negative cases (wrong key family, tampered signature, alg outside the allow-list).
3. **Conformance vectors** (`conformance/vectors/`): RFC vectors where the RFC prints them; otherwise vectors from an independent oracle in `conformance/tools/` (the 2026-11-12 vectors came from `conformance/tools/jws-oracle/gen.mjs`, Node's `crypto`). Then regenerate the WASM runner's embedded index: `POLYJOSE_WRITE_VECTOR_INDEX=1 cargo test -p polyjose-wasm --test vector_index` (it rewrites `bindings/wasm/tests/vectors/mod.rs`, a generated test file).
4. **Only if needed:** doc comments that list algorithms (`bindings/surface/src/jws.rs`, `bindings/uniffi/src/jws.rs`, and through it the regenerated `Polyjose.swift`), and the platform-key tables (`bindings/kotlin/android/src/main/kotlin/dev/polyjose/AndroidKeystoreKey.kt`, `bindings/swift/Sources/Polyjose/AppleKey.swift`) if the operating system's key service should offer the algorithm.
5. `CHANGELOG.md`, then `scripts/test-all.sh` on every platform: the new vectors run everywhere, and parity checks that every binding agrees.

## Walkthrough: add a binding operation

Example: the three unverified decodes `decodeProtectedHeaderUnverified`, `decodeJwsUnverified` and `decodeJwtUnverified` (0.4.0). The file count comes from the architecture (one adapter per framework, one conformance runner per platform), so expect about 60 files. In order:

1. **Core** (`crates/polyjose/src/`): the operation in its module (here `util.rs`, `util/unverified.rs`, with changes in `jws/compact.rs`, `jws/mod.rs`, `jwt/typ.rs`), and its tests (`crates/polyjose/tests/unverified_decode.rs`).
2. **Surface** (`bindings/surface/src/`): the function in the area file (`util.rs`) and its records in `records.rs`; tests in `bindings/surface/tests/surface_api.rs`.
3. **Adapters**, one exported function each, a type conversion and one surface call:
   - `bindings/uniffi/src/` (`lib.rs`, `records.rs`, the area file), tests `bindings/uniffi/tests/adapter_rule.rs` and `exports.rs`;
   - `bindings/node/src/` (`lib.rs`, `records.rs`, the area file) and the package entry `bindings/node/src/index.ts`;
   - `bindings/wasm/src/` (the area file; `write.rs` for result records) and the package entries `bindings/wasm/js/index.ts` and `backend.ts`.
4. **TypeScript facade** (`bindings/ts-common/`): `src/api.ts`, `src/backend.ts`, `src/types.ts` and the contract in `BACKEND.md`; tests in `test/` (`api.test.ts`, `fake-backend.ts`, `fake-entry.ts`, `prototype-pollution.test.ts`, `result-pollution.test.ts`, `runner.test.ts`, `types.test-d.ts`).
5. **Package tests:** `bindings/node/test/` (`api`, `backend`, `conformance`, `security`) and `bindings/wasm/tests/` (`engine.rs`, `memory.rs`).
6. **Kotlin:** the generated API needs nothing. Patch `bindings/kotlin/build-logic/src/main/java/dev/polyjose/gradle/UniffiKotlinPatch.java` only if a new record carries secrets that must be redacted; tests in `bindings/kotlin/jvm/src/test/kotlin/dev/polyjose/` (`PatchTest`, `RedactionTest`, `SecurityTest`) and `bindings/kotlin/android/src/androidTest/kotlin/dev/polyjose/RedactionInstrumentedTest.kt`.
7. **Swift:** regenerate `bindings/swift/Sources/Polyjose/Polyjose.swift` (`bindings/swift/scripts/build-xcframework.sh`, then copy `bindings/swift/build/generated/Polyjose.swift`; `check-generated.sh` fails until you do), update `Redaction.swift` for secret-bearing records; tests `bindings/swift/Tests/PolyjoseTests/RedactionTests.swift` and `SecurityTests.swift`.
8. **API inventory:** the operation, records and fields in `bindings/api-inventory.txt`, which `scripts/check-binding-api.sh` checks in every binding (also `SWIFT_REDACTED_RECORDS` in `scripts/check-binding-api.d/swift.sh` for a record that Swift redacts, and the counts in the self-test `scripts/tests/check-binding-api/surface.sh`).
9. **Conformance:** the operation in `conformance/schema/vectors.schema.json` and `conformance/README.md` ("Operations", "Operation mapping"), the vectors in `conformance/vectors/<dir>/` (and the directory's `NOTICE.md` when they come from third-party text, as `third_party/rfc7520/` does), the regenerated WASM index (`bindings/wasm/tests/vectors/mod.rs`), and the mapping in each runner:
   - `crates/polyjose/tests/conformance.rs` (rust-core),
   - `bindings/surface/tests/conformance.rs` (rust-surface),
   - `bindings/wasm/tests/conformance.rs` (wasm-node, wasm-chrome),
   - `bindings/ts-common/conformance/runner.ts` (node, wasm-pkg-*; `bindings/node/test/conformance.test.ts` drives it),
   - `bindings/kotlin/shared-test/kotlin/dev/polyjose/conformance/Operations.kt` (jvm, android-emulator),
   - `bindings/swift/Tests/PolyjoseTests/ConformanceRunner.swift` (swift-macos, swift-ios-sim).
10. **Interop and docs:** `interop/node/interop.test.ts` when panva/jose has the same operation; `CHANGELOG.md`, `README.md`, `SECURITY.md` when it affects security.

Then `scripts/test-all.sh` on every platform; parity fails until every runner maps the operation.
