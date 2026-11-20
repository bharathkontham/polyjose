# polyjose-uniffi-bindgen

The UniFFI generator CLI, pinned to the same UniFFI version as `bindings/uniffi`. It generates the Kotlin and Swift sources from the compiled `polyjose-ffi` library:

```sh
cargo run -p polyjose-uniffi-bindgen -- generate <libpolyjose_ffi.dylib|.so> --language swift --out-dir <dir>
```

**Why it is its own crate:** UniFFI's `cli` feature pulls in the code generator and its dependencies (templating, argument parsing). In a separate package they never enter the dependency tree of `polyjose-ffi`, so they are never linked into a shipped library. Its tree is checked against `bindings/deps-allowlist/uniffi-bindgen.txt`. It is build tooling only and is not published.

Callers: the Kotlin build's `uniffiGenerate` task, `bindings/swift/scripts/build-xcframework.sh` and `check-generated.sh`, and `bindings/uniffi/tests/generated-names.sh`.
