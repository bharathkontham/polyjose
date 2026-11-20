# bindings

Everything that exposes the core (`crates/polyjose`) to another language, one folder per package or adapter. The layers, and how one call travels through them, are in [ARCHITECTURE.md](../ARCHITECTURE.md).

| Folder | Layer | What it is |
|---|---|---|
| [`surface/`](surface/) | 2. surface | crate `polyjose-surface`: every operation, record and error once, in plain Rust |
| [`node/`](node/) | 3. adapter + package | napi-rs adapter and the `@polyjose/node` npm package |
| [`wasm/`](wasm/) | 3. adapter + package | wasm-bindgen adapter and the `@polyjose/wasm` npm package |
| [`uniffi/`](uniffi/) | 3. adapter | crate `polyjose-ffi`: the UniFFI adapter shared by Kotlin and Swift |
| [`uniffi-bindgen/`](uniffi-bindgen/) | tooling | the pinned UniFFI generator CLI (never shipped) |
| [`ts-common/`](ts-common/) | 4. host | TypeScript shared by both npm packages: facade, backend contract, JS conformance runner |
| [`kotlin/`](kotlin/) | 4. host | Gradle build of `dev.polyjose:polyjose` (Android AAR) and `dev.polyjose:polyjose-jvm` (jar) |
| [`swift/`](swift/) | 4. host | sources, tests and XCFramework scripts of the Swift package `Polyjose` (`Package.swift` is at the repo root) |

Two contracts every binding shares sit here too:
- `api-inventory.txt`: the operations, records, fields and error codes every binding must export, checked by `scripts/check-binding-api.sh`.
- `deps-allowlist/<name>.txt`: the allowed dependency tree of the crate in `bindings/<name>`, checked by `scripts/check-deps.sh`.

Each package folder has a `test.sh` (the Rust crates are tested by `scripts/test-all.sh rust`).
