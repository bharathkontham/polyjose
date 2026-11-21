# scripts

Repo-wide scripts. Each package's own scripts live in its folder (`bindings/*/scripts/`).

**Entry point.** `test-all.sh [<keys>]` runs each platform's `test.sh` (`rust wasm node android swift`, plus `tooling` on request), the guards in the `rust` block, and at the end `conformance-parity.sh`. A missing toolchain is reported as SKIPPED, never as passing.

**Guards** (each runs in every `test-all.sh rust` run; what each enforces is in [ARCHITECTURE.md](../ARCHITECTURE.md#7-guards)):
- `check-deps.sh`: the core's dependency tree against `deps-allowlist.txt`, each binding crate's against `bindings/deps-allowlist/<name>.txt`, sources and credits.
- `check-binding-api.sh` with one mode per binding in `check-binding-api.d/`: exported names against `bindings/api-inventory.txt`.
- `check-rsa-symbols.sh`: RSA private-key operations only through the `rsa` crate's blinded paths, checked on compiled output.
- `check-test-vectors-off.sh`: no build of a binding can enable the deterministic test RNG.
- `check-no-cargo-config.sh`: no cargo configuration file anywhere, and no override in any file under `scripts/`, `.github/` or `bindings/` (all of it, Kotlin and Swift included; besides the script itself, the Gradle wrapper jar is the one file not read): no `--config`, unstable cargo flag, rustc arguments after the double dash of `cargo rustc`, cargo or rustup variable, or `polyjose.jniLibsDir` in a `.properties` file. Lines split at CR too, and `#` is a comment only in shell, YAML, TOML, properties and extensionless files.

**Other scripts:** `conformance-parity.sh` (every runner's results equal `rust-core`'s), `third-party-notices.sh` (the notices file of each binary artifact, with the license texts in `licenses/`), `fuzz.sh` (the cargo-fuzz targets in `fuzz/`, before a release), and `release/` (assembling, checking and publishing release artifacts; see [RELEASING.md](../RELEASING.md)).

**`tests/` is not the library's tests.** It holds the self-tests of the scripts above and of `test-all.sh`, one folder per script, run by `scripts/test-all.sh tooling` (slow; needed only when `scripts/` or `.github/` change). Each file is its own command.
