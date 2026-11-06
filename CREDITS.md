# Credits

polyjose is MIT licensed (see [LICENSE](LICENSE)). It does not implement cryptographic primitives
itself: it composes primitives written and maintained by other projects into JOSE. This file credits
every third-party crate that the `polyjose` crate depends on at run time and says what each one does
for polyjose.

The list is exactly the output of
`cargo tree -p polyjose -e normal --all-features --target all`, so it covers every target and every
feature. Some crates are compiled only for some targets; their entries say which. Test-only
dependencies and the frameworks of the language bindings (napi-rs, wasm-bindgen, UniFFI) are not
part of the core crate and are not listed here.

- **License:** as each crate declares it in its manifest. polyjose itself is MIT.
- **Audit status:** taken from polyjose's audit register (ADR 0019). polyjose never claims an audit
  beyond what is written here.
- **Kept current:** `scripts/check-deps.sh` fails when this file, `deps-allowlist.txt` and the
  dependency tree disagree. Each crate has exactly one `` ### `crate` `` heading below.

## Cryptographic primitives and their own dependencies

### `sha2`

- **Upstream:** RustCrypto, [RustCrypto/hashes](https://github.com/RustCrypto/hashes)
  ([crates.io](https://crates.io/crates/sha2))
- **License:** MIT OR Apache-2.0
- **Used for:** SHA-256 (FIPS 180-4) for JWK thumbprints (RFC 7638). Its `zeroize` feature wipes
  the hash state on drop, since the thumbprint of an `oct` key hashes the secret.
- **Audit status:** no public independent audit found. polyjose checks it, at the exact pinned
  version, against the RFC 7638 thumbprint test vector through its own JWK code.

### `digest`

- **Upstream:** RustCrypto, [RustCrypto/traits](https://github.com/RustCrypto/traits)
  ([crates.io](https://crates.io/crates/digest))
- **License:** MIT OR Apache-2.0
- **Used for:** the `Digest` trait that polyjose calls SHA-256 through (re-exported by `sha2`).
- **Audit status:** not in the ADR 0019 register; a dependency of `sha2`.

### `block-buffer`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/block-buffer))
- **License:** MIT OR Apache-2.0
- **Used for:** not used directly. `digest` buffers `sha2`'s input into blocks with it.
- **Audit status:** not in the ADR 0019 register; a dependency of `digest` (which `sha2` uses).

### `crypto-common`

- **Upstream:** RustCrypto, [RustCrypto/traits](https://github.com/RustCrypto/traits)
  ([crates.io](https://crates.io/crates/crypto-common))
- **License:** MIT OR Apache-2.0
- **Used for:** not used directly. Common traits and types shared by the RustCrypto algorithm
  traits, here by `digest`.
- **Audit status:** not in the ADR 0019 register; a dependency of `sha2`.

### `hybrid-array`

- **Upstream:** RustCrypto, [RustCrypto/hybrid-array](https://github.com/RustCrypto/hybrid-array)
  ([crates.io](https://crates.io/crates/hybrid-array))
- **License:** MIT OR Apache-2.0
- **Used for:** the fixed-size array type of `sha2`'s blocks and outputs.
- **Audit status:** not in the ADR 0019 register; a dependency of `sha2`.

### `typenum`

- **Upstream:** [paholg/typenum](https://github.com/paholg/typenum)
  ([crates.io](https://crates.io/crates/typenum))
- **License:** MIT OR Apache-2.0
- **Used for:** not used directly. The type-level sizes behind `hybrid-array`.
- **Audit status:** not in the ADR 0019 register; a dependency of `sha2`.

### `cpufeatures`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/cpufeatures))
- **License:** MIT OR Apache-2.0
- **Used for:** not used directly. `sha2` uses it on aarch64, x86 and x86_64 to detect the SHA CPU
  extensions at run time.
- **Audit status:** not in the ADR 0019 register; a dependency of `sha2`.

## Randomness

### `getrandom`

- **Upstream:** rust-random, [rust-random/getrandom](https://github.com/rust-random/getrandom)
  ([crates.io](https://crates.io/crates/getrandom))
- **License:** MIT OR Apache-2.0
- **Used for:** the operating system's cryptographically secure random number generator, polyjose's
  only source of randomness (ADR 0005), through `getrandom::fill`.
- **Audit status:** not in the ADR 0019 register.

### `cfg-if`

- **Upstream:** The Rust Project, [rust-lang/cfg-if](https://github.com/rust-lang/cfg-if)
  ([crates.io](https://crates.io/crates/cfg-if))
- **License:** MIT OR Apache-2.0
- **Used for:** not used directly. `getrandom` and `sha2` use it to select per-platform code at
  compile time.
- **Audit status:** not in the ADR 0019 register; a dependency of `getrandom` and `sha2`.

### `libc`

- **Upstream:** The Rust Project, [rust-lang/libc](https://github.com/rust-lang/libc)
  ([crates.io](https://crates.io/crates/libc))
- **License:** MIT OR Apache-2.0
- **Used for:** not used directly. On Unix-like systems `getrandom` calls the operating system's
  random source through it, and on some aarch64 and loongarch64 targets `cpufeatures` uses it to
  detect CPU features.
- **Audit status:** not in the ADR 0019 register; a dependency of `getrandom` and `cpufeatures`.

### `r-efi`

- **Upstream:** [r-efi/r-efi](https://github.com/r-efi/r-efi)
  ([crates.io](https://crates.io/crates/r-efi))
- **License:** MIT OR Apache-2.0 OR LGPL-2.1-or-later
- **Used for:** not used directly. `getrandom`'s UEFI backend; it is compiled only for UEFI targets
  that select that backend.
- **Audit status:** not in the ADR 0019 register; a dependency of `getrandom`.

## Constant-time operations and secret wiping

### `subtle`

- **Upstream:** dalek-cryptography, [dalek-cryptography/subtle](https://github.com/dalek-cryptography/subtle)
  ([crates.io](https://crates.io/crates/subtle))
- **License:** BSD-3-Clause
- **Used for:** constant-time choices and comparisons (`Choice`, `ConstantTimeEq`), for example in
  polyjose's base64url decoder, which handles secret input.
- **Audit status:** not in the ADR 0019 register.

### `zeroize`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/zeroize))
- **License:** Apache-2.0 OR MIT
- **Used for:** wiping key material and other secrets from memory when they are dropped
  (`Zeroize`, `Zeroizing`). `sha2` also uses it to wipe its hash state.
- **Audit status:** not in the ADR 0019 register.
