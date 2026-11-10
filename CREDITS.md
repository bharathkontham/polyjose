# Credits

polyjose is MIT licensed (see [LICENSE](LICENSE)). It does not implement cryptographic primitives
itself: it composes primitives written and maintained by other projects into JOSE. This file credits
every third-party crate that the `polyjose` crate depends on, at run time or at build time, and says
what each one does for polyjose.

The list is exactly the output of
`cargo tree -p polyjose -e normal,build --all-features --target all`, so it covers every target and
every feature. Some crates are compiled only for some targets or backends; their entries say which.
The [build-time crates](#build-time-only) run on the builder's machine and link nothing into
polyjose. Test-only dependencies are not listed. The frameworks of the language bindings are not
part of the core crate; they are listed separately under [Binding frameworks](#binding-frameworks).

- **License:** as each crate declares it in its manifest. polyjose itself is MIT.
- **Version:** the exact version that `Cargo.lock` resolves for the core crate.
- **Audit status:** taken from polyjose's audit register, [AUDITS.md](AUDITS.md). polyjose never
  claims an audit beyond what is written there.
- **Kept current:** `scripts/check-deps.sh` fails when this file, `deps-allowlist.txt` and the
  dependency tree disagree. Each crate has exactly one `` ### `crate` `` heading below.

## Hashes and MACs

### `sha2`

- **Upstream:** RustCrypto, [RustCrypto/hashes](https://github.com/RustCrypto/hashes)
  ([crates.io](https://crates.io/crates/sha2))
- **License:** MIT OR Apache-2.0
- **Version:** 0.11.1
- **Used for:** SHA-256 (FIPS 180-4) for JWK thumbprints (RFC 7638), and the SHA-2 hashes of the
  HS*, ES* and RS*/PS* algorithms (through `hmac`, the curve crates and `rsa`). Its `zeroize`
  feature wipes the hash state on drop, since the thumbprint of an `oct` key hashes the secret.
- **Audit status:** no public independent audit found. polyjose checks it, at the exact pinned
  version, against the RFC 7638 thumbprint test vector through its own JWK code.

### `hmac`

- **Upstream:** RustCrypto, [RustCrypto/MACs](https://github.com/RustCrypto/MACs)
  ([crates.io](https://crates.io/crates/hmac))
- **License:** MIT OR Apache-2.0
- **Version:** 0.13.0
- **Used for:** HMAC (RFC 2104) for the JWS algorithms HS256, HS384 and HS512 (RFC 7518 §3.2)
  and the MAC half of JWE A*CBC-HS* (RFC 7518 §5.2), including the constant-time tag comparison,
  and under `pbkdf2`. Its `zeroize` feature wipes the keyed state on drop.
- **Audit status:** no public independent audit found.

### `digest`

- **Upstream:** RustCrypto, [RustCrypto/traits](https://github.com/RustCrypto/traits)
  ([crates.io](https://crates.io/crates/digest))
- **License:** MIT OR Apache-2.0
- **Version:** 0.11.3
- **Used for:** the `Digest` and `Mac` traits that polyjose calls SHA-256 and HMAC through
  (re-exported by `sha2` and `hmac`).
- **Audit status:** not in the ADR 0019 register; a dependency of `sha2`, `hmac` and `rsa`.

### `block-buffer`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/block-buffer))
- **License:** MIT OR Apache-2.0
- **Version:** 0.12.1
- **Used for:** not used directly. `digest` buffers `sha2`'s input into blocks with it.
- **Audit status:** not in the ADR 0019 register; a dependency of `digest` (which `sha2` uses).

### `crypto-common`

- **Upstream:** RustCrypto, [RustCrypto/traits](https://github.com/RustCrypto/traits)
  ([crates.io](https://crates.io/crates/crypto-common))
- **License:** MIT OR Apache-2.0
- **Version:** 0.2.2
- **Used for:** not used directly. Common traits and types shared by the RustCrypto algorithm
  traits, here by `digest`.
- **Audit status:** not in the ADR 0019 register; a dependency of `digest` (which `sha2` uses).

### `hybrid-array`

- **Upstream:** RustCrypto, [RustCrypto/hybrid-array](https://github.com/RustCrypto/hybrid-array)
  ([crates.io](https://crates.io/crates/hybrid-array))
- **License:** MIT OR Apache-2.0
- **Version:** 0.4.15
- **Used for:** not used directly. The fixed-size array type of `sha2`'s blocks and outputs, through
  `block-buffer` and `crypto-common`.
- **Audit status:** not in the ADR 0019 register; a dependency of `block-buffer` and `crypto-common`
  (both pulled in by `digest`).

### `typenum`

- **Upstream:** [paholg/typenum](https://github.com/paholg/typenum)
  ([crates.io](https://crates.io/crates/typenum))
- **License:** MIT OR Apache-2.0
- **Version:** 1.20.1
- **Used for:** not used directly. The type-level sizes behind `hybrid-array` and `crypto-common`.
- **Audit status:** not in the ADR 0019 register; a dependency of `hybrid-array` and
  `crypto-common`.

### `cpufeatures`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/cpufeatures))
- **License:** MIT OR Apache-2.0
- **Version:** 0.3.1
- **Used for:** not used directly. `sha2`, `aes` and `polyval` use it on aarch64, x86 and x86_64 to
  detect the SHA, AES and carry-less multiply CPU extensions at run time, and `curve25519-dalek`
  on x86_64 to pick its AVX2 backend.
- **Audit status:** not in the ADR 0019 register; a dependency of `sha2`, `aes`, `polyval` and
  `curve25519-dalek`.

### `ctutils`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/ctutils))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.4.8
- **Used for:** not used directly. Constant-time comparison and selection helpers: `digest` verifies
  HMAC tags with them, `aes-gcm` its GCM tags, and `crypto-bigint`, `sec1` and `universal-hash` use
  them too.
- **Audit status:** not in the ADR 0019 register; a dependency of `digest`, `aes-gcm`,
  `crypto-bigint`, `sec1` and `universal-hash`.

### `cmov`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/cmov))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.5.4
- **Used for:** not used directly. Constant-time conditional moves under `ctutils`.
- **Audit status:** not in the ADR 0019 register; a dependency of `ctutils`.

### `const-oid`

- **Upstream:** RustCrypto, [RustCrypto/formats](https://github.com/RustCrypto/formats)
  ([crates.io](https://crates.io/crates/const-oid))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.10.2
- **Used for:** not used directly. ASN.1 object identifiers of the hash algorithms, for `digest`,
  `der` and `rsa` (the PKCS#1 v1.5 DigestInfo prefixes).
- **Audit status:** not in the ADR 0019 register; a dependency of `digest`, `der` and `rsa`.

## Symmetric encryption and key derivation

### `aes`

- **Upstream:** RustCrypto, [RustCrypto/block-ciphers](https://github.com/RustCrypto/block-ciphers)
  ([crates.io](https://crates.io/crates/aes))
- **License:** MIT OR Apache-2.0
- **Version:** 0.9.4
- **Used for:** the AES block cipher (FIPS 197) under every JWE AES mode: A*GCM, A*GCMKW, A*KW and
  the CBC half of A*CBC-HS*. It picks the AES CPU instructions at run time on aarch64, x86 and
  x86_64 and a constant-time software implementation elsewhere (wasm32). Its `zeroize` feature wipes
  the key schedules on drop.
- **Audit status:** no public independent audit found. It is the cipher under `aes-gcm`, `aes-kw`
  and `cbc`.

### `aes-gcm`

- **Upstream:** RustCrypto, [RustCrypto/AEADs](https://github.com/RustCrypto/AEADs)
  ([crates.io](https://crates.io/crates/aes-gcm))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.11.1
- **Used for:** AES-GCM for the JWE content encryption algorithms A128GCM, A192GCM and A256GCM
  (RFC 7518 §5.3) and the key wrapping algorithms A128GCMKW, A192GCMKW and A256GCMKW
  (RFC 7518 §4.7). It checks the tag in constant time before decrypting.
- **Audit status:** audited by NCC Group in 2020 (for MobileCoin): no significant findings. The
  review covered the 0.8 series; polyjose pins 0.11.1, which postdates it.

### `aes-kw`

- **Upstream:** RustCrypto, [RustCrypto/key-wraps](https://github.com/RustCrypto/key-wraps)
  ([crates.io](https://crates.io/crates/aes-kw))
- **License:** MIT OR Apache-2.0
- **Version:** 0.3.1
- **Used for:** AES Key Wrap (RFC 3394) for the JWE algorithms A128KW, A192KW and A256KW
  (RFC 7518 §4.4), and the wrapping step of PBES2 (RFC 7518 §4.8) and ECDH-ES+A*KW
  (RFC 7518 §4.6). Its `zeroize` feature wipes the key on drop.
- **Audit status:** no public independent audit found.

### `cbc`

- **Upstream:** RustCrypto, [RustCrypto/block-modes](https://github.com/RustCrypto/block-modes)
  ([crates.io](https://crates.io/crates/cbc))
- **License:** MIT OR Apache-2.0
- **Version:** 0.2.1
- **Used for:** AES-CBC with PKCS#7 padding, the encryption half of A128CBC-HS256, A192CBC-HS384 and
  A256CBC-HS512 (RFC 7518 §5.2). polyjose verifies the HMAC tag before it decrypts
  (RFC 7518 §5.2.2.2), so the padding check never sees unauthenticated input.
- **Audit status:** no public independent audit found.

### `pbkdf2`

- **Upstream:** RustCrypto,
  [RustCrypto/password-hashes](https://github.com/RustCrypto/password-hashes)
  ([crates.io](https://crates.io/crates/pbkdf2))
- **License:** MIT OR Apache-2.0
- **Version:** 0.13.0
- **Used for:** PBKDF2 (RFC 8018 §5.2) with HMAC-SHA-256/384/512 for the JWE algorithms
  PBES2-HS256+A128KW, PBES2-HS384+A192KW and PBES2-HS512+A256KW (RFC 7518 §4.8). Only its
  `hmac` feature is enabled: no password-hash formats.
- **Audit status:** no public independent audit found.

### `cipher`

- **Upstream:** RustCrypto, [RustCrypto/traits](https://github.com/RustCrypto/traits)
  ([crates.io](https://crates.io/crates/cipher))
- **License:** MIT OR Apache-2.0
- **Version:** 0.5.2
- **Used for:** the RustCrypto block-cipher and block-mode traits that `aes`, `cbc`, `ctr` and
  `aes-kw` implement and polyjose calls AES-CBC through.
- **Audit status:** not in the ADR 0019 register; a dependency of `aes`, `cbc`, `ctr` and `aes-gcm`.

### `inout`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/inout))
- **License:** MIT OR Apache-2.0
- **Version:** 0.2.5
- **Used for:** not used directly. The in-place and in/out buffer types of the `cipher` and `aead`
  traits.
- **Audit status:** not in the ADR 0019 register; a dependency of `cipher` and `aead`.

### `block-padding`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/block-padding))
- **License:** MIT OR Apache-2.0
- **Version:** 0.4.2
- **Used for:** PKCS#7 padding for AES-CBC (RFC 7518 §5.2.2.1), through `cbc`'s `block-padding`
  feature.
- **Audit status:** not in the ADR 0019 register; a dependency of `cipher`.

### `aead`

- **Upstream:** RustCrypto, [RustCrypto/traits](https://github.com/RustCrypto/traits)
  ([crates.io](https://crates.io/crates/aead))
- **License:** MIT OR Apache-2.0
- **Version:** 0.6.1
- **Used for:** the RustCrypto AEAD traits that polyjose calls AES-GCM through (detached-tag,
  in-place encryption and decryption).
- **Audit status:** not in the ADR 0019 register; a dependency of `aes-gcm`.

### `ctr`

- **Upstream:** RustCrypto, [RustCrypto/block-modes](https://github.com/RustCrypto/block-modes)
  ([crates.io](https://crates.io/crates/ctr))
- **License:** MIT OR Apache-2.0
- **Version:** 0.10.1
- **Used for:** not used directly. The counter mode that `aes-gcm` encrypts with.
- **Audit status:** not in the ADR 0019 register; a dependency of `aes-gcm`.

### `ghash`

- **Upstream:** RustCrypto,
  [RustCrypto/universal-hashes](https://github.com/RustCrypto/universal-hashes)
  ([crates.io](https://crates.io/crates/ghash))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.6.0
- **Used for:** not used directly. GHASH, the authenticator of AES-GCM, inside `aes-gcm`.
- **Audit status:** not in the ADR 0019 register; a dependency of `aes-gcm` (part of the AES-GCM
  construction NCC Group reviewed in 2020, see `aes-gcm`).

### `polyval`

- **Upstream:** RustCrypto,
  [RustCrypto/universal-hashes](https://github.com/RustCrypto/universal-hashes)
  ([crates.io](https://crates.io/crates/polyval))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.7.3
- **Used for:** not used directly. The POLYVAL field arithmetic that `ghash` is computed with, using
  the carry-less multiply CPU instructions where available.
- **Audit status:** not in the ADR 0019 register; a dependency of `ghash`.

### `universal-hash`

- **Upstream:** RustCrypto, [RustCrypto/traits](https://github.com/RustCrypto/traits)
  ([crates.io](https://crates.io/crates/universal-hash))
- **License:** MIT OR Apache-2.0
- **Version:** 0.6.1
- **Used for:** not used directly. The universal-hash traits `ghash` and `polyval` implement.
- **Audit status:** not in the ADR 0019 register; a dependency of `ghash` and `polyval`.

## ECDSA

### `p256`

- **Upstream:** RustCrypto,
  [RustCrypto/elliptic-curves](https://github.com/RustCrypto/elliptic-curves)
  ([crates.io](https://crates.io/crates/p256))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.14.0
- **Used for:** the P-256 curve: ES256 (RFC 7518 §3.4), the Diffie-Hellman of JWE ECDH-ES
  (RFC 7518 §4.6, its `ecdh` feature) and the on-curve and scalar-range checks of `crv` `P-256`
  JWKs (ADR 0041 §4).
- **Audit status:** no public independent audit found.

### `p384`

- **Upstream:** RustCrypto,
  [RustCrypto/elliptic-curves](https://github.com/RustCrypto/elliptic-curves)
  ([crates.io](https://crates.io/crates/p384))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.14.0
- **Used for:** the P-384 curve: ES384 (RFC 7518 §3.4), the Diffie-Hellman of JWE ECDH-ES
  (RFC 7518 §4.6) and the on-curve and scalar-range checks of `crv` `P-384` JWKs.
- **Audit status:** no public independent audit found.

### `p521`

- **Upstream:** RustCrypto,
  [RustCrypto/elliptic-curves](https://github.com/RustCrypto/elliptic-curves)
  ([crates.io](https://crates.io/crates/p521))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.14.0
- **Used for:** the P-521 curve: ES512 (RFC 7518 §3.4), the Diffie-Hellman of JWE ECDH-ES
  (RFC 7518 §4.6) and the on-curve and scalar-range checks of `crv` `P-521` JWKs.
- **Audit status:** no public independent audit found.

### `k256`

- **Upstream:** RustCrypto,
  [RustCrypto/elliptic-curves](https://github.com/RustCrypto/elliptic-curves)
  ([crates.io](https://crates.io/crates/k256))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.14.0
- **Used for:** the secp256k1 curve: ES256K (RFC 8812 §3.2) and the on-curve and scalar-range checks
  of `crv` `secp256k1` JWKs.
- **Audit status:** audited by NCC Group in 2023 (for Entropy): two high-severity findings, both
  fixed. polyjose pins 0.14.0, which postdates the audit.

### `ecdsa`

- **Upstream:** RustCrypto, [RustCrypto/signatures](https://github.com/RustCrypto/signatures)
  ([crates.io](https://crates.io/crates/ecdsa))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.17.0
- **Used for:** not used directly. The ECDSA algorithm (FIPS 186-5) behind the `SigningKey`,
  `VerifyingKey` and `Signature` types the four curve crates re-export.
- **Audit status:** not in the ADR 0019 register; a dependency of `p256`, `p384`, `p521` and `k256`.

### `rfc6979`

- **Upstream:** RustCrypto, [RustCrypto/signatures](https://github.com/RustCrypto/signatures)
  ([crates.io](https://crates.io/crates/rfc6979))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.6.0
- **Used for:** not used directly. `ecdsa` derives its nonces with it (RFC 6979), hedged with fresh
  randomness from the OS (RFC 6979 §3.6).
- **Audit status:** not in the ADR 0019 register; a dependency of `ecdsa`.

### `elliptic-curve`

- **Upstream:** RustCrypto, [RustCrypto/traits](https://github.com/RustCrypto/traits)
  ([crates.io](https://crates.io/crates/elliptic-curve))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.14.3
- **Used for:** not used directly. The traits and types the curve crates share: points, scalars,
  public and secret keys and their validation.
- **Audit status:** not in the ADR 0019 register; a dependency of the four curve crates and `ecdsa`.

### `primeorder`

- **Upstream:** RustCrypto,
  [RustCrypto/elliptic-curves](https://github.com/RustCrypto/elliptic-curves)
  ([crates.io](https://crates.io/crates/primeorder))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.14.0
- **Used for:** not used directly. Complete addition formulas for the prime-order short Weierstrass
  curves.
- **Audit status:** not in the ADR 0019 register; a dependency of the four curve crates.

### `primefield`

- **Upstream:** RustCrypto,
  [RustCrypto/elliptic-curves](https://github.com/RustCrypto/elliptic-curves)
  ([crates.io](https://crates.io/crates/primefield))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.14.0
- **Used for:** not used directly. The prime-field arithmetic of the curve crates.
- **Audit status:** not in the ADR 0019 register; a dependency of `p256`, `p384`, `p521`,
  `primeorder` and `wnaf`.

### `ff`

- **Upstream:** zkcrypto, [zkcrypto/ff](https://github.com/zkcrypto/ff)
  ([crates.io](https://crates.io/crates/ff))
- **License:** MIT/Apache-2.0
- **Version:** 0.14.0
- **Used for:** not used directly. The finite-field traits behind the curve crates' field and scalar
  types.
- **Audit status:** not in the ADR 0019 register; a dependency of `elliptic-curve`, `group`,
  `primefield` and `wnaf`.

### `group`

- **Upstream:** zkcrypto, [zkcrypto/group](https://github.com/zkcrypto/group)
  ([crates.io](https://crates.io/crates/group))
- **License:** MIT/Apache-2.0
- **Version:** 0.14.0
- **Used for:** not used directly. The elliptic-curve group traits behind the curve crates' point
  types.
- **Audit status:** not in the ADR 0019 register; a dependency of `elliptic-curve` and `wnaf`.

### `wnaf`

- **Upstream:** RustCrypto,
  [RustCrypto/elliptic-curves](https://github.com/RustCrypto/elliptic-curves)
  ([crates.io](https://crates.io/crates/wnaf))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.14.1
- **Used for:** not used directly. Windowed non-adjacent-form scalar multiplication for `k256` and
  `primeorder`.
- **Audit status:** not in the ADR 0019 register; a dependency of `k256` and `primeorder`.

### `crypto-bigint`

- **Upstream:** RustCrypto, [RustCrypto/crypto-bigint](https://github.com/RustCrypto/crypto-bigint)
  ([crates.io](https://crates.io/crates/crypto-bigint))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.7.11
- **Used for:** not used directly. Constant-time big-integer arithmetic under the curve crates'
  fields and scalars and under `rsa`.
- **Audit status:** reviewed by NCC Group in 2023 (for Entropy), in the same review as `k256`, on
  the 0.5 line; polyjose pins 0.7.11, a later line that has diverged significantly since. A
  dependency of `elliptic-curve`, `primefield`, `rfc6979` and `rsa`.

### `cpubits`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/cpubits))
- **License:** MIT OR Apache-2.0
- **Version:** 0.1.1
- **Used for:** not used directly. Selects the 32- or 64-bit limb size of `crypto-bigint` and `k256`
  for the target at compile time.
- **Audit status:** not in the ADR 0019 register; a dependency of `crypto-bigint` and `k256`.

### `num-traits`

- **Upstream:** rust-num, [rust-num/num-traits](https://github.com/rust-num/num-traits)
  ([crates.io](https://crates.io/crates/num-traits))
- **License:** MIT OR Apache-2.0
- **Version:** 0.2.19
- **Used for:** not used directly. Generic numeric traits that `crypto-bigint` implements.
- **Audit status:** not in the ADR 0019 register; a dependency of `crypto-bigint`.

### `sec1`

- **Upstream:** RustCrypto, [RustCrypto/formats](https://github.com/RustCrypto/formats)
  ([crates.io](https://crates.io/crates/sec1))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.8.1
- **Used for:** not used directly. The SEC1 point encoding that the curve crates build public keys
  from (`x` and `y` of an `EC` JWK become an uncompressed SEC1 point).
- **Audit status:** not in the ADR 0019 register; a dependency of `elliptic-curve`.

### `der`

- **Upstream:** RustCrypto, [RustCrypto/formats](https://github.com/RustCrypto/formats)
  ([crates.io](https://crates.io/crates/der))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.8.3
- **Used for:** not used directly. ASN.1 DER types of `ecdsa` and `sec1`; polyjose writes JWS
  signatures as fixed-length R‖S (RFC 7518 §3.4), never DER.
- **Audit status:** not in the ADR 0019 register; a dependency of `ecdsa` and `sec1`.

### `base16ct`

- **Upstream:** RustCrypto, [RustCrypto/formats](https://github.com/RustCrypto/formats)
  ([crates.io](https://crates.io/crates/base16ct))
- **License:** Apache-2.0 OR MIT
- **Version:** 1.0.0
- **Used for:** not used directly. Constant-time hex encoding inside `elliptic-curve`, `sec1` and
  `p521`.
- **Audit status:** not in the ADR 0019 register; a dependency of `elliptic-curve`, `sec1` and
  `p521`.

### `signature`

- **Upstream:** RustCrypto, [RustCrypto/traits](https://github.com/RustCrypto/traits)
  ([crates.io](https://crates.io/crates/signature))
- **License:** Apache-2.0 OR MIT
- **Version:** 3.0.0
- **Used for:** the RustCrypto `Signer`, `Verifier` and `RandomizedSigner` traits that ECDSA and
  EdDSA signing and ECDSA, EdDSA and RSA verification go through (re-exported by the curve crates).
- **Audit status:** not in the ADR 0019 register; a dependency of `ecdsa`, `ed25519` and `rsa`.

### `rand_core`

- **Upstream:** rust-random, [rust-random/rand_core](https://github.com/rust-random/rand_core)
  ([crates.io](https://crates.io/crates/rand_core))
- **License:** MIT OR Apache-2.0
- **Version:** 0.10.1
- **Used for:** the `TryRng`/`TryCryptoRng` traits that hand the OS random source (`getrandom`) to
  hedged ECDSA signing (ADR 0005), reached through the primitives' re-export.
- **Audit status:** not in the ADR 0019 register; a dependency of `elliptic-curve`, `crypto-bigint`,
  `signature`, `rsa` and others.

### `hkdf`

- **Upstream:** RustCrypto, [RustCrypto/KDFs](https://github.com/RustCrypto/KDFs)
  ([crates.io](https://crates.io/crates/hkdf))
- **License:** MIT OR Apache-2.0
- **Version:** 0.13.0
- **Used for:** not used directly. HKDF (RFC 5869), which `elliptic-curve`'s `ecdh` feature brings
  for its shared-secret type. JWE derives keys with the Concat KDF instead (RFC 7518 §4.6.2), which
  polyjose writes on `sha2`.
- **Audit status:** not in the ADR 0019 register; a dependency of `elliptic-curve` (with `ecdh`).

## RSA

### `rsa`

- **Upstream:** RustCrypto, [RustCrypto/RSA](https://github.com/RustCrypto/RSA)
  ([crates.io](https://crates.io/crates/rsa))
- **License:** MIT OR Apache-2.0
- **Version:** 0.10.0
- **Used for:** RS256/384/512 and PS256/384/512 signing and verification (RFC 7518 §3.3, §3.5),
  and RSA-OAEP-256 encryption and decryption (RFC 7518 §4.3), with RSA private keys polyjose
  imports itself (RFC 7518 §6.3.2, PKCS#8, PKCS#1). It is built with the `pkcs1v15` feature only.
  Private-key operations go only through rsa's blinded entry points, with randomness from
  polyjose's OS CSPRNG source (ADR 0005, ADR 0067). polyjose does not generate RSA keys or use
  RSA1_5 or SHA-1; `scripts/check-deps.sh` and `scripts/check-rsa-symbols.sh` reject those.
- **Audit status:** audited by Include Security in 2019 (one minor finding, per its README), before
  RUSTSEC-2023-0071 (the "Marvin" timing leak in private-key operations). 0.10.0 is the first
  release the advisory lists as patched. The constant-time 0.10 rewrite has no public independent
  audit; upstream checks its constant-time code with BINSEC (`cargo checkct`), and polyjose runs
  its own dudect-style timing test of RSA-OAEP-256 decryption and RSA signing. There is no
  Marvin-toolkit run.

### `crypto-primes`

- **Upstream:** Entropy, [entropyxyz/crypto-primes](https://github.com/entropyxyz/crypto-primes)
  ([crates.io](https://crates.io/crates/crypto-primes))
- **License:** Apache-2.0 OR MIT
- **Version:** 0.7.2
- **Used for:** not used. Prime generation and primality testing for `rsa`'s key generation, a
  non-optional dependency of `rsa`; polyjose generates no RSA keys.
- **Audit status:** not in the ADR 0019 register; a dependency of `rsa`.

## EdDSA

### `ed25519-dalek`

- **Upstream:** dalek-cryptography,
  [dalek-cryptography/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
  ([crates.io](https://crates.io/crates/ed25519-dalek))
- **License:** BSD-3-Clause
- **Version:** 3.0.0
- **Used for:** EdDSA over Ed25519 (RFC 8032, RFC 8037 §3.1) and the decoding and small-order checks
  of `crv` `Ed25519` JWKs (ADR 0041 §4). Its `zeroize` feature wipes the signing key on drop.
- **Audit status:** audited by Quarkslab in 2019 (for Tari), together with `curve25519-dalek`: minor
  issues only, but `ed25519-dalek` was reviewed only marginally. RUSTSEC-2022-0093 (double public
  key oracle, fixed in 2.0) and a scalar timing fix came later; polyjose pins 3.0.0.

### `ed25519`

- **Upstream:** RustCrypto, [RustCrypto/signatures](https://github.com/RustCrypto/signatures)
  ([crates.io](https://crates.io/crates/ed25519))
- **License:** Apache-2.0 OR MIT
- **Version:** 3.0.0
- **Used for:** not used directly. The Ed25519 signature type that `ed25519-dalek` uses.
- **Audit status:** not in the ADR 0019 register; a dependency of `ed25519-dalek`.

### `x25519-dalek`

- **Upstream:** dalek-cryptography,
  [dalek-cryptography/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
  ([crates.io](https://crates.io/crates/x25519-dalek))
- **License:** BSD-3-Clause
- **Version:** 3.0.0
- **Used for:** X25519 (RFC 7748) for the OKP `X25519` curve (RFC 8037 §2): deriving the public `x`
  of a generated key (RFC 7748 §6.1) and, for JWE, ECDH-ES key agreement (RFC 8037 §3.2). Its
  `static_secrets` feature provides the reusable private key a JWK holds, and `zeroize` wipes it on
  drop.
- **Audit status:** audited by Quarkslab in 2019 (for Tari), together with `curve25519-dalek`, but
  reviewed only marginally. polyjose pins 3.0.0, which postdates the audit.

### `curve25519-dalek`

- **Upstream:** dalek-cryptography,
  [dalek-cryptography/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
  ([crates.io](https://crates.io/crates/curve25519-dalek))
- **License:** BSD-3-Clause
- **Version:** 5.0.0
- **Used for:** not used directly. The Curve25519 group and field arithmetic under `ed25519-dalek`
  and `x25519-dalek`. Its build script picks the arithmetic backend from the target and the compiler
  version, and on x86_64 it generates its SIMD backends with `curve25519-dalek-derive`.
- **Audit status:** audited by Quarkslab in 2019 (for Tari): minor issues only. polyjose pins 5.0.0,
  which postdates the audit.

### `fiat-crypto`

- **Upstream:** mit-plv, [mit-plv/fiat-crypto](https://github.com/mit-plv/fiat-crypto)
  ([crates.io](https://crates.io/crates/fiat-crypto))
- **License:** MIT OR Apache-2.0 OR BSD-1-Clause
- **Version:** 0.3.0
- **Used for:** not used by default. Formally verified field arithmetic, compiled only when the
  builder selects the `fiat` backend of `curve25519-dalek` or `p384` with a `--cfg` (ADR 0025).
- **Audit status:** not in the ADR 0019 register; an optional dependency of `curve25519-dalek` and
  `p384`.

## Build time only

These crates run on the builder's machine while polyjose compiles and link nothing into it. Each
may be reached only through one parent crate, which `scripts/check-deps.sh` checks (ADR 0025,
ADR 0042).

### `curve25519-dalek-derive`

- **Upstream:** dalek-cryptography,
  [dalek-cryptography/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
  ([crates.io](https://crates.io/crates/curve25519-dalek-derive))
- **License:** MIT/Apache-2.0
- **Version:** 0.1.1
- **Used for:** compile time only, on x86_64 targets: the procedural macro that generates
  `curve25519-dalek`'s AVX2 and AVX-512 backends. It links nothing into polyjose.
  `scripts/check-deps.sh` fails if it is reached other than through `curve25519-dalek` (ADR 0025).
- **Audit status:** not in the ADR 0019 register; a proc-macro dependency of `curve25519-dalek`.

### `syn`

- **Upstream:** [dtolnay/syn](https://github.com/dtolnay/syn)
  ([crates.io](https://crates.io/crates/syn))
- **License:** MIT OR Apache-2.0
- **Version:** 2.0.119
- **Used for:** compile time only: the Rust parser of `curve25519-dalek-derive`. Allowed only below
  that crate (ADR 0025).
- **Audit status:** not in the ADR 0019 register; a dependency of `curve25519-dalek-derive`.

### `quote`

- **Upstream:** [dtolnay/quote](https://github.com/dtolnay/quote)
  ([crates.io](https://crates.io/crates/quote))
- **License:** MIT OR Apache-2.0
- **Version:** 1.0.47
- **Used for:** compile time only: code generation in `curve25519-dalek-derive`. Allowed only below
  that crate (ADR 0025).
- **Audit status:** not in the ADR 0019 register; a dependency of `curve25519-dalek-derive` and
  `syn`.

### `proc-macro2`

- **Upstream:** [dtolnay/proc-macro2](https://github.com/dtolnay/proc-macro2)
  ([crates.io](https://crates.io/crates/proc-macro2))
- **License:** MIT OR Apache-2.0
- **Version:** 1.0.107
- **Used for:** compile time only: the token types of `curve25519-dalek-derive`, `syn` and `quote`.
  Allowed only below `curve25519-dalek-derive` (ADR 0025).
- **Audit status:** not in the ADR 0019 register; a dependency of `curve25519-dalek-derive`, `syn`
  and `quote`.

### `unicode-ident`

- **Upstream:** [dtolnay/unicode-ident](https://github.com/dtolnay/unicode-ident)
  ([crates.io](https://crates.io/crates/unicode-ident))
- **License:** (MIT OR Apache-2.0) AND Unicode-3.0
- **Version:** 1.0.27
- **Used for:** compile time only: identifier classification for `proc-macro2` and `syn`. Allowed
  only below `curve25519-dalek-derive` (ADR 0025).
- **Audit status:** not in the ADR 0019 register; a dependency of `proc-macro2` and `syn`.

### `rustc_version`

- **Upstream:** [djc/rustc-version-rs](https://github.com/djc/rustc-version-rs)
  ([crates.io](https://crates.io/crates/rustc_version))
- **License:** MIT OR Apache-2.0
- **Version:** 0.4.1
- **Used for:** build time only: `curve25519-dalek`'s build script reads the compiler version with
  it. Allowed only below `curve25519-dalek` (ADR 0042).
- **Audit status:** not in the ADR 0019 register; a build-dependency of `curve25519-dalek`.

### `semver`

- **Upstream:** [dtolnay/semver](https://github.com/dtolnay/semver)
  ([crates.io](https://crates.io/crates/semver))
- **License:** MIT OR Apache-2.0
- **Version:** 1.0.28
- **Used for:** build time only: version parsing for `rustc_version`. Allowed only below
  `curve25519-dalek` (ADR 0042).
- **Audit status:** not in the ADR 0019 register; a dependency of `rustc_version`.

### `autocfg`

- **Upstream:** [cuviper/autocfg](https://github.com/cuviper/autocfg)
  ([crates.io](https://crates.io/crates/autocfg))
- **License:** Apache-2.0 OR MIT
- **Version:** 1.5.1
- **Used for:** build time only: `num-traits`' build script probes compiler features with it.
  Allowed only below `num-traits` (ADR 0042).
- **Audit status:** not in the ADR 0019 register; a build-dependency of `num-traits`.

## Randomness

### `getrandom`

- **Upstream:** rust-random, [rust-random/getrandom](https://github.com/rust-random/getrandom)
  ([crates.io](https://crates.io/crates/getrandom))
- **License:** MIT OR Apache-2.0
- **Version:** 0.4.3
- **Used for:** the operating system's cryptographically secure random number generator, polyjose's
  only source of randomness (ADR 0005), through `getrandom::fill`.
- **Audit status:** no public independent audit found.

### `cfg-if`

- **Upstream:** The Rust Project, [rust-lang/cfg-if](https://github.com/rust-lang/cfg-if)
  ([crates.io](https://crates.io/crates/cfg-if))
- **License:** MIT OR Apache-2.0
- **Version:** 1.0.5
- **Used for:** not used directly. `getrandom`, `sha2` and `curve25519-dalek` use it to select
  per-platform code at compile time.
- **Audit status:** not in the ADR 0019 register; a dependency of `getrandom`, `sha2` and
  `curve25519-dalek`.

### `libc`

- **Upstream:** The Rust Project, [rust-lang/libc](https://github.com/rust-lang/libc)
  ([crates.io](https://crates.io/crates/libc))
- **License:** MIT OR Apache-2.0
- **Version:** 0.2.191
- **Used for:** not used directly. On Unix-like systems `getrandom` calls the operating system's
  random source through it, and on some aarch64 and loongarch64 targets `cpufeatures` uses it to
  detect CPU features.
- **Audit status:** not in the ADR 0019 register; a dependency of `getrandom` and `cpufeatures`.

### `r-efi`

- **Upstream:** [r-efi/r-efi](https://github.com/r-efi/r-efi)
  ([crates.io](https://crates.io/crates/r-efi))
- **License:** MIT OR Apache-2.0 OR LGPL-2.1-or-later
- **Version:** 6.0.0
- **Used for:** not used directly. `getrandom`'s UEFI backend; it is compiled only for UEFI targets
  that select that backend.
- **Audit status:** not in the ADR 0019 register; a dependency of `getrandom`.

## Constant-time operations and secret wiping

### `subtle`

- **Upstream:** dalek-cryptography,
  [dalek-cryptography/subtle](https://github.com/dalek-cryptography/subtle)
  ([crates.io](https://crates.io/crates/subtle))
- **License:** BSD-3-Clause
- **Version:** 2.6.1
- **Used for:** constant-time choices and comparisons (`Choice`, `ConstantTimeEq`), for example in
  polyjose's base64url decoder, which handles secret input. The curve crates, `crypto-bigint` and
  the dalek crates use it for their own constant-time code.
- **Audit status:** reviewed by Quarkslab in 2019 (for Tari), as part of its review of the
  dalek libraries: it found no trivial time leak in the source or its compiled assembly. That
  review predates the 2.6.1 that polyjose pins.

### `zeroize`

- **Upstream:** RustCrypto, [RustCrypto/utils](https://github.com/RustCrypto/utils)
  ([crates.io](https://crates.io/crates/zeroize))
- **License:** Apache-2.0 OR MIT
- **Version:** 1.9.1
- **Used for:** wiping key material and other secrets from memory when they are dropped
  (`Zeroize`, `Zeroizing`). `digest` and its `block-buffer` (under `sha2` and `hmac`) also use it
  to wipe the hash state and buffered input, and the curve crates, `crypto-bigint` and the dalek
  crates to wipe secret scalars and signing keys.
- **Audit status:** no public independent audit found.

## Binding frameworks

The language bindings are built with these frameworks. They are not dependencies of the core
crate, so `scripts/check-deps.sh` does not check this section. Versions are from `Cargo.lock`.

| Framework | Crates | Version | Used by | License |
|---|---|---|---|---|
| [napi-rs](https://github.com/napi-rs/napi-rs) | `napi`, `napi-derive`, `napi-build` | 3.16.1, 3.7.0, 2.6.0 | `bindings/node` (Node.js addon) | MIT |
| [wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen) | `wasm-bindgen` | 0.2.130 | `bindings/wasm` (WebAssembly package) | MIT OR Apache-2.0 |
| [UniFFI](https://github.com/mozilla/uniffi-rs) | `uniffi` | 0.32.2 | `bindings/ffi` (Kotlin and Swift) and `bindings/uniffi-bindgen` | MPL-2.0 |
