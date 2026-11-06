# JWE conformance vectors

This is the index of the JWE vectors (RFC 7516, RFC 7518 §4–§5, RFC 7520 §5). Each `*.json` file is one vector in the format of [`../../README.md`](../../README.md) and [`../../schema.json`](../../schema.json); this file and the `rsa-oaep-256/keys/*.jwk` files are not vectors, so the runners skip them.

- **Features.** A vector that lists `"fixed-rng"` needs the cargo feature `insecure-test-vectors` (ADR 0041 §3), and one that lists `"deflate"` needs `deflate` (ADR 0017). A build without them reports the vector SKIPPED by name and never counts it as passing. The bindings never enable `fixed-rng`, so every RFC output reproduced by a `fixed-rng` `jwe.encrypt` vector also has a `jwe.decrypt` vector that every platform runs.
- **Where the values come from.** RFC 7520 values are generated from the vendored ietf-jose cookbook (`crates/polyjose/tests/third_party/ietf-jose-cookbook/`), RFC 7516 and RFC 7517 values from the RFC text, and every other token by Node's built-in crypto (OpenSSL) or Python's standard library, independently of polyjose. Nothing is transcribed by hand. The generators are in [`../../tools/jwe/`](../../tools/jwe/) and are listed in [`../../README.md`, Tools](../../README.md#tools).
- **Notices.** The RFC 7520 values are covered by [`../third_party/rfc7520/NOTICE.md`](../third_party/rfc7520/NOTICE.md), which lists these directories; the vendored cookbook keeps its own Unlicense notice in [`../../../crates/polyjose/tests/third_party/ietf-jose-cookbook/`](../../../crates/polyjose/tests/third_party/ietf-jose-cookbook/README.md).

## Directories

| Directory | Files | `source` values | Features | Generator |
|---|---|---|---|---|
| `compact/` | 12 (4 decrypt, 8 encrypt) | RFC 7516 App. A.3; RFC 7520 §5.6, §5.8; `polyjose` (round trips, AAD) | 3 `fixed-rng` | T09, historical |
| `negative-structure/` | 48 (39 decrypt, 9 encrypt) | `polyjose` (the plan.md error contract, one rule per file); RFC 7516 App. A.1, A.2 and RFC 7520 §5.1, §5.2 (RSA-OAEP and RSA1_5 refused) | 1 `fixed-rng` | T09, historical |
| `gcmkw/` | 29 (22 decrypt, 7 encrypt) | RFC 7520 §5.7; RFC 7518 §4.7.1 (iv and tag in the per-recipient header); `polyjose`; the Node/OpenSSL oracle | 2 `fixed-rng` | `t10-gcmkw.mjs` (24), `t18-cross-family.mjs` (5) |
| `rsa-oaep-256/` | 15 (3 decrypt, 12 encrypt) | the Node/OpenSSL oracle (`../../tools/rsa-oaep-oracle.mjs`); `polyjose` | 6 `fixed-rng` | `t11-rsa-oaep-256.mjs` (6); the other 9, historical |
| `pbes2/` | 27 (16 decrypt, 11 encrypt) | RFC 7520 §5.3; RFC 7517 App. C; RFC 7518 §4.8.1, §4.8.1.1, §4.8.1.2, §8.8; RFC 7516 §11.5; ADR 0023; ADR 0050 §2 (per-token budget, encrypt limits); `polyjose` | 2 `fixed-rng` | `t12-pbes2.py` (24), `f07-pbes2-budget.mjs` (3) |
| `ecdh-es/` | 39 (23 decrypt, 16 encrypt) | RFC 7520 §5.4, §5.5; `polyjose` (RFC 7518 App. C, X25519, P-521 known answers; `epk` negatives on P-256 and X25519) | 8 `fixed-rng` | `t13-ecdh-es.js` |
| `json/` | 30 (19 decrypt, 11 encrypt) | RFC 7516 App. A.4, A.5; RFC 7520 §5.6, §5.7 (erratum 4802), §5.8, §5.10, §5.11, §5.12; `polyjose` | 4 `fixed-rng` | `t14-json.py` (28), `t18-cross-family.mjs` (2) |
| `negative-json/` | 45 (39 decrypt, 6 encrypt) | `polyjose` (RFC 7516 §7.2 shape and header rules); RFC 7516 App. A.4; RFC 7520 §5.11 | none | `t14-json.py` |
| `zip/` | 13 (12 decrypt, 1 encrypt) | RFC 7520 §5.9 (compact, flattened, general); `polyjose` (bound, bomb, malformed DEFLATE) | 13 `deflate` | `t15-zip.py` (11), `t18-cross-family.mjs` (2) |
| `rfc7520-multi/` | 6 (5 decrypt, 1 encrypt) | RFC 7520 §5.13 | 1 `fixed-rng` | `t18-cross-family.mjs` |
| `negative-crypto/` | 38 decrypt | RFC 7520 §5.3–§5.7, §5.13; `polyjose` (tokens built by the Node/OpenSSL oracle) | none | `t18-cross-family.mjs` |
| `negative-cross-mode/` | 20 decrypt (11 InvalidHeader, 1 DecryptionFailed, 8 positive controls) | ADR 0050 §1 (security audit B1; tokens built by the Node/OpenSSL oracle, plus the audit's forged token verbatim) | none | `f06-cross-mode.mjs` |

That is 316 files: 237 `jwe.decrypt`, 79 `jwe.encrypt`; 27 need `fixed-rng` and 13 need `deflate`.

## `rfc7520-multi/`: RFC 7520 §5.13

The general JSON JWE to three recipients (RSA1_5, ECDH-ES+A256KW on P-384, A256GCMKW) with a shared unprotected `cty`:

- recipient #2's EC key decrypts it as `recipient` 1, recipient #3's AES key as `recipient` 2;
- recipient #1's RSA key alone is `UnsupportedAlgorithm` (RSA1_5 is not implemented, ADR 0022, and nothing else fits an RSA key);
- the EC key with only `A256GCMKW` allowed is `AlgorithmNotAllowed`, and a flipped tag is `DecryptionFailed`;
- with `fixed-rng`, encrypting to recipients #2 and #3 with the RFC's draws reproduces the RFC output exactly, minus recipient #1.

## `negative-cross-mode/`: direct modes need a protected `alg` and `enc` (ADR 0050 §1)

A\*GCMKW wraps the CEK with AES-GCM under an empty AAD (RFC 7518 §4.7.1), and a JSON JWE with no protected header and no `aad` has the content AAD `""` too, so a GCMKW recipient's (`iv`, `encrypted_key`, `tag`) is a valid `dir` + A\*GCM ciphertext under the same key (security audit B1). polyjose therefore refuses `dir` and ECDH-ES (direct) with `InvalidHeader`, before any cryptography, unless both `alg` and `enc` are in the JWE Protected Header. Every negative here is a live token: without the rule each one decrypts, and each forgery returns the wrapped CEK.

| Case | Vectors | Expect |
|---|---|---|
| The audit's forged token (verbatim) | `audit-forged-gcmkw-as-dir` | InvalidHeader |
| The forgery in the per-recipient header, in the general form, and for A256GCMKW | `forged-gcmkw-as-dir-per-recipient-header`, `forged-gcmkw-as-dir-general`, `forged-a256gcmkw-as-dir-a256gcm` | InvalidHeader |
| An honest `dir` token with no protected header | `dir-no-protected-header` | InvalidHeader |
| The reverse relabel: that token presented as A128GCMKW. Not a direct mode, so the rule does not apply; it never decrypts | `reverse-relabel-dir-as-gcmkw` | DecryptionFailed |
| `dir` with only one of `alg` and `enc` protected | `dir-alg-shared-enc-protected`, `dir-alg-per-recipient-enc-protected`, `dir-alg-protected-enc-shared` | InvalidHeader |
| ECDH-ES (direct) with `alg` unprotected, P-256 and X25519 | `ecdh-es-p256-alg-shared`, `ecdh-es-x25519-alg-per-recipient`, `ecdh-es-x25519-general-alg-per-recipient` | InvalidHeader |
| Positive controls: protected direct tokens | `control-dir-compact-decrypts`, `control-dir-flattened-protected-decrypts`, `control-ecdh-es-{p256,x25519}-compact-decrypts` | decrypts |
| Positive controls: non-direct modes with an unprotected `alg` | `control-a128gcmkw-alg-unprotected-decrypts`, `control-a128kw-alg-per-recipient-decrypts`, `control-pbes2-alg-shared-decrypts`, `control-ecdh-es-a128kw-alg-per-recipient-decrypts` | decrypts |

Re-marked by ADR 0050 §1: `negative-json/tampered-unprotected-alg-dir-invalid-header.json` (formerly `tampered-unprotected-alg-decryption-failed.json`, which expected `DecryptionFailed`) is now `InvalidHeader`. No other vector decrypted a direct mode with `alg` or `enc` outside the protected header.

## `negative-crypto/`: cross-family negatives

Each case of the list is either here or in the directory named, and is not repeated.

| Case | Vectors |
|---|---|
| Tampered tag, ciphertext and IV for every `enc` | here: `dir-<enc>-tampered-{iv,ciphertext,tag}` for A128GCM (IV, ciphertext), A192GCM, A256GCM, A192CBC-HS384 and A256CBC-HS512, each with its untampered `dir-<enc>-decrypts`; A128CBC-HS256: `negative-structure/tampered-{tag,ciphertext,iv}.json`; the A128GCM tag: `negative-structure/dir-tampered-gcm-tag.json`; also `zip/rfc7520-5-9-bad-tag.json`, `negative-json/tampered-aad.json` |
| `alg` not allowed | here: `alg-not-allowed-{dir,a256gcmkw,pbes2-hs512-a256kw,ecdh-es-a128kw,ecdh-es}` and `rfc7520-multi/rfc7520-5-13-ec-key-alg-not-allowed.json`; A128KW: `negative-structure/alg-not-allowed.json`, `empty-allow-list.json`; JSON ranking: `negative-json/no-candidate-not-allowed-ranks-first.json` |
| `enc` not allowed | here: `enc-not-allowed-{a128gcm-dir,a128cbc-hs256-ecdh-es}`; `negative-structure/enc-not-allowed.json` |
| Invalid `epk` on each curve | P-384: here, `epk-p384-{not-on-curve,identity,coordinates-above-p,short-x}`; P-521: here, `epk-p521-{not-on-curve,identity,x-aliased-by-p,short-x}` with `ecdh-es-a256kw-p521-decrypts`; P-256: `ecdh-es/epk-{off-curve,identity,invalid-curve-point,twist-point,short-coordinate,private-d,missing,kty-mismatch,crv-mismatch}.json`; X25519: `ecdh-es/x25519-epk-ed25519.json` |
| X25519 low-order and all-zero | `ecdh-es/x25519-epk-low-order.json`, `ecdh-es/x25519-epk-zero.json` |
| `p2c` above the bound (10,001) | `pbes2/p2c-bound-plus-one.json`; also `pbes2/p2c-ceiling-plus-one.json`, `p2c-2pow32-minus-1.json`, `bound-below-count.json` |
| PBES2 budget per token, summed over candidates (ADR 0050 §2) | `pbes2/budget-16-recipients-over-default.json`, `budget-16-recipients-raised.json`, `budget-16-recipients-one-short.json`; encrypt limits: `encrypt-p2c-ceiling-plus-one.json`, `encrypt-p2s-len-257.json`, `roundtrip-pbes2-hs256-a128kw-p2s-len-256.json` |
| Missing and extra recipients | here: `rfc7520-5-13-recipient-for-key-removed`, `rfc7520-5-13-encrypted-key-removed`, `rfc7520-5-13-extra-forged-recipient-first`; `negative-json/recipients-empty.json`, `over-max-recipients.json`, `flattened-with-recipients.json`, `json/rfc7516-a4-general-failing-candidate-passed-over-decrypt.json` |
| RSA-OAEP, RSA-OAEP-256 and RSA1_5 on decrypt | RSA-OAEP: `negative-structure/rfc7516-a1-rsa-oaep-unsupported.json`, `rfc7520-5-2-rsa-oaep-unsupported.json`, `rsa-oaep-256/decrypt-rsa-oaep-sha1-unsupported.json`; RSA-OAEP-256: `negative-structure/rsa-oaep-256-decrypt-unsupported.json`, `rsa-oaep-256/decrypt-own-output-unsupported.json`, `decrypt-rsa-private-jwk-unsupported.json`; RSA1_5: `negative-structure/rfc7516-a2-rsa1-5-unsupported.json`, `rfc7520-5-1-rsa1-5-unsupported.json`, `rfc7520-multi/rfc7520-5-13-rsa-key-only-unsupported.json` |
| RSA-OAEP on encrypt | `rsa-oaep-256/encrypt-rsa-oaep-sha1-unsupported.json`; RSA1_5: `negative-structure/encrypt-rsa1-5-unsupported.json` |

## Documented omissions

These RFC outputs have a `jwe.decrypt` vector but no exact `jwe.encrypt` vector, by decision (plan.md, lead refinements 15 and 17). Each decrypt vector's `description` names the omission. No encrypt vector exists for them, so none is skipped.

- **RFC 7520 §5.11** (flattened, `alg` in the unprotected header): polyjose's encryptor always puts `alg` in the protected header for the flattened form (orchestrator decision, refinement 15).
- **RFC 7520 §5.8 and §5.10 in the general form**: the RFC keeps `alg` in the protected header; polyjose puts a non-direct `alg` in each recipient's header (refinement 17). Their flattened forms are exact.
- **RFC 7520 §5.6 in the general form**: `dir` is protected in every form (ADR 0050 §1), so the same draws reproduce the RFC's protected header, IV, ciphertext and tag; polyjose writes the one recipient as `"recipients":[{}]`, which the cookbook's output omits (`crates/polyjose/tests/jwe_json.rs`).
- **RFC 7520 §5.12, both forms**: there is no protected header; polyjose always protects `enc` and, when flattened, `alg` (refinement 17).
- **RFC 7516 App. A.5** (flattened, `alg` in the per-recipient header): polyjose protects it (refinement 17).

For these, tests show that the same `FixedRng` draws give the RFC's encrypted key, IV and ciphertext; only the header placement, and so the tag, differs (`crates/polyjose/tests/jwe_json.rs`).

Other outputs without an exact encrypt vector, for the reasons given:

- **RFC 7520 §5.9** (`zip`): DEFLATE output is not unique (erratum 7680), so `zip/roundtrip-a128kw-a128gcm-def.json` checks a round trip instead.
- **`compress` without `deflate`**: encrypting with `compress` in a build without the `deflate` feature is `UnsupportedAlgorithm` (ADR 0030 §4, ADR 0017 §5). A vector cannot express it: `features` only lists what a build needs, never a feature it must lack, and an `input/compress` vector must list `"deflate"`. `crates/polyjose/tests/jwe_zip.rs` (`without_deflate`) covers it instead, in every serialization; the `deflate` round trip stays in `zip/`.
- **RFC 7520 §5.1, §5.2 and RFC 7516 App. A.1, A.2, A.4** (RSA1_5, RSA-OAEP): not implemented (ADRs 0021, 0022); the decrypt vectors expect `UnsupportedAlgorithm` (A.4 decrypts through its A128KW recipient). **RFC 7520 §5.13** is reproduced without its RSA1_5 recipient.

Not yet covered by a vector: the JSON forms of RFC 7520 §5.3, §5.4 and §5.5 (their compact forms are in `pbes2/` and `ecdh-es/`), and §5.7 in the general form (flattened and compact are covered).
