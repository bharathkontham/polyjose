//! polyjose-wasm: the wasm-bindgen adapter behind `@polyjose/wasm` (ADR 0030 §1, ADR 0031 §3).
//!
//! A mechanical adapter over `polyjose-surface`: one `#[wasm_bindgen(js_name = …)]` export per
//! ADR 0030 §4 operation, named and ordered as the JS backend contract
//! (`bindings/js/BACKEND.md`), each body a type conversion and one surface call, with no JSON
//! parsing, policy, defaults or crypto of its own (ADR 0030 §1, "the adapter test"). The shared
//! TypeScript facade (`bindings/js`) wraps these exports into the public, Promise-returning API.
//!
//! - [`util`], [`jwk`], [`keys`], [`jws`], [`jwe`], [`jwt`]: the operations.
//! - `read`: plain JS option objects to surface records with `js_sys::Reflect`; a wrong type is a
//!   JS `TypeError` (ADR 0031 §3, "Records").
//! - `write`: surface results to plain JS objects with camelCase members.
//! - `error`: a core failure throws a `js_sys::Error` named `PolyjoseError` with the surface
//!   message and an own `code` property (ADR 0030 §5, 0006 research §2).
//!
//! # Secrets (ADR 0030 §7, ADR 0031 §3, 0006 research §3)
//!
//! Every JOSE data input (JWKs, JWK Sets, payloads, plaintext, claims, PEM and DER, tokens) is a
//! by-value `String` or `Vec<u8>`: Rust then owns the only wasm-memory copy, and the export moves
//! it into `Zeroizing` in its first statements, so it is wiped on return. A borrowed `&str` would
//! leave a freed, unwiped copy, so it is used only for registered identifiers (`alg`, `crv`,
//! `format`, `form`, `hash`). Keys and secret bytes inside records are read straight into the
//! surface's `SecretString`/`SecretBytes`. Results that may hold a secret are copied into the JS
//! value from a borrowed, zeroizing buffer (`JsString::from(&str)`, `Uint8Array::from(&[u8])`).
//! Only public results return an owned `String`: the version, codes, a public JWK, thumbprints and
//! serialized JWEs. Copies on the JS side are outside Rust's reach (ADR 0030 §7.4). Nothing is
//! logged (ADR 0030 §7.5). `src/rules.rs` checks these rules on the source.
//!
//! What a call leaves in wasm memory is regression-tested in `tests/memory.rs`. Its `KNOWN` table
//! lists every exception with its count, in Node and Chrome:
//!
//! - **No copy on the Rust heap**, with one exception: **JWT claims follow ADR 0058** (owner
//!   decision 2). They are plain text, so `jwtSign`, `jwtVerify*` and `jwtDecryptNested*` leave
//!   up to two unwiped copies of claim values.
//!
//!   The base64url(`aad`) in a `jweEncryptJson` result is **output token content** (RFC 7516
//!   §7.2.1), not residue: the JWE JSON Serialization carries the `aad` in the clear, and the
//!   serialized JWE, a public result, is returned as an owned `String`, so the token's own copy
//!   stays on the heap like any returned token. `KNOWN` asserts it all the same.
//! - **The wasm shadow stack is not scrubbed.** It shares linear memory with the heap (the low
//!   1 MiB, wasm-ld `--stack-first`), and the primitives' own frames keep fragments that
//!   `Zeroizing` never reaches. Examples are the HS256 key in full (review S2), 16 bytes of a new
//!   P-256 `d` and A128CBC-HS256 plaintext blocks after decryption (security audit L3). Others are
//!   AES and HMAC key blocks, SHA-2 blocks of the JWS signing input, and an X25519 scalar. Which
//!   ones occur depends on code generation. The core backlog (feature 0012) owns them.
//! - **Two framework edges** of the wasm-bindgen glue (review N7), outside the adapter's code:
//!   - **Non-ASCII strings.** `passStringToWasm0` writes a string's ASCII prefix into a block of
//!     the string's UTF-16 length. At the first non-ASCII character it grows the block with
//!     `realloc`. If the block moves, the old one is freed unwiped with the prefix in it. Whether
//!     it moves depends on the heap, so `tests/memory.rs` forces the move. Characters after the
//!     first non-ASCII one go only into the final block, which the export wipes.
//!   - **A later argument fails to convert.** The glue frees the strings it already passed with
//!     a plain `__wbindgen_free`, unwiped. An example is `jwtDecryptNested`'s `decryptKey`, when a
//!     later argument is not a string. Only a caller that bypasses the facade can reach this: the
//!     facade checks every argument's type before the call (BACKEND.md, "Inputs are taken at
//!     the call").
//!
//! # Clock (ADR 0028, ADR 0030 §4)
//!
//! `SystemTime::now()` panics on `wasm32-unknown-unknown`; this adapter never reads a clock. The
//! facade passes JWT `now` on every call and it reaches the surface as given.
//!
//! `unsafe` exists only in the glue wasm-bindgen generates.

#![forbid(unsafe_code)]

mod error;
mod read;
mod write;

pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod keys;
pub mod util;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod rules;
