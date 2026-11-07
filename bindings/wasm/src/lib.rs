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
//! it into `Zeroizing` in its first statements, so it is wiped on return (measured: no copy left).
//! A borrowed `&str` would leave a freed, unwiped copy, so it is used only for registered
//! identifiers (`alg`, `crv`, `format`, `form`, `hash`). Keys and secret bytes inside records are
//! read straight into the surface's `SecretString`/`SecretBytes`. Results that may hold a secret
//! are copied into the JS value from a borrowed, zeroizing buffer (`JsString::from(&str)`,
//! `Uint8Array::from(&[u8])`); only public results (the version, codes, a public JWK, thumbprints,
//! JWE ciphertext) return an owned `String`. Copies on the JS side are outside Rust's reach
//! (ADR 0030 §7.4). Nothing is logged (ADR 0030 §7.5). `src/rules.rs` checks these rules on the
//! source.
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

pub mod jwk;
pub mod keys;
pub mod util;
