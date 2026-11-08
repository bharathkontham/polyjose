#![forbid(unsafe_code)]
//! polyjose-surface: the binding API of polyjose, defined once in plain Rust (ADR 0030).
//!
//! Every operation, record and result that the bindings expose (WASM and Node through the shared
//! JS facade, Kotlin and Swift through UniFFI) is declared here, framework-free. Each binding
//! crate is a mechanical adapter: one exported function per surface operation, framework records
//! converted with `From`, and the error mapped by its code (ADR 0030 §1, "the adapter test").
//!
//! | Layer | Crate | Holds |
//! |---|---|---|
//! | Core | `polyjose` | JOSE, crypto, JSON, every default |
//! | **Surface** | `polyjose-surface` | operations, records, [`SurfaceError`], secret owners |
//! | Adapters | `polyjose-wasm`, `polyjose-node`, `polyjose-ffi` | type conversion only |
//!
//! # The API (ADR 0030 §4)
//!
//! Flat, prefixed functions, so every platform has the same names after its usual case
//! conversion (ADR 0030 option B1), grouped in one module per prefix:
//!
//! - [`util`]: `version`, `error_codes`, `base64url_encode`, `base64url_decode` (RFC 4648 §5);
//! - [`jwk`]: `jwk_parse`, `jwk_to_public`, `jwk_thumbprint`, `jwk_thumbprint_uri`,
//!   `jwks_select` (RFC 7517, RFC 7638, RFC 9278);
//! - [`keys`]: `jwk_generate_*`, `jwk_from_pem`/`_der`, `jwk_to_pem`/`_der` (RFC 7518 §6,
//!   RFC 8037, RFC 7468, RFC 5958, RFC 5280);
//! - [`jws`]: `jws_sign_*`, `jws_verify_*` (RFC 7515);
//! - [`jwe`]: `jwe_encrypt_*`, `jwe_decrypt_*` (RFC 7516, RFC 7518);
//! - [`jwt`]: `jwt_sign`, `jwt_verify*`, `jwt_encrypt_nested`, `jwt_decrypt_nested*`
//!   (RFC 7519, RFC 8725, RFC 9068).
//!
//! The options and results are in [`records`]. Keys, headers and claims are JSON text, parsed and
//! written by the core's own I-JSON code (no serde, ADR 0016). Algorithm, curve, hash and format
//! names are the registered strings (ADR 0030 option D1).
//!
//! # Security rules the surface keeps (ADR 0030 §3, §5–§7)
//!
//! - **No defaults of its own.** A `None` tunable or a `false` flag calls no core setter, so
//!   every default is the core's; allow-lists are required (ADR 0007, RFC 8725 §3.1).
//! - **Only core error codes.** [`SurfaceError`] is built only from a [`polyjose::Error`], so a
//!   binding cannot invent a code or put input in a message.
//! - **Secrets are wiped.** Secret inputs are borrowed (`&str`, `&[u8]`) and never copied by the
//!   surface; secret results and record fields are [`SecretString`]/[`SecretBytes`], which
//!   zeroize on drop and redact `Debug` (ADR 0030 §7, ADR 0049 §4, ADR 0050 §4).
//! - **No logging,** and `#![forbid(unsafe_code)]`.
//!
//! The surface builds without the core's `deflate` feature, as every binding ships (ADR 0030
//! §4, ADR 0034 §3).
//!
//! ```
//! use polyjose_surface::util;
//!
//! assert_eq!(util::base64url_encode(b"foobar"), "Zm9vYmFy");
//! let err = util::base64url_decode("Zm9vYmFy==").unwrap_err();
//! assert_eq!(err.code(), "InvalidBase64");
//! assert!(util::error_codes().contains(&err.code()));
//! ```

pub mod error;
pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod keys;
pub mod records;
pub mod secret;
pub mod util;

pub use error::{SurfaceError, SurfaceResult};
pub use secret::{SecretBytes, SecretString};
