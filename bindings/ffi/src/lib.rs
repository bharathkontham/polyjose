//! polyjose-ffi: the UniFFI adapter shared by the Kotlin and Swift bindings (ADR 0030 §1,
//! ADR 0032, ADR 0033).
//!
//! A mechanical adapter over `polyjose-surface`: every export is a type conversion and one
//! surface call, with no JSON parsing, policy, defaults or crypto of its own (ADR 0030 §1, "the
//! adapter test").
//!
//! - [`error`]: [`PolyjoseError`], one variant per stable code, with the exported `code()` and
//!   `Display` (ADR 0030 §5);
//! - [`records`]: the `uniffi::Record` mirrors of the surface records (ADR 0030 §3);
//! - [`util`]: `version`, `error_codes`, `base64url_encode`, `base64url_decode` and the
//!   unverified decode utilities of ADR 0069;
//! - [`jwk`], [`keys`], [`jws`], [`jwe`], [`jwt`]: the operations (feature 0013 T12), among them
//!   the six `…_with_platform_key` operations, Kotlin and Swift only (ADR 0071 §5);
//! - [`platform_key`]: [`PlatformKey`], the foreign interface host code implements for a key the
//!   platform holds, and [`PlatformKeyError`] (ADR 0071 §5), with the copies of the signing
//!   input, Z and the CEK that each call leaves (ADR 0071 §8).
//!
//! The Kotlin and Swift sources are generated from the built library by the separate
//! `polyjose-uniffi-bindgen` package, with the names in `uniffi.toml` (ADR 0032 §2, ADR 0033).
//! Secret-bearing inputs are moved into `Zeroizing` owners in each export's first statement
//! (ADR 0030 §7.1). `unsafe` exists only in the scaffolding UniFFI generates.

#![forbid(unsafe_code)]

uniffi::setup_scaffolding!();

pub mod error;
pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod keys;
pub mod platform_key;
pub mod records;
pub mod util;

pub use error::PolyjoseError;
pub use platform_key::{PlatformKey, PlatformKeyError};
