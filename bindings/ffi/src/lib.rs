//! polyjose-ffi: the UniFFI adapter shared by the Kotlin and Swift bindings (ADR 0030 §1,
//! ADR 0032, ADR 0033).

#![forbid(unsafe_code)]

uniffi::setup_scaffolding!();

pub mod error;
pub mod util;

pub use error::PolyjoseError;
