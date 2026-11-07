#![forbid(unsafe_code)]
//! polyjose-surface: the binding API of polyjose, defined once in plain Rust (ADR 0030 §1).

pub mod error;
pub mod secret;
pub mod util;

pub use error::{SurfaceError, SurfaceResult};
pub use secret::{SecretBytes, SecretString};
