//! Test-only support code shared by the crate's unit tests.
//!
//! The inner `#![cfg(test)]` keeps every item here out of non-test builds,
//! however the module is reached, and `lib.rs` declares it under
//! `#[cfg(test)]` as well. Nothing here is part of the public API.
#![cfg(test)]

pub(crate) mod wycheproof;
