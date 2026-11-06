//! JSON Web Token (RFC 7519): claims, the RFC 8725 validation policy, and
//! nested JWTs.

mod clock;
mod numeric_date;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use clock::SystemClock;
pub use clock::{Clock, FixedClock};
pub use numeric_date::NumericDate;
