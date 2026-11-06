//! JSON Web Token (RFC 7519): claims, the RFC 8725 validation policy, and
//! nested JWTs.

mod clock;
mod numeric_date;
// The pipeline modules below are wired together by the later tasks of
// feature 0004; until verify (T07) and nested (T09) call them, their
// crate-internal items have no caller. `allow`, not `expect`: each task
// fills in its own file and must not edit this one, and an `expect` would
// become an error as soon as the item is used. Remove these attributes
// once the feature's last code task has landed (as 0003 did in a5b789b).
#[allow(
    dead_code,
    reason = "the JWT skeleton (0004 T01): read once validate (T06) and verify (T07) land"
)]
mod policy;
pub mod typ;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use clock::SystemClock;
pub use clock::{Clock, FixedClock};
pub use numeric_date::NumericDate;
pub use policy::{Policy, TypMode};
