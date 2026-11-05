//! polyjose's own JSON: RFC 8259 with the I-JSON constraints of RFC 7493.

mod number;
mod value;

pub use number::{MAX_SAFE_INTEGER, Number};
pub use value::{IntoIter, Iter, Object, Value};
