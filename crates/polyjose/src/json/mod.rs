//! polyjose's own JSON: RFC 8259 with the I-JSON constraints of RFC 7493.

mod number;
mod parse;
mod value;

pub use number::{MAX_SAFE_INTEGER, Number};
pub use parse::{Limits, parse, parse_with_limits};
pub use value::{IntoIter, Iter, Object, Value};
