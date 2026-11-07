//! The Kotlin and Swift error type (ADR 0030 §5, ADR 0032 §3, ADR 0033 §3).
//!
//! [`PolyjoseError`] has one variant per stable core code, in [`polyjose::Error::CODES`] order,
//! each with one field, `detail`, the core's `Display` text. UniFFI generates from it:
//!
//! - **Kotlin:** `sealed class PolyjoseException : Exception()` with one subclass per code
//!   (ADR 0033 §3). The field is `detail`, never `message`, which collides with
//!   `Throwable.message` and fails `compileKotlin` (measured, 0008 research §1);
//! - **Swift:** `public enum PolyjoseError: Swift.Error` with one case per code (ADR 0032 §3).
//!
//! On both, `code()` is a call into Rust ([`PolyjoseError::code`], exported with
//! `#[uniffi::export]`), so R8 renaming or a Swift case rename can never change the string; and
//! `toString()` / `description` is the core message through the exported `Display`. Hosts match
//! on `code()`, never on the class or case name (ADR 0033 §3).

use core::fmt;

use polyjose_surface::SurfaceError;

/// Declares [`PolyjoseError`] from one list of codes: the variants, [`PolyjoseError::CODES`],
/// [`PolyjoseError::code`], [`PolyjoseError::detail`] and the `From<SurfaceError>` mapping, so the
/// five cannot disagree. The compile-time check below ties the list to `polyjose::Error::CODES`.
macro_rules! polyjose_error {
    ($($(#[$doc:meta])* $code:ident,)+) => {
        /// The error every polyjose call throws in Kotlin (`PolyjoseException`) and Swift
        /// (`PolyjoseError`): one variant per stable core code (ADR 0030 §5, option E1).
        ///
        /// Built only from a [`SurfaceError`], so the code is always one of
        /// [`polyjose::Error::CODES`] and `detail` is the core's message, which never holds key
        /// material or input (ADR 0007). Match on [`code`](Self::code); the `detail` text is not
        /// stable.
        #[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
        #[uniffi::export(Display)]
        pub enum PolyjoseError {
            $(
                $(#[$doc])*
                $code {
                    /// The core's human-readable message (`polyjose::Error`'s `Display`). Not
                    /// stable: match on `code()` (ADR 0030 §5).
                    detail: String,
                },
            )+
        }

        impl PolyjoseError {
            /// The variant names, which are the stable codes, in declaration order.
            pub const CODES: [&'static str; [$(stringify!($code)),+].len()] =
                [$(stringify!($code)),+];

            /// The core message this error carries (ADR 0030 §5).
            pub fn detail(&self) -> &str {
                match self {
                    $(Self::$code { detail } => detail,)+
                }
            }

            fn code_str(&self) -> &'static str {
                match self {
                    $(Self::$code { .. } => stringify!($code),)+
                }
            }
        }

        /// Maps by the code string: the variant named like [`SurfaceError::code`], with
        /// [`SurfaceError::message`] as `detail` (ADR 0030 §5).
        impl From<SurfaceError> for PolyjoseError {
            fn from(e: SurfaceError) -> Self {
                let detail = e.message().to_owned();
                match e.code() {
                    $(stringify!($code) => Self::$code { detail },)+
                    // Unreachable in any build that compiles: the surface code is a core code
                    // (`SurfaceError` is built only from a `polyjose::Error`), and the assertion
                    // below makes the arms above exactly `polyjose::Error::CODES`.
                    other => unreachable!("polyjose returned an unknown error code {other}"),
                }
            }
        }
    };
}

polyjose_error! {
    /// Input is not valid unpadded base64url (RFC 4648 §5, RFC 7515 §2).
    InvalidBase64,
    /// Input is not a valid JSON object of the expected shape (RFC 7515 §5.2 step 3, RFC 7516
    /// §5.2 step 3, RFC 7517 §4, RFC 7519 §7.2 step 10).
    InvalidJson,
    /// The JOSE Header is structurally invalid (RFC 7515 §4, RFC 7516 §4).
    InvalidHeader,
    /// The `alg`, `enc`, curve, hash or format names nothing polyjose implements (RFC 7515
    /// §4.1.1, RFC 7516 §4.1.1–§4.1.2; ADR 0021, ADR 0022).
    UnsupportedAlgorithm,
    /// The algorithm is supported but not in the caller's allow-list (RFC 8725 §3.1, ADR 0007).
    AlgorithmNotAllowed,
    /// The key is malformed or too weak for any use (RFC 7517 §4, RFC 7518 §6, RFC 8725 §3.4).
    InvalidKey,
    /// The key is valid but not for this algorithm or operation (RFC 8725 §3.1, RFC 7517
    /// §4.2–§4.4).
    KeyAlgorithmMismatch,
    /// A JWS signature or MAC did not validate (RFC 7515 §5.2 step 8).
    InvalidSignature,
    /// JWE decryption failed, whatever the cause (RFC 7516 §11.5).
    DecryptionFailed,
    /// `crit` lists an extension polyjose does not understand (RFC 7515 §4.1.11, RFC 7516
    /// §4.1.13).
    UnknownCritical,
    /// The JWT `exp` time has passed (RFC 7519 §4.1.4).
    TokenExpired,
    /// The JWT `nbf` time has not been reached yet (RFC 7519 §4.1.5).
    TokenNotYetValid,
    /// A JWT claim is missing, malformed or failed validation (RFC 7519 §4.1, §7.2; RFC 8725
    /// §3.8–§3.9).
    InvalidClaim,
    /// The operating-system CSPRNG could not supply random bytes (RFC 7515 §10.1, RFC 8725 §3.5;
    /// ADR 0005).
    RandomnessUnavailable,
    /// The serialization does not have the shape its RFC requires, or the input exceeds a
    /// configured limit (RFC 7515 §7, RFC 7516 §7; ADR 0026 §1, §7).
    InvalidFormat,
    /// No key of the caller's JWK Set may verify this JWS (RFC 7517 §5, RFC 8725 §3.1;
    /// ADR 0029 §4).
    NoMatchingKey,
    /// Two or more keys of the caller's JWK Set match the `jwks_select` selector; RFC 7517 §5.1
    /// gives a set's order no meaning, so none is chosen (RFC 7517 §4.5; ADR 0054 §4, §5).
    MultipleMatchingKeys,
}

/// Compares two code lists in a `const` context (`==` on `&str` is not `const`).
const fn same_codes(a: &[&str], b: &[&str]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        let (x, y) = (a[i].as_bytes(), b[i].as_bytes());
        if x.len() != y.len() {
            return false;
        }
        let mut j = 0;
        while j < x.len() {
            if x[j] != y[j] {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

// The build fails unless the variants are exactly the core's codes, in the core's order
// (MultipleMatchingKeys last, ADR 0054 §5): a code the core adds, renames or reorders must be mirrored here first
// (ADR 0030 §5, §8). This is what makes the wildcard arm of `From<SurfaceError>` unreachable.
const _: () = assert!(
    same_codes(&PolyjoseError::CODES, polyjose::Error::CODES),
    "PolyjoseError's variants must be polyjose::Error::CODES, in order"
);

#[uniffi::export]
impl PolyjoseError {
    /// The stable error code, one of [`error_codes`](crate::util::error_codes), equal to the core
    /// `Error::code()` (ADR 0030 §5). Exported, so Kotlin's `code()` and Swift's `code()` are
    /// calls into Rust that no R8 renaming can change (ADR 0033 §3, ADR 0032 §3).
    pub fn code(&self) -> String {
        self.code_str().to_owned()
    }
}

/// The core message, which UniFFI exports as Kotlin `toString()` and Swift `description`
/// (ADR 0032 §3, ADR 0033 §3).
impl fmt::Display for PolyjoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.detail())
    }
}

/// No cause, like the core and surface errors (ADR 0007).
impl std::error::Error for PolyjoseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use polyjose::Error;
    use polyjose_surface::SurfaceError;

    /// One value of every core variant, in `Error::CODES` order (as in the surface's error tests).
    fn one_of_each() -> Vec<Error> {
        vec![
            Error::InvalidBase64,
            Error::InvalidJson("syntax error"),
            Error::InvalidHeader("missing \"alg\""),
            Error::UnsupportedAlgorithm,
            Error::AlgorithmNotAllowed,
            Error::InvalidKey("RSA modulus is under 2048 bits"),
            Error::KeyAlgorithmMismatch,
            Error::InvalidSignature,
            Error::DecryptionFailed,
            Error::UnknownCritical,
            Error::TokenExpired,
            Error::TokenNotYetValid,
            Error::InvalidClaim("aud"),
            Error::RandomnessUnavailable,
            Error::InvalidFormat("compact JWS must have three parts"),
            Error::NoMatchingKey,
            Error::MultipleMatchingKeys,
        ]
    }

    #[test]
    fn the_adapter_code_list_is_the_core_list_in_core_order() {
        assert_eq!(PolyjoseError::CODES, polyjose::Error::CODES);
        assert_eq!(PolyjoseError::CODES.last(), Some(&"MultipleMatchingKeys"));
    }

    #[test]
    fn every_code_round_trips() {
        let codes: Vec<String> = one_of_each()
            .into_iter()
            .map(|e| PolyjoseError::from(SurfaceError::from(e)).code())
            .collect();
        assert_eq!(codes, polyjose::Error::CODES);
    }

    #[test]
    fn detail_and_display_are_the_core_display_text() {
        for e in one_of_each() {
            let expected = e.to_string();
            let ffi = PolyjoseError::from(SurfaceError::from(e));
            assert_eq!(ffi.detail(), expected);
            assert_eq!(ffi.to_string(), expected);
        }
    }

    #[test]
    fn the_variant_is_the_one_named_like_the_code() {
        let e = PolyjoseError::from(SurfaceError::from(Error::InvalidClaim("aud")));
        assert_eq!(
            e,
            PolyjoseError::InvalidClaim {
                detail: "invalid claim: aud".to_owned()
            }
        );
        let e = PolyjoseError::from(SurfaceError::from(Error::NoMatchingKey));
        assert!(matches!(e, PolyjoseError::NoMatchingKey { .. }));
        let e = PolyjoseError::from(SurfaceError::from(Error::MultipleMatchingKeys));
        assert!(matches!(e, PolyjoseError::MultipleMatchingKeys { .. }));
    }
}
