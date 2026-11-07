//! Owners for secret-bearing values that cross the surface (ADR 0030 §7).
//!
//! Secret-bearing values are private JWKs and JWK Sets, PBES2 passwords (an `oct` JWK), JWE
//! plaintext, JWS payloads, generated keys, private `jwk_to_pem`/`jwk_to_der` output and the JWE
//! `aad` (ADR 0030 §7, ADR 0049 §4, ADR 0050 §4). The surface returns them, and holds them inside
//! records, as [`SecretString`] or [`SecretBytes`]:
//!
//! - the buffer is a [`Zeroizing`] owner, so it is wiped when it drops (ADR 0030 §7.2);
//! - `Debug` prints `<redacted>`, and there is no `Display` (ADR 0030 §7.5);
//! - there is no `Clone` and no conversion into a plain `String`/`Vec<u8>`, so the only way out
//!   is a borrow ([`SecretString::as_str`], [`SecretBytes::as_bytes`]) from which an adapter
//!   copies into the host value (ADR 0030 §7.2).
//!
//! Both are built only by moving an owned buffer in (`From<String>`, `From<Zeroizing<String>>`,
//! and the byte equivalents), which copies nothing.

use core::fmt;

use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A secret UTF-8 string, wiped on drop (ADR 0030 §7): for example a private JWK, or the PEM of
/// a private key.
///
/// ```
/// use polyjose_surface::secret::SecretString;
///
/// let key = SecretString::from(String::from(r#"{"kty":"oct","k":"c2VjcmV0"}"#));
/// assert!(key.as_str().starts_with('{'));
/// assert_eq!(format!("{key:?}"), "<redacted>");
/// ```
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Borrows the secret. Copying it out (`to_owned`, `to_string`) leaves the copy unprotected:
    /// adapters build the host value straight from this borrow (ADR 0030 §7.2).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Takes ownership without copying.
impl From<Zeroizing<String>> for SecretString {
    fn from(value: Zeroizing<String>) -> Self {
        Self(value)
    }
}

/// Takes ownership without copying; the buffer is wiped from now on.
impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

/// Never prints the secret (ADR 0030 §7.5).
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The only field is a [`Zeroizing`] owner, which wipes the string when it drops.
impl ZeroizeOnDrop for SecretString {}

/// Secret octets, wiped on drop (ADR 0030 §7): for example JWE plaintext, a verified JWS payload,
/// the JWE `aad`, or the DER of a private key.
///
/// ```
/// use polyjose_surface::secret::SecretBytes;
///
/// let plaintext = SecretBytes::from(b"attack at dawn".to_vec());
/// assert_eq!(plaintext.as_bytes(), b"attack at dawn");
/// assert_eq!(format!("{plaintext:?}"), "<redacted>");
/// ```
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Borrows the secret. Copying it out (`to_vec`) leaves the copy unprotected: adapters build
    /// the host value straight from this borrow (ADR 0030 §7.2).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Takes ownership without copying.
impl From<Zeroizing<Vec<u8>>> for SecretBytes {
    fn from(value: Zeroizing<Vec<u8>>) -> Self {
        Self(value)
    }
}

/// Takes ownership without copying; the buffer is wiped from now on.
impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }
}

/// Never prints the secret (ADR 0030 §7.5).
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The only field is a [`Zeroizing`] owner, which wipes the octets when it drops.
impl ZeroizeOnDrop for SecretBytes {}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = "pj-SECRET-marker-7f3a";

    /// Compiles only if `T` wipes itself on drop.
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    /// Negative trait checks without a crate: `some_item` resolves only when exactly one impl of
    /// `NotImpl<_>` applies, which is the case only when `T` lacks the trait.
    macro_rules! assert_not_impl {
        ($ty:ty, $($bound:tt)+) => {{
            trait NotImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> NotImpl<()> for T {}
            #[allow(dead_code)]
            struct Invalid;
            impl<T: ?Sized + $($bound)+> NotImpl<Invalid> for T {}
            <$ty as NotImpl<_>>::some_item();
        }};
    }

    #[test]
    fn both_types_wipe_on_drop() {
        assert_zeroize_on_drop::<SecretString>();
        assert_zeroize_on_drop::<SecretBytes>();
        assert_zeroize_on_drop::<Option<SecretBytes>>();
    }

    #[test]
    fn no_clone_no_display_no_conversion_out() {
        assert_not_impl!(SecretString, Clone);
        assert_not_impl!(SecretBytes, Clone);
        assert_not_impl!(SecretString, fmt::Display);
        assert_not_impl!(SecretBytes, fmt::Display);
        assert_not_impl!(SecretString, Into<String>);
        assert_not_impl!(SecretString, Into<Vec<u8>>);
        assert_not_impl!(SecretBytes, Into<Vec<u8>>);
        assert_not_impl!(SecretBytes, Into<String>);
    }

    #[test]
    fn debug_is_redacted() {
        let s = SecretString::from(MARKER.to_owned());
        let b = SecretBytes::from(MARKER.as_bytes().to_vec());
        for rendered in [
            format!("{s:?}"),
            format!("{s:#?}"),
            format!("{b:?}"),
            format!("{b:#?}"),
            format!("{:?}", Some(&b)),
        ] {
            assert!(
                !rendered.contains(MARKER),
                "Debug leaks a secret: {rendered}"
            );
        }
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(format!("{b:?}"), "<redacted>");
    }

    #[test]
    fn accessors_borrow_the_value_moved_in() {
        let s = SecretString::from(Zeroizing::new(MARKER.to_owned()));
        assert_eq!(s.as_str(), MARKER);
        let b = SecretBytes::from(Zeroizing::new(vec![1, 2, 3]));
        assert_eq!(b.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn moving_a_string_in_keeps_its_allocation() {
        // From<String> must not copy: the secret then exists in one buffer only.
        let owned = MARKER.to_owned();
        let ptr = owned.as_ptr();
        let s = SecretString::from(owned);
        assert_eq!(s.as_str().as_ptr(), ptr);

        let bytes = MARKER.as_bytes().to_vec();
        let ptr = bytes.as_ptr();
        let b = SecretBytes::from(bytes);
        assert_eq!(b.as_bytes().as_ptr(), ptr);
    }
}
