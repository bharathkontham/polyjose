//! Algorithm identifiers: JWS `alg`, JWE `alg` and JWE `enc` (RFC 7518).
//!
//! Each enum covers the polyjose 0.1.0 algorithm matrix (ADR 0006). The
//! string form of every variant is the name registered in the IANA "JSON Web
//! Signature and Encryption Algorithms" registry (RFC 7518 §7.1), matched
//! case-sensitively (RFC 7515 §4.1.1, RFC 7516 §4.1.1–§4.1.2).
//!
//! # Unknown values
//!
//! Any other string parses as `Unknown(String)` and serializes back to the
//! exact same string, so a header can be read and re-written without loss.
//! An unknown value only fails when it is about to be used:
//! [`SigningAlg::ensure_known`] (and its siblings) return
//! [`Error::UnsupportedAlgorithm`], which never echoes the value.
//!
//! Construct values with `From<&str>`/`From<String>` (or the variants). Building
//! `Unknown` directly from a registered name (e.g. `Unknown("HS256".into())`)
//! is non-canonical: it compares unequal to the named variant, so it fails
//! closed against an allow-list, and `ensure_known` rejects it.
//!
//! # `none`
//!
//! [`SigningAlg::None`] (RFC 7518 §3.6) is a known identifier so that headers
//! using it can be parsed and diagnosed, but it is never verifiable: the
//! verify allow-list rejects it with [`Error::AlgorithmNotAllowed`]
//! (RFC 8725 §3.1, ADR 0007). Being "known" here only means "recognised".

use core::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};

use crate::error::{Error, Result};

/// Defines an algorithm-identifier enum with its registered names, an
/// `Unknown(String)` catch-all and the string conversions shared by all
/// three enums.
macro_rules! alg_enum {
    (
        $(#[$meta:meta])*
        $name:ident, $expecting:literal {
            $( $(#[$vmeta:meta])* $variant:ident => $s:literal, )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )*
            /// A value that is not one of the registered names above.
            ///
            /// Preserved verbatim so it round-trips through serialization;
            /// it fails with [`Error::UnsupportedAlgorithm`] when used
            /// (RFC 7515 §4.1.1, RFC 7516 §4.1.1–§4.1.2).
            Unknown(String),
        }

        impl $name {
            /// Every registered (known) value, in declaration order.
            pub const KNOWN: &'static [$name] = &[$($name::$variant),*];

            /// The identifier string, exactly as it appears in a header.
            pub fn as_str(&self) -> &str {
                match self {
                    $( Self::$variant => $s, )*
                    Self::Unknown(s) => s,
                }
            }

            /// Returns the variant whose registered name is exactly `name`
            /// (case-sensitive), if any.
            fn lookup(name: &str) -> Option<Self> {
                match name {
                    $( $s => Some(Self::$variant), )*
                    _ => None,
                }
            }

            /// Whether this is a registered value (not `Unknown`).
            pub fn is_known(&self) -> bool {
                !matches!(self, Self::Unknown(_))
            }

            /// Returns `self` if it is a registered value.
            ///
            /// # Errors
            ///
            /// [`Error::UnsupportedAlgorithm`] for `Unknown` values
            /// (RFC 7515 §4.1.1, RFC 7516 §4.1.1–§4.1.2). The value is not
            /// included in the error.
            pub fn ensure_known(&self) -> Result<&Self> {
                match self {
                    Self::Unknown(_) => Err(Error::UnsupportedAlgorithm),
                    _ => Ok(self),
                }
            }
        }

        impl From<&str> for $name {
            fn from(name: &str) -> Self {
                Self::lookup(name).unwrap_or_else(|| Self::Unknown(name.to_owned()))
            }
        }

        impl From<String> for $name {
            fn from(name: String) -> Self {
                Self::lookup(&name).unwrap_or(Self::Unknown(name))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
                struct V;
                impl Visitor<'_> for V {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }
                    fn visit_str<E: de::Error>(self, v: &str) -> core::result::Result<$name, E> {
                        Ok($name::from(v))
                    }
                    fn visit_string<E: de::Error>(self, v: String) -> core::result::Result<$name, E> {
                        Ok($name::from(v))
                    }
                }
                deserializer.deserialize_str(V)
            }
        }
    };
}

alg_enum! {
    /// JWS `alg` values (RFC 7515 §4.1.1, RFC 7518 §3.1).
    SigningAlg, "a JWS alg string" {
        /// `HS256`: HMAC using SHA-256 (RFC 7518 §3.2).
        HS256 => "HS256",
        /// `HS384`: HMAC using SHA-384 (RFC 7518 §3.2).
        HS384 => "HS384",
        /// `HS512`: HMAC using SHA-512 (RFC 7518 §3.2).
        HS512 => "HS512",
        /// `RS256`: RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 §3.3).
        RS256 => "RS256",
        /// `RS384`: RSASSA-PKCS1-v1_5 using SHA-384 (RFC 7518 §3.3).
        RS384 => "RS384",
        /// `RS512`: RSASSA-PKCS1-v1_5 using SHA-512 (RFC 7518 §3.3).
        RS512 => "RS512",
        /// `ES256`: ECDSA using P-256 and SHA-256 (RFC 7518 §3.4).
        ES256 => "ES256",
        /// `ES384`: ECDSA using P-384 and SHA-384 (RFC 7518 §3.4).
        ES384 => "ES384",
        /// `ES512`: ECDSA using P-521 and SHA-512 (RFC 7518 §3.4).
        ES512 => "ES512",
        /// `ES256K`: ECDSA using secp256k1 and SHA-256 (RFC 8812 §3.2).
        ES256K => "ES256K",
        /// `PS256`: RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (RFC 7518 §3.5).
        PS256 => "PS256",
        /// `PS384`: RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (RFC 7518 §3.5).
        PS384 => "PS384",
        /// `PS512`: RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (RFC 7518 §3.5).
        PS512 => "PS512",
        /// `EdDSA`: the polymorphic EdDSA identifier (RFC 8037 §3.1).
        ///
        /// Deprecated in favour of the fully-specified [`SigningAlg::Ed25519`]
        /// (RFC 9864 §2.2). polyjose accepts it with Ed25519 keys only
        /// (Ed448 is out of scope, ADR 0006).
        EdDSA => "EdDSA",
        /// `Ed25519`: EdDSA using the Ed25519 parameter set (RFC 9864 §2.2).
        Ed25519 => "Ed25519",
        /// `none`: Unsecured JWS, no signature or MAC (RFC 7518 §3.6).
        ///
        /// Parsed for diagnostics only. It is never verifiable and is
        /// rejected by every verify allow-list (RFC 8725 §3.1, ADR 0007).
        None => "none",
    }
}

alg_enum! {
    /// JWE `alg` (key management) values (RFC 7516 §4.1.1, RFC 7518 §4.1).
    KeyMgmtAlg, "a JWE alg string" {
        /// `RSA1_5`: RSAES-PKCS1-v1_5 (RFC 7518 §4.2).
        ///
        /// Implemented only behind a feature gate (ADR 0003).
        RsaPkcs1v15 => "RSA1_5",
        /// `RSA-OAEP`: RSAES OAEP using default parameters (RFC 7518 §4.3).
        RsaOaep => "RSA-OAEP",
        /// `RSA-OAEP-256`: RSAES OAEP using SHA-256 and MGF1 with SHA-256 (RFC 7518 §4.3).
        RsaOaep256 => "RSA-OAEP-256",
        /// `A128KW`: AES Key Wrap with a 128-bit key (RFC 7518 §4.4).
        A128KW => "A128KW",
        /// `A192KW`: AES Key Wrap with a 192-bit key (RFC 7518 §4.4).
        A192KW => "A192KW",
        /// `A256KW`: AES Key Wrap with a 256-bit key (RFC 7518 §4.4).
        A256KW => "A256KW",
        /// `dir`: direct use of a shared symmetric key as the CEK (RFC 7518 §4.5).
        Dir => "dir",
        /// `ECDH-ES`: ECDH Ephemeral Static direct key agreement (RFC 7518 §4.6).
        EcdhEs => "ECDH-ES",
        /// `ECDH-ES+A128KW`: ECDH-ES with A128KW wrapping (RFC 7518 §4.6).
        EcdhEsA128KW => "ECDH-ES+A128KW",
        /// `ECDH-ES+A192KW`: ECDH-ES with A192KW wrapping (RFC 7518 §4.6).
        EcdhEsA192KW => "ECDH-ES+A192KW",
        /// `ECDH-ES+A256KW`: ECDH-ES with A256KW wrapping (RFC 7518 §4.6).
        EcdhEsA256KW => "ECDH-ES+A256KW",
        /// `A128GCMKW`: key wrapping with AES-GCM using a 128-bit key (RFC 7518 §4.7).
        A128GCMKW => "A128GCMKW",
        /// `A192GCMKW`: key wrapping with AES-GCM using a 192-bit key (RFC 7518 §4.7).
        A192GCMKW => "A192GCMKW",
        /// `A256GCMKW`: key wrapping with AES-GCM using a 256-bit key (RFC 7518 §4.7).
        A256GCMKW => "A256GCMKW",
        /// `PBES2-HS256+A128KW`: PBES2 with HMAC SHA-256 and A128KW wrapping (RFC 7518 §4.8).
        Pbes2Hs256A128KW => "PBES2-HS256+A128KW",
        /// `PBES2-HS384+A192KW`: PBES2 with HMAC SHA-384 and A192KW wrapping (RFC 7518 §4.8).
        Pbes2Hs384A192KW => "PBES2-HS384+A192KW",
        /// `PBES2-HS512+A256KW`: PBES2 with HMAC SHA-512 and A256KW wrapping (RFC 7518 §4.8).
        Pbes2Hs512A256KW => "PBES2-HS512+A256KW",
    }
}

alg_enum! {
    /// JWE `enc` (content encryption) values (RFC 7516 §4.1.2, RFC 7518 §5.1).
    ContentEncAlg, "a JWE enc string" {
        /// `A128CBC-HS256`: AES-128-CBC with HMAC SHA-256 (RFC 7518 §5.2.3).
        A128CbcHs256 => "A128CBC-HS256",
        /// `A192CBC-HS384`: AES-192-CBC with HMAC SHA-384 (RFC 7518 §5.2.4).
        A192CbcHs384 => "A192CBC-HS384",
        /// `A256CBC-HS512`: AES-256-CBC with HMAC SHA-512 (RFC 7518 §5.2.5).
        A256CbcHs512 => "A256CBC-HS512",
        /// `A128GCM`: AES-GCM using a 128-bit key (RFC 7518 §5.3).
        A128GCM => "A128GCM",
        /// `A192GCM`: AES-GCM using a 192-bit key (RFC 7518 §5.3).
        A192GCM => "A192GCM",
        /// `A256GCM`: AES-GCM using a 256-bit key (RFC 7518 §5.3).
        A256GCM => "A256GCM",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The in-scope rows of the IANA "JSON Web Signature and Encryption
    /// Algorithms" registry (ADR 0006), copied from the registry CSV.
    const JWS_NAMES: &[&str] = &[
        "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "ES256K",
        "PS256", "PS384", "PS512", "EdDSA", "Ed25519", "none",
    ];
    const JWE_ALG_NAMES: &[&str] = &[
        "RSA1_5",
        "RSA-OAEP",
        "RSA-OAEP-256",
        "A128KW",
        "A192KW",
        "A256KW",
        "dir",
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
        "A128GCMKW",
        "A192GCMKW",
        "A256GCMKW",
        "PBES2-HS256+A128KW",
        "PBES2-HS384+A192KW",
        "PBES2-HS512+A256KW",
    ];
    const JWE_ENC_NAMES: &[&str] = &[
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
    ];

    fn json(s: &str) -> String {
        format!("\"{s}\"")
    }

    /// Every registered name parses to a known variant and serializes back
    /// byte-for-byte; the known set is exactly the registry list.
    fn assert_names<T>(names: &[&str], known: &[T])
    where
        T: for<'de> Deserialize<'de> + Serialize + PartialEq + fmt::Debug + fmt::Display,
        T: for<'a> From<&'a str>,
    {
        for name in names {
            let parsed: T = serde_json::from_str(&json(name)).unwrap_or_else(|_| unreachable!());
            assert_eq!(parsed, T::from(*name), "{name}");
            assert!(known.contains(&parsed), "{name} must be a known variant");
            assert_eq!(parsed.to_string(), *name);
            assert_eq!(serde_json::to_string(&parsed).ok(), Some(json(name)));
        }
        let known_names: Vec<String> = known.iter().map(ToString::to_string).collect();
        assert_eq!(known_names, names, "KNOWN must match the registry list");
    }

    #[test]
    fn jws_alg_names_match_the_iana_registry() {
        assert_names(JWS_NAMES, SigningAlg::KNOWN);
    }

    #[test]
    fn jwe_alg_names_match_the_iana_registry() {
        assert_names(JWE_ALG_NAMES, KeyMgmtAlg::KNOWN);
    }

    #[test]
    fn jwe_enc_names_match_the_iana_registry() {
        assert_names(JWE_ENC_NAMES, ContentEncAlg::KNOWN);
    }

    #[test]
    fn new_identifiers_have_their_variants() {
        assert_eq!(SigningAlg::from("ES256K"), SigningAlg::ES256K);
        assert_eq!(SigningAlg::from("Ed25519"), SigningAlg::Ed25519);
        assert_eq!(SigningAlg::from("none"), SigningAlg::None);
        assert_eq!(KeyMgmtAlg::from("RSA1_5"), KeyMgmtAlg::RsaPkcs1v15);
        assert_eq!(KeyMgmtAlg::from("A192GCMKW"), KeyMgmtAlg::A192GCMKW);
        assert_eq!(
            KeyMgmtAlg::from("PBES2-HS512+A256KW"),
            KeyMgmtAlg::Pbes2Hs512A256KW
        );
    }

    /// Values that are not in scope: wrong case, registered but out of
    /// scope (Ed448, RSA-OAEP-384, HPKE-0, ML-DSA-44), the other family's
    /// names, whitespace and empty strings.
    const NOT_JWS: &[&str] = &[
        "hs256",
        "Hs256",
        "NONE",
        "None",
        "eddsa",
        "ED25519",
        "Ed448",
        "ML-DSA-44",
        "ES256k",
        " HS256",
        "HS256 ",
        "",
        "RSA-OAEP",
        "A128GCM",
    ];
    const NOT_JWE_ALG: &[&str] = &[
        "rsa-oaep",
        "RSA-OAEP-384",
        "RSA_1_5",
        "Dir",
        "DIR",
        "HPKE-0",
        "ECDH-ES+A128GCMKW",
        "pbes2-hs256+a128kw",
        "",
        "HS256",
        "none",
    ];
    const NOT_JWE_ENC: &[&str] = &["a128gcm", "A128CBC", "A128CBC-HS512", "", "A256KW", "dir"];

    fn assert_unknown_round_trips<T>(values: &[&str], unknown: fn(String) -> T)
    where
        T: for<'de> Deserialize<'de> + Serialize + PartialEq + fmt::Debug + fmt::Display,
    {
        for value in values {
            let input = serde_json::to_string(value).unwrap_or_else(|_| unreachable!());
            let parsed: T = serde_json::from_str(&input).unwrap_or_else(|_| unreachable!());
            assert_eq!(parsed, unknown((*value).to_owned()), "{value:?}");
            assert_eq!(serde_json::to_string(&parsed).ok(), Some(input));
            assert_eq!(parsed.to_string(), *value);
        }
    }

    #[test]
    fn unknown_jws_alg_round_trips_exactly() {
        assert_unknown_round_trips(NOT_JWS, SigningAlg::Unknown);
    }

    #[test]
    fn unknown_jwe_alg_round_trips_exactly() {
        assert_unknown_round_trips(NOT_JWE_ALG, KeyMgmtAlg::Unknown);
    }

    #[test]
    fn unknown_jwe_enc_round_trips_exactly() {
        assert_unknown_round_trips(NOT_JWE_ENC, ContentEncAlg::Unknown);
    }

    #[test]
    fn unknown_with_escapes_and_unicode_round_trips() {
        // JSON escapes decode before lookup; the decoded value is preserved.
        let parsed: SigningAlg =
            serde_json::from_str(r#""HS256""#).unwrap_or_else(|_| unreachable!());
        assert_eq!(parsed, SigningAlg::HS256);
        let parsed: SigningAlg =
            serde_json::from_str(r#""HS256\u0000""#).unwrap_or_else(|_| unreachable!());
        assert_eq!(parsed, SigningAlg::Unknown("HS256\0".into()));
        let parsed: SigningAlg =
            serde_json::from_str("\"ＨＳ256\"").unwrap_or_else(|_| unreachable!());
        assert_eq!(parsed, SigningAlg::Unknown("ＨＳ256".into()));
        assert_eq!(
            serde_json::to_string(&parsed).ok().as_deref(),
            Some("\"ＨＳ256\"")
        );
    }

    #[test]
    fn ensure_known_rejects_unknown_with_unsupported_algorithm() {
        let marker = "pj-SECRET-marker-alg";
        let cases = [
            SigningAlg::from(marker).ensure_known().err(),
            KeyMgmtAlg::from(marker).ensure_known().err(),
            ContentEncAlg::from(marker).ensure_known().err(),
        ];
        for err in cases {
            let err = err.unwrap_or_else(|| unreachable!("unknown must fail"));
            assert_eq!(err, Error::UnsupportedAlgorithm);
            assert!(!format!("{err:?}").contains(marker));
            assert!(!err.to_string().contains(marker));
        }
    }

    #[test]
    fn ensure_known_accepts_every_known_value() {
        for alg in SigningAlg::KNOWN {
            assert_eq!(alg.ensure_known().ok(), Some(alg));
            assert!(alg.is_known());
        }
        for alg in KeyMgmtAlg::KNOWN {
            assert_eq!(alg.ensure_known().ok(), Some(alg));
        }
        for enc in ContentEncAlg::KNOWN {
            assert_eq!(enc.ensure_known().ok(), Some(enc));
        }
        assert!(!SigningAlg::from("HS1").is_known());
    }

    #[test]
    fn non_canonical_unknown_fails_closed() {
        // Building `Unknown` from a registered name never equals the variant.
        let forged = SigningAlg::Unknown("HS256".into());
        assert_ne!(forged, SigningAlg::HS256);
        assert_eq!(forged.ensure_known(), Err(Error::UnsupportedAlgorithm));
    }

    #[test]
    fn non_string_json_is_rejected_without_echo() {
        for input in ["256", "null", "true", "[\"HS256\"]", "{\"alg\":\"HS256\"}"] {
            let err = serde_json::from_str::<SigningAlg>(input)
                .err()
                .unwrap_or_else(|| unreachable!("{input} must fail"));
            assert_eq!(Error::from(err).code(), "InvalidJson");
        }
    }
}
