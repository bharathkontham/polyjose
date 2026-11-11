//! Content encryption: the CEK, the content IV, the Additional
//! Authenticated Data and the `enc` dispatcher (RFC 7516 §5.1 steps 2, 9
//! and 13–15, §5.2 steps 14–16; RFC 7518 §5).
//!
//! [`encrypt`] and [`decrypt`] dispatch on `enc` to `enc_gcm` (A*GCM,
//! RFC 7518 §5.3) and `enc_cbc_hmac` (A*CBC-HS*, RFC 7518 §5.2). Every
//! decryption failure is [`Error::DecryptionFailed`], with no detail
//! (RFC 7516 §11.4).

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::random::RandomSource;
use super::{enc_cbc_hmac, enc_gcm};
use crate::jwa::ContentEncAlg;
use crate::util::b64url_encode;
use crate::{Error, Result};

/// A Content Encryption Key (RFC 7516 §2).
///
/// The bytes are wiped on drop, and `Debug` prints `<redacted>` instead of
/// them (ADR 0007).
pub(crate) struct Cek(Zeroizing<Vec<u8>>);

impl Cek {
    /// A CEK holding `bytes`.
    pub(crate) fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Cek(bytes)
    }

    /// A CEK holding a copy of `bytes`.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Cek(Zeroizing::new(bytes.to_vec()))
    }

    /// The key bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The key length in bytes.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

impl Zeroize for Cek {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// The only field is a [`Zeroizing`] buffer.
impl ZeroizeOnDrop for Cek {}

impl fmt::Debug for Cek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cek(<redacted>)")
    }
}

/// The CEK length `enc` requires, in bytes: 32, 48 and 64 for
/// A128CBC-HS256, A192CBC-HS384 and A256CBC-HS512 (RFC 7518 §5.2.3–§5.2.5:
/// MAC_KEY || ENC_KEY), and 16, 24 and 32 for A128GCM, A192GCM and A256GCM
/// (RFC 7518 §5.3).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc` (RFC 7516 §4.1.2).
pub(crate) fn cek_len(enc: &ContentEncAlg) -> Result<usize> {
    match enc {
        ContentEncAlg::A128CbcHs256 => Ok(32),
        ContentEncAlg::A192CbcHs384 => Ok(48),
        ContentEncAlg::A256CbcHs512 => Ok(64),
        ContentEncAlg::A128GCM => Ok(16),
        ContentEncAlg::A192GCM => Ok(24),
        ContentEncAlg::A256GCM => Ok(32),
        ContentEncAlg::Unknown(_) => Err(Error::UnsupportedAlgorithm),
    }
}

/// The content IV length `enc` requires, in bytes: 16 for A*CBC-HS*, the
/// AES block size (RFC 7518 §5.2.2.1), and 12 for A*GCM, 96 bits
/// (RFC 7518 §5.3).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc` (RFC 7516 §4.1.2).
pub(crate) fn iv_len(enc: &ContentEncAlg) -> Result<usize> {
    match enc {
        ContentEncAlg::A128CbcHs256 | ContentEncAlg::A192CbcHs384 | ContentEncAlg::A256CbcHs512 => {
            Ok(16)
        }
        ContentEncAlg::A128GCM | ContentEncAlg::A192GCM | ContentEncAlg::A256GCM => Ok(12),
        ContentEncAlg::Unknown(_) => Err(Error::UnsupportedAlgorithm),
    }
}

/// Draws a random CEK of exactly [`cek_len`] bytes from `rng` (RFC 7516
/// §5.1 step 2: "generate a random Content Encryption Key"; RFC 7518 §8.9:
/// a key must not be reused across algorithms), as the first draw of a
/// message (see `jwe::random` for the draw order).
///
/// The bytes go straight into the zeroizing [`Cek`] buffer; no other copy
/// is made.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc`, before anything
/// is drawn; [`Error::RandomnessUnavailable`] if `rng` fails (ADR 0005:
/// fail closed, never a short key).
pub(crate) fn generate_cek(enc: &ContentEncAlg, rng: &mut dyn RandomSource) -> Result<Cek> {
    let mut cek = Zeroizing::new(vec![0u8; cek_len(enc)?]);
    rng.fill(&mut cek)?;
    Ok(Cek::new(cek))
}

/// Draws a random content IV of exactly [`iv_len`] bytes from `rng`
/// (RFC 7516 §5.1 step 9: "generate a random JWE Initialization Vector of
/// the correct size for the content encryption algorithm"): 16 bytes for
/// A*CBC-HS* (RFC 7518 §5.2.2.1) and 12 for A*GCM (RFC 7518 §5.3).
///
/// A random 96-bit GCM IV under one key is safe for at most 2^32
/// messages (RFC 7518 §8.4); that bound is documented, not enforced.
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc`, before anything
/// is drawn; [`Error::RandomnessUnavailable`] if `rng` fails (ADR 0005).
pub(crate) fn generate_iv(enc: &ContentEncAlg, rng: &mut dyn RandomSource) -> Result<Vec<u8>> {
    let mut iv = vec![0u8; iv_len(enc)?];
    rng.fill(&mut iv)?;
    Ok(iv)
}

/// The Additional Authenticated Data of RFC 7516 §5.1 step 14 (and §5.2
/// step 15): `ASCII(Encoded Protected Header)`, or, with a JWE AAD value,
/// `ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD))`.
///
/// `encoded_protected` must be the protected header **as received** (or as
/// produced on encrypt), never a re-serialization (RFC 7516 §5.2 step 14;
/// erratum 8676). It is empty when a JSON JWE has no protected header
/// (RFC 7516 §7.2.1).
///
/// The JWE AAD can carry application secrets (ADR 0050 §4, ADR 0030 §7.2),
/// so its encoding and the result are wiped on drop, and the result is
/// allocated once at its final size, so no reallocation frees an unwiped
/// prefix.
pub(crate) fn aad(encoded_protected: &str, jwe_aad: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let encoded = jwe_aad.map(|jwe_aad| Zeroizing::new(b64url_encode(jwe_aad)));
    let len = encoded_protected.len() + encoded.as_ref().map_or(0, |e| 1 + e.len());
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(encoded_protected.as_bytes());
    if let Some(encoded) = encoded {
        out.push(b'.');
        out.extend_from_slice(encoded.as_bytes());
    }
    out
}

/// Encrypts `plaintext` under `cek` and `iv` with `aad` (RFC 7516 §5.1
/// step 15) and returns `(ciphertext, tag)`, dispatching on `enc` to
/// AES-GCM (RFC 7518 §5.3, `enc_gcm`) or AES_CBC_HMAC_SHA2 (RFC 7518 §5.2,
/// `enc_cbc_hmac`).
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc` (RFC 7516 §4.1.2);
/// otherwise the family's error for a CEK or IV of the wrong length
/// ([`Error::InvalidKey`] for the CEK, [`Error::InvalidFormat`] for the IV
/// on A*GCM).
pub(crate) fn encrypt(
    enc: &ContentEncAlg,
    cek: &Cek,
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    match enc {
        ContentEncAlg::A128GCM | ContentEncAlg::A192GCM | ContentEncAlg::A256GCM => {
            enc_gcm::encrypt(enc, cek.as_bytes(), iv, aad, plaintext)
        }
        ContentEncAlg::A128CbcHs256 | ContentEncAlg::A192CbcHs384 | ContentEncAlg::A256CbcHs512 => {
            enc_cbc_hmac::encrypt(enc, cek.as_bytes(), iv, aad, plaintext)
        }
        ContentEncAlg::Unknown(_) => Err(Error::UnsupportedAlgorithm),
    }
}

/// Verifies `tag` and decrypts `ciphertext` (RFC 7516 §5.2 step 16): no
/// plaintext is returned, or left in a returned buffer, unless the tag is
/// correct ("reject the input without emitting any decrypted output").
/// Dispatches like [`encrypt`].
///
/// # Errors
///
/// [`Error::UnsupportedAlgorithm`] for an unknown `enc` (RFC 7516 §4.1.2;
/// the pipeline rejects it before key management). Once `enc` is known,
/// [`Error::DecryptionFailed`] for every failure, with no detail: tag,
/// ciphertext, IV, AAD, padding, or CEK length (RFC 7516 §11.4, §11.5).
pub(crate) fn decrypt(
    enc: &ContentEncAlg,
    cek: &Cek,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(test)]
    crate::test_counters::content_decryptions::tick();
    match enc {
        ContentEncAlg::A128GCM | ContentEncAlg::A192GCM | ContentEncAlg::A256GCM => {
            enc_gcm::decrypt(enc, cek.as_bytes(), iv, aad, ciphertext, tag)
        }
        ContentEncAlg::A128CbcHs256 | ContentEncAlg::A192CbcHs384 | ContentEncAlg::A256CbcHs512 => {
            enc_cbc_hmac::decrypt(enc, cek.as_bytes(), iv, aad, ciphertext, tag)
        }
        ContentEncAlg::Unknown(_) => Err(Error::UnsupportedAlgorithm),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwe::random::OsRandom;
    use crate::rng::insecure_test_vectors::FixedRng;
    use crate::test_support::wycheproof::{self, Outcome};

    fn assert_zeroize_on_drop<T: Zeroize + ZeroizeOnDrop>() {}

    #[test]
    fn cek_is_wiped_and_never_printed() {
        assert_zeroize_on_drop::<Cek>();
        let mut cek = Cek::from_slice(&[0xC5; 16]);
        assert_eq!(cek.len(), 16);
        assert_eq!(cek.as_bytes(), &[0xC5; 16]);
        let debug = format!("{cek:?}");
        assert_eq!(debug, "Cek(<redacted>)");
        assert!(!debug.contains("197") && !debug.to_lowercase().contains("c5"));
        cek.zeroize();
        assert!(cek.as_bytes().iter().all(|&b| b == 0));
        let cek = Cek::new(Zeroizing::new(vec![1, 2, 3]));
        assert_eq!(cek.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn cek_and_iv_lengths_follow_rfc_7518() {
        let table = [
            (ContentEncAlg::A128CbcHs256, 32, 16),
            (ContentEncAlg::A192CbcHs384, 48, 16),
            (ContentEncAlg::A256CbcHs512, 64, 16),
            (ContentEncAlg::A128GCM, 16, 12),
            (ContentEncAlg::A192GCM, 24, 12),
            (ContentEncAlg::A256GCM, 32, 12),
        ];
        assert_eq!(table.len(), ContentEncAlg::KNOWN.len());
        for (enc, cek, iv) in table {
            assert_eq!((cek_len(&enc), iv_len(&enc)), (Ok(cek), Ok(iv)), "{enc}");
        }
        let unknown = ContentEncAlg::from("A128CTR");
        assert_eq!(cek_len(&unknown), Err(Error::UnsupportedAlgorithm));
        assert_eq!(iv_len(&unknown), Err(Error::UnsupportedAlgorithm));
    }

    /// `0, 1, 2, ...`, so a draw's bytes show where in the stream it read.
    fn counting_rng(len: usize) -> FixedRng {
        FixedRng::new((0..len).map(|i| (i % 251) as u8).collect::<Vec<u8>>())
    }

    #[test]
    fn cek_and_iv_are_the_injected_bytes_in_draw_order() {
        // RFC 7516 §5.1 steps 2 and 9: the CEK is drawn first, then the IV
        // (the documented draw order of `jwe::random`), and each takes
        // exactly cek_len / iv_len bytes of the stream, nothing more.
        for enc in ContentEncAlg::KNOWN {
            let (cek_n, iv_n) = (cek_len(enc).unwrap(), iv_len(enc).unwrap());
            let mut rng = counting_rng(cek_n + iv_n + 5);
            let cek = generate_cek(enc, &mut rng).unwrap();
            assert_eq!(rng.remaining(), iv_n + 5, "{enc}: CEK draw size");
            let iv = generate_iv(enc, &mut rng).unwrap();
            assert_eq!(rng.remaining(), 5, "{enc}: IV draw size");
            let expected: Vec<u8> = (0..cek_n + iv_n).map(|i| i as u8).collect();
            assert_eq!(cek.as_bytes(), &expected[..cek_n], "{enc}");
            assert_eq!(iv, &expected[cek_n..], "{enc}");
        }
    }

    #[test]
    fn cek_and_iv_from_the_os_are_fresh() {
        // 128 bits or more per draw: equal draws are a 2^-96 event at
        // worst (the 96-bit GCM IV), not flakiness.
        for enc in ContentEncAlg::KNOWN {
            let mut os = OsRandom;
            let (a, b) = (generate_cek(enc, &mut os), generate_cek(enc, &mut os));
            let (a, b) = (a.unwrap(), b.unwrap());
            assert_eq!(a.len(), cek_len(enc).unwrap());
            assert_ne!(a.as_bytes(), b.as_bytes(), "{enc}");
            let (a, b) = (generate_iv(enc, &mut os), generate_iv(enc, &mut os));
            let (a, b) = (a.unwrap(), b.unwrap());
            assert_eq!(a.len(), iv_len(enc).unwrap());
            assert_ne!(a, b, "{enc}");
        }
    }

    #[test]
    fn cek_and_iv_fail_closed() {
        // An unknown `enc` draws nothing (RFC 7516 §4.1.2); a source that
        // runs short fails with RandomnessUnavailable (ADR 0005), never a
        // short or padded key or IV.
        let unknown = ContentEncAlg::from("A128CTR");
        let mut rng = counting_rng(64);
        assert_eq!(
            generate_cek(&unknown, &mut rng).map(|_| ()),
            Err(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            generate_iv(&unknown, &mut rng),
            Err(Error::UnsupportedAlgorithm)
        );
        assert_eq!(rng.remaining(), 64);
        for enc in ContentEncAlg::KNOWN {
            let mut short = counting_rng(cek_len(enc).unwrap() - 1);
            assert_eq!(
                generate_cek(enc, &mut short).map(|_| ()),
                Err(Error::RandomnessUnavailable),
                "{enc}"
            );
            let mut short = counting_rng(iv_len(enc).unwrap() - 1);
            assert_eq!(
                generate_iv(enc, &mut short),
                Err(Error::RandomnessUnavailable),
                "{enc}"
            );
        }
    }

    #[test]
    fn aad_is_the_encoded_protected_header_and_the_encoded_jwe_aad() {
        assert_eq!(*aad("eyJ9", None), b"eyJ9");
        assert_eq!(*aad("eyJ9", Some(b"\xff")), b"eyJ9._w");
        // No protected header (RFC 7516 §7.2.1): the '.' still separates.
        assert_eq!(*aad("", Some(b"\xff")), b"._w");
        assert_eq!(*aad("", None), b"");
    }

    /// The AAD holds `BASE64URL(JWE AAD)`, which can carry application
    /// secrets (ADR 0050 §4), so it is wiped on drop and allocated once at
    /// its final size: a reallocation would free an unwiped prefix (0006
    /// security audit L3).
    #[test]
    fn aad_is_zeroizing_and_never_reallocated() {
        for (protected, jwe_aad) in [
            ("", None),
            ("eyJ9", None),
            ("", Some(&b"\xff"[..])),
            (
                "eyJlbmMiOiJBMTI4R0NNIn0",
                Some(&b"0123456789abcdef0123456789abcdef"[..]),
            ),
            ("eyJ9", Some(&[7u8; 1000][..])),
        ] {
            let full: Zeroizing<Vec<u8>> = aad(protected, jwe_aad);
            assert_eq!(full.capacity(), full.len(), "{protected} {jwe_aad:?}");
        }
    }

    /// The content-encryption part of one RFC 7520 §5 example, read from
    /// the vendored ietf-jose cookbook JSON (`tests/third_party/
    /// ietf-jose-cookbook/`, Unlicense), not transcribed by hand.
    struct Cookbook {
        enc: ContentEncAlg,
        /// The encoded protected header as printed, or `""` when the
        /// example has none (RFC 7520 §5.12).
        protected_b64: String,
        /// The JWE AAD as raw bytes (`input.aad`, RFC 7520 §5.10).
        jwe_aad: Option<Vec<u8>>,
        /// `BASE64URL(JWE AAD)` as the RFC prints it.
        jwe_aad_b64: Option<String>,
        /// The CEK: `generated.cek`, or the `dir` key itself (§5.6).
        cek: Vec<u8>,
        iv: Vec<u8>,
        /// The bytes that are encrypted: the plaintext, or for `zip: DEF`
        /// the RFC's compressed bytes (§5.9, erratum 7680).
        plaintext: Vec<u8>,
        ciphertext: Vec<u8>,
        tag: Vec<u8>,
    }

    fn b64(text: &str) -> Vec<u8> {
        crate::util::b64url_decode(text).unwrap()
    }

    fn cookbook(json: &str) -> Cookbook {
        let doc: serde_json::Value = serde_json::from_str(json).unwrap();
        let text = |v: &serde_json::Value| v.as_str().unwrap().to_owned();
        let content = &doc["encrypting_content"];
        Cookbook {
            enc: ContentEncAlg::from(doc["input"]["enc"].as_str().unwrap()),
            protected_b64: content.get("protected_b64u").map(text).unwrap_or_default(),
            jwe_aad: doc["input"].get("aad").map(|v| text(v).into_bytes()),
            jwe_aad_b64: doc["generated"].get("aad_b64u").map(text),
            cek: b64(doc["generated"]
                .get("cek")
                .unwrap_or(&doc["input"]["key"]["k"])
                .as_str()
                .unwrap()),
            iv: b64(doc["generated"]["iv"].as_str().unwrap()),
            plaintext: match doc["generated"].get("plaintext_c") {
                Some(compressed) => b64(compressed.as_str().unwrap()),
                None => text(&doc["input"]["plaintext"]).into_bytes(),
            },
            ciphertext: b64(content["ciphertext"].as_str().unwrap()),
            tag: b64(content["tag"].as_str().unwrap()),
        }
    }

    const RFC7520_5_10: &str = include_str!(
        "../../tests/third_party/ietf-jose-cookbook/jwe/5_10.including_additional_authentication_data.json"
    );
    const RFC7520_5_12: &str = include_str!(
        "../../tests/third_party/ietf-jose-cookbook/jwe/5_12.protecting_content_only.json"
    );

    /// Every RFC 7520 §5 example whose `enc` is A*GCM.
    const RFC7520_GCM: [(&str, &str); 8] = [
        (
            "§5.2",
            include_str!(
                "../../tests/third_party/ietf-jose-cookbook/jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json"
            ),
        ),
        (
            "§5.4",
            include_str!(
                "../../tests/third_party/ietf-jose-cookbook/jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json"
            ),
        ),
        (
            "§5.6",
            include_str!(
                "../../tests/third_party/ietf-jose-cookbook/jwe/5_6.direct_encryption_using_aes-gcm.json"
            ),
        ),
        (
            "§5.8",
            include_str!(
                "../../tests/third_party/ietf-jose-cookbook/jwe/5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json"
            ),
        ),
        (
            "§5.9",
            include_str!(
                "../../tests/third_party/ietf-jose-cookbook/jwe/5_9.compressed_content.json"
            ),
        ),
        ("§5.10", RFC7520_5_10),
        (
            "§5.11",
            include_str!(
                "../../tests/third_party/ietf-jose-cookbook/jwe/5_11.protecting_specific_header_fields.json"
            ),
        ),
        ("§5.12", RFC7520_5_12),
    ];

    #[test]
    fn gcm_reproduces_the_rfc_7520_content_encryption() {
        // RFC 7520 §5.x.4/§5.x.5: from the printed CEK, IV and AAD, the
        // content layer gives the printed ciphertext and tag byte for
        // byte, and decrypts them back (RFC 7516 §5.1 step 15, §5.2
        // step 16). The key-management layer is not involved.
        let mut seen = Vec::new();
        for (section, json) in RFC7520_GCM {
            let ex = cookbook(json);
            assert!(GCM.contains(&ex.enc), "{section}: {}", ex.enc);
            seen.push(ex.enc.clone());
            let cek = Cek::from_slice(&ex.cek);
            let full_aad = aad(&ex.protected_b64, ex.jwe_aad.as_deref());
            let sealed = encrypt(&ex.enc, &cek, &ex.iv, &full_aad, &ex.plaintext).unwrap();
            assert_eq!(sealed, (ex.ciphertext.clone(), ex.tag.clone()), "{section}");
            let opened =
                decrypt(&ex.enc, &cek, &ex.iv, &full_aad, &ex.ciphertext, &ex.tag).unwrap();
            assert_eq!(opened.as_slice(), ex.plaintext, "{section}");
            // The AAD is bound: another JWE AAD (or one added) fails.
            let other = aad(&ex.protected_b64, Some(b"x"));
            assert_eq!(
                decrypt(&ex.enc, &cek, &ex.iv, &other, &ex.ciphertext, &ex.tag),
                Err(Error::DecryptionFailed),
                "{section}"
            );
        }
        assert!(seen.contains(&ContentEncAlg::A128GCM));
        assert!(seen.contains(&ContentEncAlg::A256GCM));
    }

    #[test]
    fn aad_matches_rfc_7520_5_10() {
        // RFC 7520 §5.10.4: the AAD is ASCII(protected || '.' ||
        // BASE64URL(JWE AAD)). The JWE AAD is encoded here from the raw
        // vCard text and must equal the RFC's printed encoding.
        let example = cookbook(RFC7520_5_10);
        let (raw, printed) = (example.jwe_aad.unwrap(), example.jwe_aad_b64.unwrap());
        let expected = format!("{}.{printed}", example.protected_b64);
        assert!(expected.starts_with("eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIy"));
        assert!(expected.ends_with(".WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxbImZuIix7fSwidGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4iLHt9LCJ0ZXh0IixbIkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIsIiJdXSxbImJkYXkiLHt9LCJ0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVyIix7fSwidGV4dCIsIk0iXV1d"));
        assert_eq!(
            *aad(&example.protected_b64, Some(&raw)),
            expected.as_bytes()
        );
        // Without the JWE AAD only the protected header is authenticated.
        assert_eq!(
            *aad(&example.protected_b64, None),
            example.protected_b64.as_bytes()
        );
    }

    #[test]
    fn aad_is_empty_without_protected_header_or_jwe_aad() {
        // RFC 7520 §5.12: no protected header and no AAD, so the AAD is
        // ASCII("") (RFC 7516 §5.1 step 14).
        let example = cookbook(RFC7520_5_12);
        assert_eq!(example.protected_b64, "");
        assert!(example.jwe_aad.is_none());
        assert_eq!(*aad(&example.protected_b64, None), b"");
        // An empty protected header with a JWE AAD keeps the '.'.
        assert_eq!(
            *aad("", Some(b"[\"vcard\"]")),
            format!(".{}", b64url_encode(b"[\"vcard\"]")).as_bytes()
        );
    }

    const GCM: [ContentEncAlg; 3] = [
        ContentEncAlg::A128GCM,
        ContentEncAlg::A192GCM,
        ContentEncAlg::A256GCM,
    ];
    const CBC: [ContentEncAlg; 3] = [
        ContentEncAlg::A128CbcHs256,
        ContentEncAlg::A192CbcHs384,
        ContentEncAlg::A256CbcHs512,
    ];

    #[test]
    fn gcm_dispatches_to_enc_gcm() {
        // RFC 7518 §5.3: the dispatcher hands the CEK bytes through
        // unchanged, so its output is exactly enc_gcm's.
        for enc in &GCM {
            let cek = Cek::from_slice(&vec![0x42; cek_len(enc).unwrap()]);
            let iv = [9u8; 12];
            let sealed = encrypt(enc, &cek, &iv, b"aad", b"msg").unwrap();
            assert_eq!(
                sealed,
                enc_gcm::encrypt(enc, cek.as_bytes(), &iv, b"aad", b"msg").unwrap()
            );
            let (ct, tag) = sealed;
            let opened = decrypt(enc, &cek, &iv, b"aad", &ct, &tag).unwrap();
            assert_eq!(opened.as_slice(), b"msg", "{enc}");
        }
    }

    #[test]
    fn cbc_dispatches_to_enc_cbc_hmac() {
        // RFC 7518 §5.2 is enc_cbc_hmac's (T03): whatever it answers, the
        // dispatcher answers the same, in both directions.
        for enc in &CBC {
            let cek = Cek::from_slice(&vec![0x42; cek_len(enc).unwrap()]);
            let iv = [9u8; 16];
            assert_eq!(
                encrypt(enc, &cek, &iv, b"aad", b"msg"),
                enc_cbc_hmac::encrypt(enc, cek.as_bytes(), &iv, b"aad", b"msg"),
                "{enc}"
            );
            assert_eq!(
                decrypt(enc, &cek, &iv, b"aad", b"msg", &[0; 16]),
                enc_cbc_hmac::decrypt(enc, cek.as_bytes(), &iv, b"aad", b"msg", &[0; 16]),
                "{enc}"
            );
        }
    }

    #[test]
    fn unknown_enc_is_unsupported_in_both_directions() {
        // RFC 7516 §4.1.2: an `enc` the implementation does not support
        // is rejected; it never reaches a cipher.
        let unknown = ContentEncAlg::from("A128CTR");
        let cek = Cek::from_slice(&[0; 16]);
        assert_eq!(
            encrypt(&unknown, &cek, &[0; 12], b"", b"msg"),
            Err(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            decrypt(&unknown, &cek, &[0; 12], b"", b"msg", &[0; 16]),
            Err(Error::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn every_gcm_decrypt_failure_is_the_same_unit_error() {
        // RFC 7516 §11.4/§11.5: bad tag, ciphertext, IV, AAD or CEK length
        // all give DecryptionFailed, which carries no data, so no
        // plaintext byte can be returned with it.
        for enc in &GCM {
            let n = cek_len(enc).unwrap();
            let cek = Cek::from_slice(&vec![0x42; n]);
            let iv = [9u8; 12];
            let (ct, tag) = encrypt(enc, &cek, &iv, b"aad", b"secret plaintext").unwrap();
            let mut bad_tag = tag.clone();
            bad_tag[0] ^= 1;
            let mut bad_ct = ct.clone();
            bad_ct[3] ^= 4;
            let short_cek = Cek::from_slice(&vec![0x42; n - 1]);
            let results = [
                decrypt(enc, &cek, &iv, b"aad", &ct, &bad_tag),
                decrypt(enc, &cek, &iv, b"aad", &bad_ct, &tag),
                decrypt(enc, &cek, &[9; 16], b"aad", &ct, &tag),
                decrypt(enc, &cek, &iv, b"aae", &ct, &tag),
                decrypt(enc, &cek, &iv, b"aad", &ct, &tag[..12]),
                decrypt(enc, &short_cek, &iv, b"aad", &ct, &tag),
            ];
            for result in results {
                assert_eq!(result, Err(Error::DecryptionFailed), "{enc}");
                let error = result.unwrap_err();
                assert_eq!(format!("{error:?}"), "DecryptionFailed");
                assert!(!error.to_string().contains("secret"));
            }
        }
    }

    /// Wycheproof AES-GCM tests whose group polyjose rejects as a whole:
    /// every IV size but 96 bits (64, 128, 120, 160, 256, 512, 1024, 2056,
    /// 8–80 bits). The 0-bit groups (tcId 311–316) are `invalid` upstream
    /// too, so they need no entry.
    const AES_GCM: &[wycheproof::Deviation] = &[
        wycheproof::Deviation::range(68, 90, Outcome::Reject, GCM_IV_ONLY_96),
        wycheproof::Deviation::range(157, 175, Outcome::Reject, GCM_IV_ONLY_96),
        wycheproof::Deviation::range(240, 310, Outcome::Reject, GCM_IV_ONLY_96),
    ];
    const GCM_IV_ONLY_96: &str = "RFC 7518 §5.3: JWE AES-GCM requires a 96-bit IV";

    /// The `enc` of a Wycheproof AES-GCM group, if JWE has one: a 96-bit
    /// IV, a 128-bit tag and a 128-, 192- or 256-bit key (RFC 7518 §5.3).
    fn jwe_enc(group: &wycheproof::Group) -> Option<ContentEncAlg> {
        if (group.iv_size, group.tag_size) != (Some(96), Some(128)) {
            return None;
        }
        match group.key_size {
            Some(128) => Some(ContentEncAlg::A128GCM),
            Some(192) => Some(ContentEncAlg::A192GCM),
            Some(256) => Some(ContentEncAlg::A256GCM),
            _ => None,
        }
    }

    #[test]
    fn wycheproof_aes_gcm() {
        // Every in-scope `valid` test round-trips exactly (the ciphertext
        // and detached tag, and the plaintext back); every `invalid` one is
        // DecryptionFailed (RFC 7516 §5.2 step 16, §11.4). Groups JWE
        // cannot express still run through decrypt and must be rejected;
        // they are counted so nothing is skipped silently.
        let suite = wycheproof::load("aes_gcm");
        let (mut run, mut skipped) = (0usize, 0usize);
        let summary = wycheproof::assert_conforms(&suite, AES_GCM, |group, test| {
            let input = test.aead();
            let cek = Cek::from_slice(&input.key);
            let Some(enc) = jwe_enc(group) else {
                skipped += 1;
                // Decrypt as A*GCM by key size: the IV length rejects it.
                let enc = match input.key.len() {
                    16 => ContentEncAlg::A128GCM,
                    24 => ContentEncAlg::A192GCM,
                    _ => ContentEncAlg::A256GCM,
                };
                let opened = decrypt(&enc, &cek, &input.iv, &input.aad, &input.ct, &input.tag);
                assert_eq!(opened, Err(Error::DecryptionFailed), "tcId {}", test.tc_id);
                return Outcome::Reject;
            };
            run += 1;
            let opened = decrypt(&enc, &cek, &input.iv, &input.aad, &input.ct, &input.tag);
            if test.result == wycheproof::Expected::Valid {
                let sealed = encrypt(&enc, &cek, &input.iv, &input.aad, &input.msg);
                assert_eq!(
                    sealed,
                    Ok((input.ct.clone(), input.tag.clone())),
                    "tcId {}",
                    test.tc_id
                );
                let opened = opened.as_ref().map(|pt| pt.as_slice());
                assert_eq!(opened, Ok(input.msg.as_slice()), "tcId {}", test.tc_id);
            } else if opened.is_err() {
                assert_eq!(opened, Err(Error::DecryptionFailed), "tcId {}", test.tc_id);
            }
            Outcome::of(&opened)
        });
        // The pinned file: 316 tests in 45 groups; 3 groups (128-, 192- and
        // 256-bit keys, 96-bit IV, 128-bit tag) with 197 tests are JWE's.
        let in_scope = suite.groups.iter().filter(|g| jwe_enc(g).is_some()).count();
        assert_eq!((in_scope, suite.groups.len() - in_scope), (3, 42));
        assert_eq!((run, skipped, summary.tests), (197, 119, 316));
        assert_eq!(summary.accepted, 116);
    }

    mod properties {
        use proptest::prelude::*;

        use super::super::*;
        use super::GCM;

        /// An A*GCM `enc` with a key of its size, a 96-bit IV, and up to
        /// 256 bytes of plaintext and 64 of AAD.
        fn gcm_input() -> impl Strategy<Value = (ContentEncAlg, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>
        {
            (0..GCM.len()).prop_flat_map(|i| {
                let enc = GCM[i].clone();
                let n = cek_len(&enc).unwrap();
                (
                    Just(enc),
                    proptest::collection::vec(any::<u8>(), n),
                    proptest::collection::vec(any::<u8>(), 12),
                    proptest::collection::vec(any::<u8>(), 0..=64),
                    proptest::collection::vec(any::<u8>(), 0..=256),
                )
            })
        }

        proptest! {
            // ADR 0008 layer 2: bounded case counts in the fast suite.
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// RFC 7516 §5.1 step 15 and §5.2 step 16: decrypt inverts
            /// encrypt for every key size, plaintext and AAD, with a
            /// same-length ciphertext and a 128-bit tag (RFC 7518 §5.3).
            #[test]
            fn gcm_round_trips((enc, key, iv, aad, msg) in gcm_input()) {
                let cek = Cek::from_slice(&key);
                let (ct, tag) = encrypt(&enc, &cek, &iv, &aad, &msg)?;
                prop_assert_eq!((ct.len(), tag.len()), (msg.len(), 16));
                let opened = decrypt(&enc, &cek, &iv, &aad, &ct, &tag)?;
                prop_assert_eq!(opened.as_slice(), msg.as_slice());
            }

            /// RFC 7516 §5.2 step 16, RFC 7518 §5.3: flipping any one bit
            /// of the ciphertext, tag, IV or AAD makes decryption fail with
            /// the detail-free DecryptionFailed.
            #[test]
            fn gcm_rejects_any_one_bit_flip(
                (enc, key, iv, aad, msg) in gcm_input(),
                bit in any::<usize>(),
            ) {
                let cek = Cek::from_slice(&key);
                let (ct, tag) = encrypt(&enc, &cek, &iv, &aad, &msg)?;
                let mut parts = [ct, tag, iv, aad];
                let total: usize = parts.iter().map(|p| p.len() * 8).sum();
                let mut at = bit % total;
                for part in parts.iter_mut() {
                    if at < part.len() * 8 {
                        part[at / 8] ^= 1 << (at % 8);
                        break;
                    }
                    at -= part.len() * 8;
                }
                let [ct, tag, iv, aad] = parts;
                prop_assert_eq!(
                    decrypt(&enc, &cek, &iv, &aad, &ct, &tag),
                    Err(Error::DecryptionFailed)
                );
            }
        }
    }
}
