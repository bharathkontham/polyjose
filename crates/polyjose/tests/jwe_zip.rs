//! JWE `zip: "DEF"` through the public API (0003 T15): RFC 7516 §4.1.3,
//! §5.1 step 11 and §5.2 step 17, RFC 8725 §3.6, ADR 0017.
//!
//! - In every build: any `zip` other than `DEF` is `UnsupportedAlgorithm`,
//!   and so is `DEF` without the `deflate` feature, where
//!   `Encryptor::compress` does not exist either.
//! - With `deflate`: RFC 7520 §5.9 (A128KW + A128GCM + DEF) decrypts to the
//!   Figure 72 plaintext in the compact form; our compressed output round
//!   trips and inflates with an independent decoder (byte-exact compression
//!   is not required, erratum 7680); `max_decompressed_len` is inclusive,
//!   0 rejects every `zip` JWE, and a 1 GiB bomb (about 1 MiB of input)
//!   is `DecryptionFailed`.
//!
//! The JSON forms of §5.9 wait for the JSON serialization (T14) and are
//! T16's. That inflation never starts before the tag verifies, and that
//! the inflater gets exactly the policy bound (so it allocates at most
//! that), are unit tests in `src/jwe/zip.rs`, next to the
//! `test_counters::inflate_calls` counter they read.
#![allow(clippy::panic)] // test code: a panic is a failed assertion

use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, decrypt_compact};
use polyjose::jwk::Jwk;
use polyjose::util::b64url_encode;

use ContentEncAlg as E;
use KeyMgmtAlg as A;

fn oct(bytes: &[u8]) -> Jwk {
    let json = format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(bytes));
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"))
}

fn policy(algs: &[KeyMgmtAlg], encs: &[ContentEncAlg]) -> DecryptPolicy {
    DecryptPolicy::new(algs, encs).unwrap_or_else(|e| panic!("{e}"))
}

fn code<T>(result: polyjose::Result<T>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

/// A compact JWE (RFC 7516 §7.1) from a protected header given as JSON text
/// and raw parts.
fn forge(
    header_json: &str,
    encrypted_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> String {
    [
        b64url_encode(header_json.as_bytes()),
        b64url_encode(encrypted_key),
        b64url_encode(iv),
        b64url_encode(ciphertext),
        b64url_encode(tag),
    ]
    .join(".")
}

const DIR_KEY: [u8; 16] = [0x5A; 16];
const IV: [u8; 12] = [7; 12];

fn dir_policy() -> DecryptPolicy {
    policy(&[A::Dir], &[E::A128GCM])
}

#[test]
fn a_zip_other_than_def_is_unsupported_in_every_build() {
    // RFC 7516 §4.1.3, RFC 7518 §7.3: `DEF` is the only value defined and
    // is case-sensitive. The check comes before key management, so the
    // other parts do not matter.
    for zip in ["GZIP", "def", "Def", "DEF ", "", "deflate"] {
        let header = format!(r#"{{"alg":"dir","enc":"A128GCM","zip":"{zip}"}}"#);
        let token = forge(&header, &[], &IV, &[0; 8], &[0; 16]);
        assert_eq!(
            code(decrypt_compact(&token, &oct(&DIR_KEY), &dir_policy())),
            "UnsupportedAlgorithm",
            "{zip:?}"
        );
    }
    // A registered parameter of the wrong type is a header error.
    let token = forge(
        r#"{"alg":"dir","enc":"A128GCM","zip":1}"#,
        &[],
        &IV,
        &[0; 8],
        &[0; 16],
    );
    assert_eq!(
        code(decrypt_compact(&token, &oct(&DIR_KEY), &dir_policy())),
        "InvalidHeader"
    );
}

#[cfg(not(feature = "deflate"))]
mod without_deflate {
    use super::*;

    #[test]
    fn zip_def_is_unsupported() {
        // ADR 0017 §5, ADR 0006: no codec, so `DEF` is not supported, even
        // with a well-formed, authenticated-looking token.
        let token = forge(
            r#"{"alg":"dir","enc":"A128GCM","zip":"DEF"}"#,
            &[],
            &IV,
            &[0; 8],
            &[0; 16],
        );
        assert_eq!(
            code(decrypt_compact(&token, &oct(&DIR_KEY), &dir_policy())),
            "UnsupportedAlgorithm"
        );
    }

    /// Method-resolution probe: an inherent `Encryptor::compress` would be
    /// picked before this trait method (inherent methods take priority),
    /// and its `Encryptor` result would not compile as `&str`. So this
    /// builds only while the method does not exist.
    trait Probe {
        fn compress(self) -> &'static str;
    }

    impl Probe for Encryptor {
        fn compress(self) -> &'static str {
            "no inherent compress"
        }
    }

    #[test]
    fn encryptor_compress_does_not_exist() {
        // RFC 8725 §3.6: compression before encryption is opt-in, and only
        // with the `deflate` feature.
        let probe: &'static str = Encryptor::new(E::A128GCM).compress();
        assert_eq!(probe, "no inherent compress");
    }
}

#[cfg(feature = "deflate")]
mod with_deflate {
    use aes_gcm::aead::consts::U12;
    use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit, Nonce};
    use polyjose::json::{self, Value};
    use polyjose::jwe::Recipient;
    use polyjose::util::b64url_decode;
    use proptest::prelude::*;

    use super::*;

    /// A `dir` + A128GCM + `zip: DEF` JWE whose authenticated plaintext is
    /// `payload` exactly, sealed with an independent AES-GCM (the RustCrypto
    /// crate directly), so it can hold a stream polyjose never writes.
    fn zip_token(payload: &[u8]) -> String {
        let header = r#"{"alg":"dir","enc":"A128GCM","zip":"DEF"}"#;
        let aad = b64url_encode(header.as_bytes());
        let cipher = Aes128Gcm::new_from_slice(&DIR_KEY).unwrap_or_else(|e| panic!("{e}"));
        let nonce = Nonce::<U12>::try_from(&IV[..]).unwrap_or_else(|e| panic!("{e}"));
        let mut buffer = payload.to_vec();
        let tag = cipher
            .encrypt_inout_detached(&nonce, aad.as_bytes(), buffer.as_mut_slice().into())
            .unwrap_or_else(|e| panic!("{e}"));
        forge(header, &[], &IV, &buffer, &tag)
    }

    /// The A128GCM plaintext of a `dir` JWE, opened with the same
    /// independent AES-GCM: what polyjose compressed, before inflation.
    fn open(token: &str) -> Vec<u8> {
        let parts: Vec<&str> = token.split('.').collect();
        let bytes = |s: &str| b64url_decode(s).unwrap_or_else(|e| panic!("{e}"));
        let cipher = Aes128Gcm::new_from_slice(&DIR_KEY).unwrap_or_else(|e| panic!("{e}"));
        let nonce = Nonce::<U12>::try_from(&bytes(parts[2])[..]).unwrap_or_else(|e| panic!("{e}"));
        let tag = bytes(parts[4]);
        let tag = tag[..].try_into().unwrap_or_else(|e| panic!("{e}"));
        let mut buffer = bytes(parts[3]);
        cipher
            .decrypt_inout_detached(
                &nonce,
                parts[0].as_bytes(),
                buffer.as_mut_slice().into(),
                tag,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        buffer
    }

    fn compressed_dir_token(plaintext: &[u8]) -> String {
        Encryptor::new(E::A128GCM)
            .compress()
            .recipient(Recipient::new(A::Dir, &oct(&DIR_KEY)))
            .encrypt_compact(plaintext)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn header_of(token: &str) -> Value {
        let protected = token.split('.').next().unwrap_or_default();
        let bytes = b64url_decode(protected).unwrap_or_else(|e| panic!("{e}"));
        json::parse(&bytes).unwrap_or_else(|e| panic!("{e}"))
    }

    // -----------------------------------------------------------------
    // RFC 7520 §5.9
    // -----------------------------------------------------------------

    /// The vendored ietf-jose cookbook entry for RFC 7520 §5.9, read at run
    /// time so no value is transcribed.
    fn cookbook_5_9() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/third_party/ietf-jose-cookbook/jwe/5_9.compressed_content.json"
        );
        let text = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        json::parse(&text).unwrap_or_else(|e| panic!("{e}"))
    }

    fn string<'a>(value: &'a Value, path: &[&str]) -> &'a str {
        path.iter()
            .try_fold(value, |v, name| v.get(name))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no string at {path:?}"))
    }

    /// The RFC 7520 §5 plaintext (Figure 72), with its two U+2013 dashes.
    const FIGURE_72: &str = "You can trust us to stick with you through thick and \
        thin\u{2013}to the bitter end. And you can trust us to keep any secret of yours\u{2013}closer \
        than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off \
        without a word. We are your friends, Frodo.";

    #[test]
    fn rfc_7520_5_9_compact_decrypts_to_figure_72() {
        let cookbook = cookbook_5_9();
        let key = cookbook
            .get("input")
            .and_then(|i| i.get("key"))
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("no key"));
        let key = Jwk::from_object(key).unwrap_or_else(|e| panic!("{e}"));
        let token = string(&cookbook, &["output", "compact"]);
        assert_eq!(string(&cookbook, &["input", "plaintext"]), FIGURE_72);

        let d = decrypt_compact(token, &key, &policy(&[A::A128KW], &[E::A128GCM]))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.plaintext(), FIGURE_72.as_bytes());
        assert_eq!(d.header().zip.as_deref(), Some("DEF"));
        assert_eq!(
            d.header().kid.as_deref(),
            Some("81b20965-8332-43d9-a468-82160ad91ac8")
        );

        // A one-bit change to the tag is the uniform error.
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut tag = b64url_decode(&parts[4]).unwrap_or_else(|e| panic!("{e}"));
        tag[15] ^= 1;
        parts[4] = b64url_encode(&tag);
        assert_eq!(
            code(decrypt_compact(
                &parts.join("."),
                &key,
                &policy(&[A::A128KW], &[E::A128GCM])
            )),
            "DecryptionFailed"
        );
    }

    // -----------------------------------------------------------------
    // Encryption: compress before encrypting
    // -----------------------------------------------------------------

    #[test]
    fn compressed_jwes_round_trip_and_carry_zip_in_the_protected_header() {
        let text = FIGURE_72.repeat(20);
        for (alg, enc, key_len) in [
            (A::A128KW, E::A128GCM, 16),
            (A::Dir, E::A256CbcHs512, 64),
            (A::A256KW, E::A192CbcHs384, 32),
        ] {
            let key = oct(&vec![0x33; key_len]);
            let token = Encryptor::new(enc.clone())
                .compress()
                .recipient(Recipient::new(alg.clone(), &key))
                .encrypt_compact(text.as_bytes())
                .unwrap_or_else(|e| panic!("{e}"));
            // RFC 7516 §4.1.3: `zip` is in the protected header, so it is
            // integrity protected.
            assert_eq!(
                header_of(&token).get("zip").and_then(Value::as_str),
                Some("DEF")
            );
            // The ciphertext is the compressed plaintext's length (plus
            // CBC padding): well under the plaintext.
            let ciphertext = token.split('.').nth(3).unwrap_or_default();
            assert!(ciphertext.len() * 3 / 4 < text.len() / 4, "{alg:?} {enc:?}");
            let d = decrypt_compact(&token, &key, &policy(&[alg], &[enc]))
                .unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(d.plaintext(), text.as_bytes());
        }
    }

    #[test]
    fn our_compressed_output_inflates_with_an_independent_decoder() {
        // Erratum 7680: DEFLATE output is not unique, so instead of the
        // RFC's compressed bytes the check is interoperability: what
        // polyjose encrypted is a raw RFC 1951 stream another decoder
        // (miniz_oxide, a dev-dependency oracle, ADR 0017 §4) reads.
        for plaintext in [FIGURE_72.as_bytes(), b"", &[0xA5; 100_000]] {
            let compressed = open(&compressed_dir_token(plaintext));
            let inflated = miniz_oxide::inflate::decompress_to_vec(&compressed)
                .unwrap_or_else(|e| panic!("{e:?}"));
            assert_eq!(inflated, plaintext);
        }
        // And the other way: a stream another encoder wrote decrypts.
        let other = miniz_oxide::deflate::compress_to_vec(FIGURE_72.as_bytes(), 9);
        let d = decrypt_compact(&zip_token(&other), &oct(&DIR_KEY), &dir_policy())
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.plaintext(), FIGURE_72.as_bytes());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn any_plaintext_round_trips_compressed(
            plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
            repeat in 1usize..8,
        ) {
            let plaintext = plaintext.repeat(repeat);
            let d = decrypt_compact(&compressed_dir_token(&plaintext), &oct(&DIR_KEY), &dir_policy());
            prop_assert_eq!(d.map(|d| d.plaintext().to_vec()), Ok(plaintext));
        }
    }

    // -----------------------------------------------------------------
    // The bound (ADR 0017 §3)
    // -----------------------------------------------------------------

    #[test]
    fn the_default_bound_is_250_000_bytes_inclusive() {
        let plaintext = b"0123456789abcdef".repeat(15_626);
        let exact = compressed_dir_token(&plaintext[..250_000]);
        let d = decrypt_compact(&exact, &oct(&DIR_KEY), &dir_policy())
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.plaintext(), &plaintext[..250_000]);

        let over = compressed_dir_token(&plaintext[..250_001]);
        assert_eq!(
            code(decrypt_compact(&over, &oct(&DIR_KEY), &dir_policy())),
            "DecryptionFailed"
        );
        let raised = dir_policy().max_decompressed_len(250_001);
        assert_eq!(code(decrypt_compact(&over, &oct(&DIR_KEY), &raised)), "ok");
    }

    #[test]
    fn a_zero_bound_rejects_every_zip_jwe() {
        let zero = dir_policy().max_decompressed_len(0);
        // Even an empty plaintext, which inflates to 0 bytes.
        for plaintext in [&b""[..], b"x", FIGURE_72.as_bytes()] {
            let token = compressed_dir_token(plaintext);
            assert_eq!(
                code(decrypt_compact(&token, &oct(&DIR_KEY), &zero)),
                "DecryptionFailed"
            );
            assert_eq!(
                code(decrypt_compact(&token, &oct(&DIR_KEY), &dir_policy())),
                "ok"
            );
        }
        // The bound is for `zip` only: an uncompressed JWE still decrypts.
        let plain = Encryptor::new(E::A128GCM)
            .recipient(Recipient::new(A::Dir, &oct(&DIR_KEY)))
            .encrypt_compact(FIGURE_72.as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(code(decrypt_compact(&plain, &oct(&DIR_KEY), &zero)), "ok");
    }

    /// An RFC 1951 stream written LSB first (§3.1.1); Huffman codes go
    /// most-significant bit first (§3.2.2).
    #[derive(Default)]
    struct Bits {
        out: Vec<u8>,
        len: usize,
    }

    impl Bits {
        fn bit(&mut self, bit: u32) {
            self.zeros(1);
            if let Some(last) = self.out.last_mut() {
                *last |= u8::from(bit & 1 == 1) << ((self.len - 1) % 8);
            }
        }

        fn value(&mut self, value: u32, count: u32) {
            (0..count).for_each(|i| self.bit(value >> i));
        }

        fn code(&mut self, code: u32, count: u32) {
            (0..count).rev().for_each(|i| self.bit(code >> i));
        }

        fn zeros(&mut self, count: usize) {
            self.len += count;
            self.out.resize(self.len.div_ceil(8), 0);
        }
    }

    /// A decompression bomb (CVE-2024-28180, CVE-2024-28176,
    /// CVE-2024-29371): one dynamic block (RFC 1951 §3.2.7) with one-bit
    /// codes for length 258 and distance 1, so after one `a` every two
    /// zero bits expand to 258 more: the 1,032:1 DEFLATE ceiling. Inflates
    /// to `1 + 258 * matches` bytes.
    fn bomb(matches: usize) -> Vec<u8> {
        let mut w = Bits::default();
        w.value(1, 1); // BFINAL
        w.value(0b10, 2); // BTYPE: dynamic
        w.value(286 - 257, 5); // HLIT
        w.value(0, 5); // HDIST: one distance code
        w.value(18 - 4, 4); // HCLEN
        // Code-length code lengths in the §3.2.7 order: 18 -> 1 (code 0),
        // 1 and 2 -> 2 (codes 10 and 11).
        for symbol in [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1] {
            let length = match symbol {
                18 => 1,
                1 | 2 => 2,
                _ => 0,
            };
            w.value(length, 3);
        }
        let zeros = |w: &mut Bits, n: u32| {
            w.code(0, 1); // 18: a run of 11-138 zero lengths
            w.value(n - 11, 7);
        };
        // 'a' -> 2, 256 -> 2, 285 -> 1; distance 0 -> 1.
        zeros(&mut w, 97);
        w.code(0b11, 2);
        zeros(&mut w, 138);
        zeros(&mut w, 20);
        w.code(0b11, 2);
        zeros(&mut w, 28);
        w.code(0b10, 2);
        w.code(0b10, 2);
        // Codes: 285 -> 0, 'a' -> 10, 256 -> 11; distance 0 -> 0.
        w.code(0b10, 2);
        w.zeros(2 * matches);
        w.code(0b11, 2);
        w.out
    }

    #[test]
    fn the_bomb_generator_writes_valid_deflate() {
        let inflated = miniz_oxide::inflate::decompress_to_vec(&bomb(1000))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(inflated.len(), 1 + 258 * 1000);
        assert!(inflated.iter().all(|&b| b == b'a'));
    }

    #[test]
    fn a_1_gib_bomb_is_decryption_failed() {
        // ADR 0017: about 1 MiB of authenticated input that would inflate to
        // 1 GiB stops at the 250,000-byte default. The single up-front
        // allocation is that bound (the inflater is handed exactly it:
        // `zip::tests::inflate_gets_exactly_the_policy_bound`), within the
        // bound plus the 32 KiB window.
        let bomb = bomb((1 << 30) / 258 + 1);
        assert!(bomb.len() < 1100 * 1024, "bomb is {} bytes", bomb.len());
        let token = zip_token(&bomb);

        // Its compact form is over the default 1 MiB input limit, which is
        // checked first (ADR 0026 §7)...
        assert!(token.len() > 1 << 20);
        assert_eq!(
            code(decrypt_compact(&token, &oct(&DIR_KEY), &dir_policy())),
            "InvalidFormat"
        );
        // ...so raise it to reach the inflater.
        let roomy = dir_policy().max_input_len(2 << 20);
        assert_eq!(
            code(decrypt_compact(&token, &oct(&DIR_KEY), &roomy)),
            "DecryptionFailed"
        );
        // Whatever the bound: 64 MiB still stops it.
        let big = roomy.clone().max_decompressed_len(64 << 20);
        assert_eq!(
            code(decrypt_compact(&token, &oct(&DIR_KEY), &big)),
            "DecryptionFailed"
        );

        // A smaller bomb inside the default input limit, the same way.
        let small = zip_token(&bomb[..64 * 1024]);
        assert_eq!(
            code(decrypt_compact(&small, &oct(&DIR_KEY), &dir_policy())),
            "DecryptionFailed"
        );
    }

    #[test]
    fn every_inflate_error_is_the_uniform_decryption_failed() {
        // ADR 0017 §1, RFC 7516 §11.4: a malformed stream under a valid tag
        // is the same unit error as a bad tag.
        let valid = miniz_oxide::deflate::compress_to_vec(FIGURE_72.as_bytes(), 6);
        let malformed: [&[u8]; 6] = [
            b"",                             // no block (RFC 1951 §3.2.3)
            &[0x07],                         // BTYPE 11, reserved
            &[0x01, 0x05, 0x00, 0x00, 0x00], // stored, NLEN not ~LEN (§3.2.4)
            &[0x00],                         // a non-final block, then nothing
            &valid[..valid.len() / 2],       // truncated
            &[0x03],                         // a fixed block cut before end-of-block
        ];
        let mut bad_tag = zip_token(&valid);
        bad_tag.replace_range(bad_tag.len() - 2.., "AA");
        let reference = decrypt_compact(&bad_tag, &oct(&DIR_KEY), &dir_policy()).err();
        assert_eq!(
            reference.as_ref().map(polyjose::Error::code),
            Some("DecryptionFailed")
        );
        for payload in malformed {
            let result = decrypt_compact(&zip_token(payload), &oct(&DIR_KEY), &dir_policy());
            assert_eq!(result.err(), reference, "{payload:?}");
        }
    }
}
