//! Verifying a compact JWS against a JWK Set: candidate selection by
//! `alg` and `kid`, a bounded try-in-order, and `NoMatchingKey`
//! (ADR 0029; RFC 7515 §4.1.4, §6; RFC 7517 §4.2–§4.5, §5).

use crate::error::{Error, Result};
use crate::jwk::{Jwk, JwkSet};
use crate::jws::{
    CompactPrechecked, FAMILIES, Families, Verified, finish_compact, furthest, precheck_compact,
};

use super::Policy;

/// Verifies the compact JWS `token` against the members of `set`
/// (ADR 0029 §2–§4), returning the verified JWS and the selected
/// member's index in [`JwkSet::keys`] (its position in the set as
/// parsed, skipped members not counted).
///
/// This is [`precheck_compact`] (ADR 0026 §2 steps 1–7, with the policy's
/// allow-list and input limit, [`Policy::verify_options`]) followed by
/// [`select_and_verify`]. Only the compact serialization is accepted
/// (RFC 7519 §1), so there is no unprotected header: `alg` and `kid` come
/// from the JWS Protected Header (ADR 0049 §2).
///
/// The key always comes from `set`. A `jwk`, `jku`, `x5u` or `x5c` header
/// parameter never selects, supplies or fetches one (ADR 0026 §2,
/// RFC 8725 §3.10; CVE-2018-0114), and nothing here does any I/O
/// (ADR 0029 §5).
///
/// # Errors
///
/// - Steps 1–7, before any key is looked at: [`Error::InvalidFormat`],
///   [`Error::InvalidBase64`], [`Error::InvalidJson`],
///   [`Error::InvalidHeader`], [`Error::UnknownCritical`],
///   [`Error::UnsupportedAlgorithm`], [`Error::AlgorithmNotAllowed`].
/// - Then [`select_and_verify`]'s errors.
pub(crate) fn verify_with_set(
    token: &str,
    set: &JwkSet,
    p: &Policy<'_>,
) -> Result<(Verified, usize)> {
    verify_with_set_using(&FAMILIES, token, set, p)
}

/// [`verify_with_set`] with the signature primitives taken from
/// `families` (the test seam of `jws/alg.rs`).
fn verify_with_set_using(
    families: &Families,
    token: &str,
    set: &JwkSet,
    p: &Policy<'_>,
) -> Result<(Verified, usize)> {
    let opts = p.verify_options();
    let pre = precheck_compact(token, &opts)?;
    select_and_verify_using(families, &pre, set, p)
}

/// The key-selection half of [`verify_with_set`], on a compact JWS that
/// already passed ADR 0026 §2 steps 1–7 ([`precheck_compact`]). The JWT
/// pipeline calls it after its own header rules, which ADR 0027 §9 puts
/// between step 7 and key selection, so the token is parsed only once.
///
/// 1. **Select** the candidates: [`JwkSet::verification_candidates`] for
///    the header `alg` and the protected header's `kid` (ADR 0029 §2:
///    family, JWK `alg`, `use`, `key_ops`, then exact `kid` equality,
///    RFC 7515 §4.1.4, RFC 7517 §4.2–§4.5). The `kid` is only compared,
///    never used as a path, URL or query (RFC 8725 §3.10).
/// 2. **Bound** them: none, or more than [`Policy::max_key_candidates`],
///    → [`Error::NoMatchingKey`], before any signature is computed
///    (ADR 0029 §4). This bounds the work an unauthenticated token can
///    cause.
/// 3. **Try** each candidate in set order with ADR 0026 §2 steps 8–9
///    ([`finish_compact`]); the first that verifies wins, and its index in
///    [`JwkSet::keys`] is returned with the result.
///
/// # Errors
///
/// - [`Error::NoMatchingKey`]: no candidate, or too many.
/// - When every candidate fails, the failure that progressed furthest
///   (ADR 0026 §3: [`Error::InvalidSignature`] > [`Error::InvalidKey`] >
///   [`Error::KeyAlgorithmMismatch`]), ties going to the lowest index
///   (ADR 0029 §4).
pub(crate) fn select_and_verify(
    pre: &CompactPrechecked<'_>,
    set: &JwkSet,
    p: &Policy<'_>,
) -> Result<(Verified, usize)> {
    select_and_verify_using(&FAMILIES, pre, set, p)
}

/// [`select_and_verify`] with the signature primitives taken from
/// `families`.
fn select_and_verify_using(
    families: &Families,
    pre: &CompactPrechecked<'_>,
    set: &JwkSet,
    p: &Policy<'_>,
) -> Result<(Verified, usize)> {
    let candidates = candidates(pre, set, p.key_candidate_limit())?;
    let mut failures = Vec::with_capacity(candidates.len());
    for (index, key) in candidates {
        // ADR 0029 §4: steps 8-9 per candidate, in set order; the first
        // success wins.
        match finish_compact(families, pre, key) {
            Ok(verified) => return Ok((verified, index)),
            Err(error) => failures.push(error),
        }
    }
    // ADR 0026 §3 ranking over the failures in set order, ties to the
    // lowest index. `candidates` is never empty, so `furthest` always has
    // an error to return.
    Err(furthest(failures).unwrap_or(Error::NoMatchingKey))
}

/// The ADR 0029 §2 candidates for `pre` in `set`, in set order, with
/// their indices: between 1 and `limit` of them, or
/// [`Error::NoMatchingKey`] (ADR 0029 §4).
///
/// `alg` and `kid` are the JWS Protected Header's (ADR 0049 §2). At most
/// `limit + 1` members pass the filter before the answer is known, and no
/// key material is used.
fn candidates<'a>(
    pre: &'a CompactPrechecked<'_>,
    set: &'a JwkSet,
    limit: usize,
) -> Result<Vec<(usize, &'a Jwk)>> {
    let kid = pre.header().kid.as_deref();
    let found: Vec<(usize, &Jwk)> = set
        .verification_candidates(pre.alg(), kid)
        .take(limit.saturating_add(1))
        .collect();
    if found.is_empty() || found.len() > limit {
        return Err(Error::NoMatchingKey);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwa::SigningAlg as A;
    use crate::jws::{ProtectedHeader, SignOptions, sign_compact};
    use crate::jwt::FixedClock;
    use crate::test_counters::{jws_family_signs as signs, jws_family_verifies as verifies};
    use crate::util::b64url_encode;

    // ---- Fixtures ----

    /// An EC key pair as base64url coordinates and private scalar.
    struct Ec {
        x: &'static str,
        y: &'static str,
        d: &'static str,
    }

    // P-256 key pairs from the JWT oracle's keys.json (feature 0004 T02,
    // `conformance/tools/jwt-oracle/keys.json`), generated once for the
    // ADR 0029 key-selection tests.
    /// `p256-kid-a`.
    const KEY_A: Ec = Ec {
        x: "9k4oxJo3yFhw4XvUDFOFlmhgwqGrC25aBd7xhpkFB6Y",
        y: "zE-06UddsK2b0rpGKPXn9gz55y3tneIwQbTHPYn4o_I",
        d: "LCPRTP8np_fQxQvMdfDwaCr30xArOCNFsTMqauaxMF8",
    };
    /// `p256-kid-b`.
    const KEY_B: Ec = Ec {
        x: "kYUQsFzddzDVWQ2zrOHzLvP5Xh0vfUGlmngWR9XMJTw",
        y: "8uWP4BrVkuiNMETAGTs-RXFQpR9p5DtW6MzL2D6yXX8",
        d: "77vIcbbx8enORFALjumhmnHnLbvyhFLORpLTTENmDdA",
    };
    /// `p256-kid-c`, the `key_ops: ["sign"]` member of [`SELECTION`].
    const KEY_C: Ec = Ec {
        x: "Tb3zGAzRHxCqmkYrR0PJBzFoP-eeWagnQAwuoQEqBXA",
        y: "32fch9uDiHQleNvG6vnJRjtKAYay5rt63qo37QGgzjU",
        d: "iHOPbFusnHIn0GPpRrq0xQEgS833Dv78gj_w-sm7jeg",
    };
    /// `p256-cand-1`, a kid-less candidate.
    const CAND_1: Ec = Ec {
        x: "veFmhYCtqSHviMxLOuvn3KOaC1prHxYfq5GI9sCTgMc",
        y: "aVnGcc1rZHjUHOPyuGItVPHbMds_wEoTO9mil0DSgTE",
        d: "gGRJxEwTfHm6o1cdxJ5K3HOaQKOuB3pJQ06XXuBfleA",
    };
    /// RFC 7520 §5.4.1's P-384 key (keys.json `p384`), public part.
    const P384_PUBLIC: &str = r#""kty":"EC","crv":"P-384","x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2","y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP""#;
    /// RFC 8037 Appendix A.1's Ed25519 key, public part.
    const ED25519_PUBLIC: &str =
        r#""kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo""#;
    /// RFC 8037 Appendix A.1's Ed25519 private key `d`.
    const ED25519_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

    /// The public members of a P-256 key, followed by `extra` members.
    fn p256_member(key: &Ec, extra: &str) -> String {
        format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"{extra}}}"#,
            key.x, key.y
        )
    }

    /// The private P-256 JWK the tests sign with.
    fn p256_signer(key: &Ec) -> Jwk {
        Jwk::from_json(p256_member(key, &format!(r#","d":"{}""#, key.d)).as_bytes()).unwrap()
    }

    fn set(members: &[&str]) -> JwkSet {
        JwkSet::from_json(format!(r#"{{"keys":[{}]}}"#, members.join(",")).as_bytes()).unwrap()
    }

    /// The seven-key set of the selection criteria, in this order:
    /// 0. P-256, `kid` `a`
    /// 1. P-256, `kid` `b`
    /// 2. P-256, no `kid`
    /// 3. P-384, `kid` `a`
    /// 4. `oct`, `kid` `h`
    /// 5. Ed25519, `use: enc`
    /// 6. P-256, `key_ops: ["sign"]`
    fn selection() -> JwkSet {
        let oct = format!(
            r#"{{"kty":"oct","k":"{}","kid":"h"}}"#,
            b64url_encode(&[0x11; 32])
        );
        let set = set(&[
            &p256_member(&KEY_A, r#","kid":"a""#),
            &p256_member(&KEY_B, r#","kid":"b""#),
            &p256_member(&CAND_1, ""),
            &format!(r#"{{{P384_PUBLIC},"kid":"a"}}"#),
            &oct,
            &format!(r#"{{{ED25519_PUBLIC},"use":"enc"}}"#),
            &p256_member(&KEY_C, r#","key_ops":["sign"]"#),
        ]);
        assert_eq!((set.len(), set.skipped()), (7, 0));
        set
    }

    /// Every algorithm the tests use.
    const ALGS: &[A] = &[A::ES256, A::ES384, A::EdDSA, A::HS256, A::RS256];
    const CLOCK: FixedClock = FixedClock(0);

    fn policy() -> Policy<'static> {
        Policy::new(&CLOCK, ALGS).unwrap()
    }

    const PAYLOAD: &[u8] = br#"{"sub":"keyset"}"#;

    /// A compact JWS of [`PAYLOAD`] with the protected header `header`
    /// (exact JSON text), signed by `key` (RFC 7515 §5.1).
    fn token(header: &str, key: &Jwk) -> String {
        let protected = ProtectedHeader::from_encoded(&b64url_encode(header.as_bytes())).unwrap();
        sign_compact(&protected, PAYLOAD, key, &SignOptions::new()).unwrap()
    }

    fn es256(header: &str, key: &Ec) -> String {
        token(header, &p256_signer(key))
    }

    /// The candidate indices ADR 0029 §2 selects for `token`.
    fn candidate_indices(token: &str, set: &JwkSet, p: &Policy<'_>) -> Result<Vec<usize>> {
        let opts = p.verify_options();
        let pre = precheck_compact(token, &opts)?;
        let found = candidates(&pre, set, p.key_candidate_limit())?;
        Ok(found.into_iter().map(|(index, _)| index).collect())
    }

    /// The real families, counting every call (ADR 0026 §2 step 9, and
    /// `sign`, which verification must never reach).
    const COUNTING: Families = Families {
        sign: |alg, key, input| {
            signs::tick();
            (FAMILIES.sign)(alg, key, input)
        },
        verify: |alg, key, input, signature| {
            verifies::tick();
            (FAMILIES.verify)(alg, key, input, signature)
        },
    };

    /// [`verify_with_set`] through [`COUNTING`]: the result, then the
    /// number of family `verify` and `sign` calls it made.
    fn counted(token: &str, set: &JwkSet, p: &Policy<'_>) -> (Result<usize>, u64, u64) {
        let ((result, verify_calls), sign_calls) =
            signs::count(|| verifies::count(|| verify_with_set_using(&COUNTING, token, set, p)));
        (result.map(|(_, index)| index), verify_calls, sign_calls)
    }

    fn selected(token: &str, set: &JwkSet) -> Result<usize> {
        verify_with_set(token, set, &policy()).map(|(_, index)| index)
    }

    // ---- Selection (ADR 0029 §2) ----

    #[test]
    fn kid_b_selects_exactly_the_p256_b_key() {
        let jws = es256(r#"{"alg":"ES256","kid":"b"}"#, &KEY_B);
        assert_eq!(
            candidate_indices(&jws, &selection(), &policy()),
            Ok(vec![1])
        );
        let (verified, index) = verify_with_set(&jws, &selection(), &policy()).unwrap();
        assert_eq!(index, 1);
        assert_eq!(verified.alg, A::ES256);
        assert_eq!(&verified.payload[..], PAYLOAD);
    }

    /// The P-384 key with the same `kid` is excluded by family (ADR 0026
    /// §2 step 8).
    #[test]
    fn kid_a_selects_only_the_p256_a_key() {
        let jws = es256(r#"{"alg":"ES256","kid":"a"}"#, &KEY_A);
        assert_eq!(
            candidate_indices(&jws, &selection(), &policy()),
            Ok(vec![0])
        );
        assert_eq!(selected(&jws, &selection()), Ok(0));
    }

    /// Without a `kid`, every compatible key in set order; the
    /// `key_ops: ["sign"]` key is not one (RFC 7517 §4.3).
    #[test]
    fn no_kid_selects_every_compatible_p256_key_in_set_order() {
        let jws = es256(r#"{"alg":"ES256"}"#, &CAND_1);
        assert_eq!(
            candidate_indices(&jws, &selection(), &policy()),
            Ok(vec![0, 1, 2])
        );
        assert_eq!(counted(&jws, &selection(), &policy()), (Ok(2), 3, 0));
    }

    #[test]
    fn unknown_kid_is_no_matching_key_before_any_signature() {
        let jws = es256(r#"{"alg":"ES256","kid":"zzz"}"#, &KEY_A);
        assert_eq!(
            counted(&jws, &selection(), &policy()),
            (Err(Error::NoMatchingKey), 0, 0)
        );
    }

    /// The only Ed25519 key has `use: enc` (RFC 7517 §4.2).
    #[test]
    fn eddsa_finds_no_signature_key() {
        let signer =
            Jwk::from_json(format!(r#"{{{ED25519_PUBLIC},"d":"{ED25519_D}"}}"#).as_bytes())
                .unwrap();
        let jws = token(r#"{"alg":"EdDSA"}"#, &signer);
        assert_eq!(selected(&jws, &selection()), Err(Error::NoMatchingKey));
    }

    /// RFC 7515 §4.1.4, RFC 7517 §4.5: `kid` is compared exactly,
    /// case-sensitively.
    #[test]
    fn kid_comparison_is_exact() {
        for kid in ["B", "b ", " b", ""] {
            let jws = es256(&format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#), &KEY_B);
            assert_eq!(
                selected(&jws, &selection()),
                Err(Error::NoMatchingKey),
                "{kid:?}"
            );
        }
    }

    /// RFC 7517 §4.4, RFC 8725 §3.1: a JWK `alg` of `ES384` on a P-256
    /// key never serves `ES256`. `JwkSet::from_json` already skips such a
    /// member (ADR 0041 §2), so it is no candidate, with or without `kid`.
    #[test]
    fn a_p256_key_with_jwk_alg_es384_is_excluded_for_es256() {
        let set = set(&[
            &p256_member(&KEY_A, r#","kid":"a","alg":"ES384""#),
            &p256_member(&KEY_B, r#","kid":"b","alg":"ES256""#),
        ]);
        assert_eq!((set.len(), set.skipped()), (1, 1));
        let by_kid = es256(r#"{"alg":"ES256","kid":"a"}"#, &KEY_A);
        assert_eq!(selected(&by_kid, &set), Err(Error::NoMatchingKey));
        let kid_less = es256(r#"{"alg":"ES256"}"#, &KEY_A);
        assert_eq!(candidate_indices(&kid_less, &set, &policy()), Ok(vec![0]));
        assert_eq!(selected(&kid_less, &set), Err(Error::InvalidSignature));
        let by_b = es256(r#"{"alg":"ES256","kid":"b"}"#, &KEY_B);
        assert_eq!(selected(&by_b, &set), Ok(0));
    }

    /// ADR 0029 §1: steps 1–7 run first, so their errors win over
    /// selection, and the policy's `max_input_len` applies.
    #[test]
    fn steps_1_to_7_run_before_selection() {
        let empty = set(&[]);
        let jws = es256(r#"{"alg":"ES256"}"#, &KEY_A);
        assert_eq!(selected(&jws, &empty), Err(Error::NoMatchingKey));
        let es384_only = Policy::new(&CLOCK, &[A::ES384]).unwrap();
        assert_eq!(
            verify_with_set(&jws, &empty, &es384_only).map(|(_, i)| i),
            Err(Error::AlgorithmNotAllowed)
        );
        let short = policy().max_input_len(jws.len() - 1);
        assert!(matches!(
            verify_with_set(&jws, &selection(), &short),
            Err(Error::InvalidFormat(_))
        ));
        assert_eq!(
            selected("a.b", &selection()).map_err(|e| e.code()),
            Err("InvalidFormat")
        );
    }

    // ---- Several candidates (ADR 0029 §4) ----

    /// `p256-cand-2`.
    const CAND_2: Ec = Ec {
        x: "jjgFcO4B9fBwnRZ8E1LOCM3ZJzRC-xfUm32gnyEtVew",
        y: "C0MPLKegZh95o8tRrtCEI74o_ydt0_jw97NHWK_Oa3Q",
        d: "JptMBJVQcY56OG-Ft3PeD14NrHqUZD0BcRKv-aUHnWg",
    };
    /// `p256-cand-3`.
    const CAND_3: Ec = Ec {
        x: "E85pHKYaeBBNe-CI6UtPtYY5p8WHE3m3-1kCTweJiis",
        y: "XeNaod_9kYFUDwhUCOecuRQsdcKYfr3KDmneZRXCkg4",
        d: "CwPnivlhyi-CVp7dDOWXFkg20A3rLd1LeLV9etnpOcs",
    };
    /// `p256-attacker`: never a member of a verifying set (CVE-2018-0114).
    const ATTACKER: Ec = Ec {
        x: "uhAd3X7C07ijtmAyxKzts_abN-ZyyzTqGDHuIVAYZCw",
        y: "QFlPJHN8yY_RShgvH0QSsFl1Ngxc5XsNzyfmLhg7iSw",
        d: "VbIeLL_X7qVX9KkkZbWgnSAk0-lVOCVEU1hCnpgiai8",
    };

    fn three_candidates() -> JwkSet {
        set(&[
            &p256_member(&CAND_1, ""),
            &p256_member(&CAND_2, ""),
            &p256_member(&CAND_3, ""),
        ])
    }

    #[test]
    fn the_third_of_three_candidates_verifies_with_key_index_2() {
        let jws = es256(r#"{"alg":"ES256"}"#, &CAND_3);
        assert_eq!(counted(&jws, &three_candidates(), &policy()), (Ok(2), 3, 0));
        let (verified, index) = verify_with_set(&jws, &three_candidates(), &policy()).unwrap();
        assert_eq!(index, 2);
        assert_eq!(&verified.payload[..], PAYLOAD);
        assert_eq!(verified.signature_index, 0);
    }

    #[test]
    fn a_token_no_candidate_signed_is_invalid_signature() {
        let jws = es256(r#"{"alg":"ES256"}"#, &ATTACKER);
        assert_eq!(
            counted(&jws, &three_candidates(), &policy()),
            (Err(Error::InvalidSignature), 3, 0)
        );
    }

    /// More candidates than the bound → `NoMatchingKey` before any
    /// signature is computed (ADR 0029 §4), counted through the family
    /// double; at the bound, they are all tried.
    #[test]
    fn more_candidates_than_the_limit_is_no_matching_key_before_any_signature() {
        let jws = es256(r#"{"alg":"ES256"}"#, &CAND_3);
        let two = policy().max_key_candidates(2);
        assert_eq!(
            counted(&jws, &three_candidates(), &two),
            (Err(Error::NoMatchingKey), 0, 0)
        );
        let three = policy().max_key_candidates(3);
        assert_eq!(counted(&jws, &three_candidates(), &three), (Ok(2), 3, 0));
        let zero = policy().max_key_candidates(0);
        assert_eq!(
            counted(&jws, &three_candidates(), &zero),
            (Err(Error::NoMatchingKey), 0, 0)
        );
    }

    /// The default bound is [`Policy::DEFAULT_MAX_KEY_CANDIDATES`] (8).
    #[test]
    fn the_default_limit_is_eight() {
        let member = p256_member(&CAND_1, "");
        let jws = es256(r#"{"alg":"ES256"}"#, &CAND_1);
        let eight = set(&[member.as_str(); 8]);
        assert_eq!(counted(&jws, &eight, &policy()), (Ok(0), 1, 0));
        let nine = set(&[member.as_str(); 9]);
        assert_eq!(
            counted(&jws, &nine, &policy()),
            (Err(Error::NoMatchingKey), 0, 0)
        );
    }

    // ---- Error ranking (ADR 0026 §3) ----

    /// An HS256 key of `len` octets of `fill`, without `kid`.
    fn oct_member(fill: u8, len: usize) -> String {
        format!(
            r#"{{"kty":"oct","k":"{}"}}"#,
            b64url_encode(&vec![fill; len])
        )
    }

    /// A weak-key candidate fails at key binding (`InvalidKey`, RFC 7518
    /// §3.2), a wrong key at the signature (`InvalidSignature`); the
    /// latter progressed further, in either order.
    #[test]
    fn a_weak_key_and_a_wrong_signature_rank_invalid_signature() {
        let signer = Jwk::from_json(oct_member(0x22, 32).as_bytes()).unwrap();
        let jws = token(r#"{"alg":"HS256"}"#, &signer);
        let weak = oct_member(0x33, 16);
        let wrong = oct_member(0x44, 32);
        assert_eq!(
            selected(&jws, &set(&[&weak, &wrong])),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            selected(&jws, &set(&[&wrong, &weak])),
            Err(Error::InvalidSignature)
        );
        assert!(matches!(
            selected(&jws, &set(&[&weak, &weak])),
            Err(Error::InvalidKey(_))
        ));
        let right = oct_member(0x22, 32);
        assert_eq!(selected(&jws, &set(&[&weak, &wrong, &right])), Ok(2));
    }

    // ---- RSA (ADR 0021) ----

    /// RFC 7515 Appendix A.2: the RS256 JWS.
    const A2_TOKEN: &str = concat!(
        "eyJhbGciOiJSUzI1NiJ9",
        ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        ".cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5",
        "jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb",
        "1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QO",
        "YEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw",
    );
    /// RFC 7515 Appendix A.2.1: the public members of the RS256 key, with a
    /// `kid` added.
    const A2_PUBLIC: &str = concat!(
        r#"{"kty":"RSA","kid":"rfc7515-a2","e":"AQAB","n":""#,
        "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4Ql",
        "L-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUs",
        "LA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoud",
        "F8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
        r#""}"#,
    );
    /// RFC 7520 §4.1.3 (Figure 13): an RS256 JWS whose protected header
    /// carries `kid` `bilbo.baggins@hobbiton.example`.
    const RFC7520_TOKEN: &str = concat!(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9",
        ".SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0",
        "aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91",
        "IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
        ".MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7P",
        "NDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9e",
        "Ro4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4",
        "uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg",
    );
    /// RFC 7520 §3.3 (Figure 3): the public RSA key of [`RFC7520_TOKEN`].
    const RFC7520_PUBLIC: &str = concat!(
        r#"{"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig","e":"AQAB","n":""#,
        "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMa",
        "JMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6c",
        "S6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwd",
        "q_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
        r#""}"#,
    );

    /// ADR 0021: RS256 verifies through a set. The RFC 7515 A.2 token has
    /// no `kid`, so every RSA member is a candidate and the A.2 key is
    /// found second; alone in the set it is found first.
    #[test]
    fn rfc7515_a2_rs256_verifies_through_a_set_without_a_kid() {
        let both = set(&[RFC7520_PUBLIC, A2_PUBLIC]);
        assert_eq!(
            candidate_indices(A2_TOKEN, &both, &policy()),
            Ok(vec![0, 1])
        );
        let (verified, index) = verify_with_set(A2_TOKEN, &both, &policy()).unwrap();
        assert_eq!((index, &verified.alg), (1, &A::RS256));
        assert!(verified.payload.starts_with(br#"{"iss":"joe""#));
        assert_eq!(selected(A2_TOKEN, &set(&[A2_PUBLIC])), Ok(0));
        assert_eq!(both.keys()[1].kid(), Some("rfc7515-a2"));
    }

    /// The same set selects by `kid`: RFC 7520 §4.1's token names its key
    /// in the protected header, so the A.2 key is not even tried.
    #[test]
    fn an_rs256_token_with_a_kid_selects_its_key_by_kid() {
        let both = set(&[A2_PUBLIC, RFC7520_PUBLIC]);
        assert_eq!(
            candidate_indices(RFC7520_TOKEN, &both, &policy()),
            Ok(vec![1])
        );
        assert_eq!(counted(RFC7520_TOKEN, &both, &policy()), (Ok(1), 1, 0));
        let a2_only = set(&[A2_PUBLIC]);
        assert_eq!(selected(RFC7520_TOKEN, &a2_only), Err(Error::NoMatchingKey));
    }

    /// RFC 7517 Appendix A.2's RSA private key, the second member of the
    /// RFC's set (line breaks inside values removed).
    const A2_PRIVATE_MEMBER: &str = concat!(
        r#"{"kty":"RSA","alg":"RS256","kid":"2011-04-29","e":"AQAB","#,
        r#""n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","#,
        r#""d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q","#,
        r#""p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs","#,
        r#""q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk","#,
        r#""dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0","#,
        r#""dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk","#,
        r#""qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"}"#,
    );

    /// ADR 0021, ADR 0029 §3: an RSA private member fails the whole set
    /// import, so no token can verify against it, even one whose `kid`
    /// names a different, valid member.
    #[test]
    fn a_set_with_an_rsa_private_member_fails_to_import() {
        let first = p256_member(&KEY_A, r#","kid":"a""#);
        let json = format!(r#"{{"keys":[{first},{A2_PRIVATE_MEMBER}]}}"#);
        assert_eq!(
            JwkSet::from_json(json.as_bytes()).unwrap_err(),
            Error::UnsupportedAlgorithm
        );
        // Without the private member, the same token verifies.
        let jws = es256(r#"{"alg":"ES256","kid":"a"}"#, &KEY_A);
        assert_eq!(selected(&jws, &set(&[&first])), Ok(0));
    }

    /// RFC 7517 §5: members of an unknown `kty` or `crv` are skipped, and
    /// the rest of the set still verifies.
    #[test]
    fn unknown_kty_and_crv_members_are_skipped() {
        let set = set(&[
            r#"{"kty":"XYZ","kid":"a"}"#,
            r#"{"kty":"OKP","crv":"Ed448","x":"AAAA","kid":"a"}"#,
            r#"{"kty":"EC","crv":"P-192","x":"AAAA","y":"AAAA","kid":"a"}"#,
            &p256_member(&KEY_A, r#","kid":"a""#),
        ]);
        assert_eq!((set.len(), set.skipped()), (1, 3));
        let jws = es256(r#"{"alg":"ES256","kid":"a"}"#, &KEY_A);
        assert_eq!(selected(&jws, &set), Ok(0));
    }

    // A fixed public modulus of 8200 bits (keys.json `rsa-8200`, feature
    // 0004 T02): only the public key was ever exported (ADR 0021).
    const MODULUS_8200: &str = concat!(
        "rTphzws3aF2xHUrDRw7j7R0JuF-6mnSdJxusXRTdeVVx0N1gj3iBWnh7TUe3iRCs3swR_c4sfVx-xhm6wrHBWDQk",
        "PQnJw6Jtnvd5JgybX_Qbh3LZj4hQrWKCSzXNkjsZ_JpYpWDWwwjut-lVCt1z7uWkTeUVjxcT2fD-JCRa2Fw0lxk4",
        "TlSy3EivgtjOBpjKdvq60pF8DZa1q0zQ7pt_Evak4d8221qFZ4GKuifRKojcuzjCtJ7AG-9FCXad0lnjObOYwGdm",
        "d3QOC3J_pHiNsGWMT6y0B7PxRu31HTsaXIPuQKyghhthhsA5XIpj9ByUNcepFPQ4D6o0Bi-nb14xAOMhW3zwbC8I",
        "kKHVBRYjnP3379DluI8zS7yXup4TIsX-I1U69mHr5TmQGLf6uMTjye8DELEmE2XqywReZGchQN0qhounhXRX1du1",
        "_af4vQ_dT81Pf8gzoQe5hL3iSDcMeK9pEN2u4vjU9GdlNLH1kvD3BnO6-gyhdSaXcGFW0vUoxqFQ-0aAVrM31dcy",
        "20aJ9V1tttWVlVT9RYvQRiycKan-Ao5lJlM3APL0bLHPXubd0ugZ6gnZ0OJUIA1c8TU6DnOpr35vPo024JG9Y-95",
        "TdFR2cwyJs0W7ij3awMzfFKB5IgYmujBRatP7ff8aGjT8634bwCdZNToWWdaxaSDHTW-EgIoLYnb3vc_cKFm48LZ",
        "uMsLPqoTpXEOxFKsN8s8Yd6sgN2i8_EDUWz2GrUgXS0chIZexXC_O-IsmZyZYsLalcf10Ux7skk08vc2z5lXkIu6",
        "lSxhh9Z_GDhBU9oEC3C33VS4nSIqkwJhYlS77yPTXD_rBhxrL0tU9sGfgk9a4Wji4HEz1Hew8qsTazW5_a03fUVo",
        "opAvIwiEZF1NfSM-WcN5jPBitK48PaGp03_oPoa7hFcYElUIJo9CLBONZiWmeXDoOvGDbZizpyytRkQ0qf0ApJaP",
        "yBOlurmOkSJ2DAa40KWRYTOIETCSWExH2PotJkGsqu5Mer39EAxI6UIzPUSR07OReca9eXmtZmuK438pa1m6KGml",
        "KIUg4pu1bgEfGQZx_CYqH2R_kL4M61CVZ3l00nCC_qupUJwkMEPSj_c_YB2Uc83qMHvAo5GeTFDgc5MAA7ztE5H5",
        "pbEs4LI3THcFyoKx2V3zu2k69EWmbtn0wbet1tkJxy5MhmdRVNIckR-teJiGMJ6jerOrewTzncUbF0ywyl7yBwjr",
        "BcyGRo-L4QCSfwc_PHPmaMrdkH7dnZp9HMWzGz8uunZwZ-GL3_DNOtSZbgHaq0or9ajPQzjBAelNNzts3_Wl4L8s",
        "ZsCkxEFtc_bRclaPYGA1zZRH6Qs-LxUVsNVivykD366X04M",
    );

    /// ADR 0041 §2, RFC 7518 §3.3: a member whose modulus is over 8192
    /// bits is skipped at import, so a set whose only RS256-capable member
    /// is one gives `NoMatchingKey`.
    #[test]
    fn an_oversized_rsa_member_is_skipped_and_gives_no_matching_key() {
        let oversized = format!(r#"{{"kty":"RSA","n":"{MODULUS_8200}","e":"AQAB"}}"#);
        let bits = crate::util::b64url_decode(MODULUS_8200).unwrap().len() * 8;
        assert!(bits > 8192, "{bits}");
        let set = set(&[&p256_member(&KEY_A, ""), &oversized]);
        assert_eq!((set.len(), set.skipped()), (1, 1));
        assert_eq!(
            counted(A2_TOKEN, &set, &policy()),
            (Err(Error::NoMatchingKey), 0, 0)
        );
    }
}
