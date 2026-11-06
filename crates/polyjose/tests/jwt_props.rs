//! 0004 T14: JWT properties against test-local executable models, through
//! the public API only (ADR 0008 layer 2).
//!
//! Each property sets a small model, written from the ADRs and RFCs and
//! never from the implementation, against `polyjose::jwt`:
//!
//! 1. **NumericDate** (RFC 7519 §2, ADR 0027 §2–§3): the ±(2^53 − 1)
//!    range, the JSON round trip, and `is_expired` / `is_not_yet_valid`
//!    against the inequalities `exp ≤ now − leeway` and
//!    `nbf > now + leeway`. The model compares exactly in `i128`, on the
//!    double's IEEE 754 decomposition `m × 2^e` (see [`cmp_exact`]).
//! 2. **Claims round trip** (RFC 7519 §4, ADR 0027 §1): random Claims
//!    Sets, with private claims from a bounded JSON generator (depth ≤ 4),
//!    survive `to_json` → `from_json`, and serialization is stable.
//! 3. **Verdict model** (ADR 0027 §9 J4–J10): HS256 and EdDSA tokens
//!    issued with `jwt::sign` under random claims, policy and time, and
//!    checked with `jwt::verify`, give exactly the predicted result.
//! 4. **Selection model** (ADR 0029 §2, §4): random JWK Sets of up to ten
//!    members and a token from one of them; `jwt::verify` succeeds iff the
//!    model's candidate filter and bound let a matching key through, and
//!    otherwise fails with the predicted `NoMatchingKey`,
//!    `InvalidSignature` or `InvalidKey` (ADR 0026 §3 ranking).
//! 5. **Nested round trip** (RFC 7519 §5.2, §11.2; ADR 0027 §7): random
//!    claims through `jwt::sign` → `encrypt_nested` (`dir` + A256GCM,
//!    ECDH-ES+A128KW) → `decrypt_nested` come back unchanged.
//!
//! **Determinism.** Every key is a published or fixed key: RFC 7515
//! A.1/A.3, RFC 8032 §7.1, the shared `common` curve points, and constant
//! HMAC octets. No key is generated, so no case depends on the OS CSPRNG
//! for its keys. The only fresh randomness is what JWE encryption itself
//! draws (CEK, IV, ephemeral ECDH key; ADR 0005), and the properties hold
//! for every value of it. Time comes only from `FixedClock` (ADR 0028,
//! pipeline rule 8). The proptest configuration follows the rest of the
//! suite (`ProptestConfig::with_cases`), at most 1,000 cases per property
//! (pipeline rule 8, ADR 0009), and no assertion depends on wall-clock
//! timing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a panic is a failed assertion

mod common;

use core::cmp::Ordering;

use polyjose::Error;
use polyjose::json::{MAX_SAFE_INTEGER, Number, Object, Value, parse};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg, SigningAlg};
use polyjose::jwe::{DecryptPolicy, Encryptor, Recipient};
use polyjose::jwk::{Jwk, JwkSet};
use polyjose::jwt::{self, Audience, Claims, FixedClock, IssueOptions, Keys, NumericDate, Policy};
use polyjose::util::b64url_encode;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;

// ---------------------------------------------------------------------------
// The exact model of a NumericDate comparison
// ---------------------------------------------------------------------------

/// 2^53 − 1, the NumericDate bound (ADR 0027 §2, RFC 7493 §2.2).
const MAX_SAFE: i128 = MAX_SAFE_INTEGER as i128;

/// The exact order of the finite double `v` against the integer `t`,
/// independent of the implementation's floor-based comparison.
///
/// A finite double is exactly `m × 2^e` with an integer `|m| < 2^53`
/// (IEEE 754 §3.4: the significand of a normal number is `1.f`, of a
/// subnormal `0.f`, scaled by `2^(E − 1075)` with `E` the biased exponent,
/// `2^−1074` for a subnormal). So `v` against `t` is `m` against `t × 2^−e`
/// when `e < 0`, or `m × 2^e` against `t` when `e ≥ 0`, both in `i128`. A
/// product that would overflow `i128` is decided by magnitude alone:
/// `|t| < 2^64` (it is an `i64` plus or minus a `u32` leeway), and
/// `|m| < 2^53`.
fn cmp_exact(v: f64, t: i128) -> Ordering {
    assert!(v.is_finite(), "the model is defined for finite doubles");
    let bits = v.to_bits();
    let biased = ((bits >> 52) & 0x7ff) as i32;
    let fraction = (bits & ((1 << 52) - 1)) as i128;
    let (magnitude, e) = if biased == 0 {
        (fraction, -1074)
    } else {
        (fraction | (1 << 52), biased - 1075)
    };
    let m = if bits >> 63 == 1 {
        -magnitude
    } else {
        magnitude
    };
    if m == 0 {
        return 0.cmp(&t);
    }
    if e >= 0 {
        // |m × 2^e| ≥ 2^e, which is above every |t| once e ≥ 65.
        return if e <= 64 { (m << e).cmp(&t) } else { m.cmp(&0) };
    }
    let s = -e;
    if t == 0 {
        return m.cmp(&0);
    }
    if s >= 64 {
        // |t × 2^s| ≥ 2^64 > |m|: only the sign of t matters.
        return if t > 0 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    // |t| < 2^64 and s < 64, so |t × 2^s| < 2^127: no overflow.
    m.cmp(&(t * (1i128 << s)))
}

/// The model of `exp` (RFC 7519 §4.1.4, ADR 0027 §3): expired iff
/// `exp ≤ now − leeway`, exactly.
fn model_expired(exp: f64, now: i64, leeway: u32) -> bool {
    cmp_exact(exp, i128::from(now) - i128::from(leeway)) != Ordering::Greater
}

/// The model of `nbf` (RFC 7519 §4.1.5, ADR 0027 §3): not yet valid iff
/// `nbf > now + leeway`, exactly.
fn model_not_yet_valid(nbf: f64, now: i64, leeway: u32) -> bool {
    cmp_exact(nbf, i128::from(now) + i128::from(leeway)) == Ordering::Greater
}

/// The model's NumericDate range (ADR 0027 §2): finite, `|v| ≤ 2^53 − 1`.
fn model_in_range(v: f64) -> bool {
    v.is_finite() && cmp_exact(v.abs(), MAX_SAFE) != Ordering::Greater
}

#[test]
fn the_exact_model_agrees_with_adr_0027_s3_examples() {
    // The model itself, on the ADR 0027 §3 worked examples.
    assert!(!model_expired(1000.0, 1059, 60));
    assert!(model_expired(1000.0, 1060, 60));
    assert!(!model_expired(1000.0, 999, 0));
    assert!(model_expired(1000.0, 1000, 0));
    assert!(!model_expired(1000.5, 1000, 0));
    assert!(model_expired(1000.5, 1001, 0));
    assert!(!model_not_yet_valid(1000.0, 940, 60));
    assert!(model_not_yet_valid(1000.0, 939, 60));
    // Subnormals, signed values and the range edge.
    assert_eq!(cmp_exact(f64::from_bits(1), 0), Ordering::Greater);
    assert_eq!(cmp_exact(-f64::from_bits(1), 0), Ordering::Less);
    assert_eq!(cmp_exact(-0.5, -1), Ordering::Greater);
    assert_eq!(cmp_exact(-1.5, -1), Ordering::Less);
    assert_eq!(
        cmp_exact(9_007_199_254_740_991.0, MAX_SAFE),
        Ordering::Equal
    );
    assert!(model_in_range(9_007_199_254_740_991.0));
    assert!(!model_in_range(9_007_199_254_740_992.0));
    assert!(!model_in_range(f64::INFINITY));
    assert_eq!(cmp_exact(1e300, i128::from(i64::MAX)), Ordering::Greater);
    assert_eq!(cmp_exact(-1e300, i128::from(i64::MIN)), Ordering::Less);
}

// ---------------------------------------------------------------------------
// Date generators
// ---------------------------------------------------------------------------

/// Any double, finite or not: a random sign, biased exponent and fraction
/// (IEEE 754 binary64), plus the edges of the NumericDate range.
fn any_double() -> impl Strategy<Value = f64> {
    let max = MAX_SAFE_INTEGER as f64;
    prop_oneof![
        6 => (any::<bool>(), 0u64..=2047, any::<u64>()).prop_map(|(neg, biased, fraction)| {
            f64::from_bits((u64::from(neg) << 63) | (biased << 52) | (fraction & ((1 << 52) - 1)))
        }),
        1 => select(vec![max, -max, max + 1.0, -(max + 1.0), 0.0, -0.0, 0.5, -0.5]),
    ]
}

/// A finite double with `|v| ≤ 2^53 − 1`, the NumericDate range
/// (ADR 0027 §2): every biased exponent up to 1075 (`|v| < 2^53`), so
/// subnormals, fractions and negatives of every magnitude.
fn date_double() -> impl Strategy<Value = f64> {
    let max = MAX_SAFE_INTEGER as f64;
    prop_oneof![
        4 => (any::<bool>(), 0u64..=1075, any::<u64>()).prop_map(|(neg, biased, fraction)| {
            f64::from_bits((u64::from(neg) << 63) | (biased << 52) | (fraction & ((1 << 52) - 1)))
        }),
        2 => (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).prop_map(|i| i as f64),
        1 => select(vec![max, -max, 0.0, 1.0, -1.0, 0.5, -0.5]),
    ]
}

/// A fraction to add to a whole-second date: none, half a second, or the
/// smallest steps either side of an integer that a double near 2^31 holds.
fn fraction() -> impl Strategy<Value = f64> {
    select(vec![
        0.0,
        0.5,
        -0.5,
        f64::EPSILON,
        -f64::EPSILON,
        1.0 / 1_048_576.0,
        1.0 - 1.0 / 1_048_576.0,
        -(1.0 / 1_048_576.0),
    ])
}

/// A clock reading: mostly realistic epochs, sometimes the edges of the
/// ADR 0028 §1 range and of `i64`.
fn now_secs() -> impl Strategy<Value = i64> {
    prop_oneof![
        6 => 0i64..=4_102_444_800, // 1970 .. 2100
        2 => -4_102_444_800i64..=0,
        1 => select(vec![MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER, MAX_SAFE_INTEGER - 600]),
    ]
}

/// A date near `t` (within a few seconds, with a fraction), or anywhere in
/// the range: the boundary cases of ADR 0027 §3 are within one second of
/// `now ± leeway`.
fn date_near(t: i128) -> impl Strategy<Value = f64> {
    prop_oneof![
        4 => (-3i128..=3, fraction()).prop_map(move |(off, frac)| (t + off) as f64 + frac),
        1 => date_double(),
    ]
    .prop_filter("a NumericDate", |v| model_in_range(*v))
}

// ---------------------------------------------------------------------------
// 1. NumericDate (RFC 7519 §2; ADR 0027 §2–§3)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// ADR 0027 §2: a double is a NumericDate iff it is finite and at most
    /// 2^53 − 1 in magnitude; then `from_json(to_json_value(d)) == d`, both
    /// as a value and through the JSON text, and the double is unchanged
    /// (RFC 7519 §2: "non-integer values can be represented").
    #[test]
    fn numeric_date_range_and_json_round_trip(v in prop_oneof![any_double(), date_double()]) {
        let date = NumericDate::from_f64(v);
        prop_assert_eq!(date.is_some(), model_in_range(v), "{:e}", v);
        if let Some(d) = date {
            prop_assert_eq!(NumericDate::from_json(&d.to_json_value(), "exp"), Ok(d));
            let text = d.to_json_value().to_json();
            let back = NumericDate::from_json(&parse(text.as_bytes()).unwrap(), "exp").unwrap();
            prop_assert_eq!(back, d, "{}", text);
            // Equal doubles, and -0 is stored as +0 (RFC 7493 §2.2).
            prop_assert_eq!(back.as_f64().to_bits(), (v + 0.0).to_bits(), "{}", text);
            // An integral date is written without a fraction (ADR 0027 §1).
            if let Some(secs) = d.as_secs() {
                prop_assert_eq!(text, secs.to_string());
            }
        }
    }

    /// ADR 0027 §3: `is_expired` is `exp ≤ now − leeway` and
    /// `is_not_yet_valid` is `nbf > now + leeway`, exactly, for any
    /// integer `now` (the whole `i64`, beyond the clock's range too) and
    /// any leeway up to 600 s.
    #[test]
    fn time_checks_match_the_exact_model(
        (now, leeway, v) in (
            prop_oneof![3 => now_secs(), 1 => any::<i64>()],
            prop_oneof![0u32..=600, select(vec![0u32, 60, 600])],
        )
            .prop_flat_map(|(now, leeway)| {
                let edges = prop_oneof![
                    date_near(i128::from(now) - i128::from(leeway)),
                    date_near(i128::from(now) + i128::from(leeway)),
                    date_double(),
                ];
                (Just(now), Just(leeway), edges)
            }),
    ) {
        let d = NumericDate::from_f64(v).unwrap();
        prop_assert_eq!(d.is_expired(now, leeway), model_expired(v, now, leeway), "exp {:e} now {} leeway {}", v, now, leeway);
        prop_assert_eq!(
            d.is_not_yet_valid(now, leeway),
            model_not_yet_valid(v, now, leeway),
            "nbf {:e} now {} leeway {}", v, now, leeway
        );
    }
}

// ---------------------------------------------------------------------------
// JSON and Claims Set generators
// ---------------------------------------------------------------------------

/// A short string of any Unicode scalar values, control characters,
/// quotes, backslashes and non-BMP characters included (RFC 8259 §7).
fn any_string() -> impl Strategy<Value = String> + Clone {
    prop_oneof![
        3 => vec(any::<char>(), 0..8).prop_map(String::from_iter),
        2 => vec(select(vec!['a', '"', '\\', '/', '\u{0}', '\u{1f}', '\u{7f}', 'é', '\u{2028}', '😀']), 0..6)
            .prop_map(String::from_iter),
    ]
}

/// A JSON number: any finite double (RFC 7493 §2.2), or an exact integer.
fn any_number() -> impl Strategy<Value = Number> {
    prop_oneof![
        any_double().prop_filter_map("finite", Number::from_f64),
        (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).prop_map(|i| Number::from_i64(i).unwrap()),
    ]
}

/// A JSON value of depth at most 4 (a scalar is depth 0), with at most four
/// entries per container.
fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any_number().prop_map(Value::Number),
        any_string().prop_map(Value::from),
    ];
    leaf.prop_recursive(4, 48, 4, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..4).prop_map(Value::from),
            vec((any_string(), inner), 0..4).prop_map(|members| {
                let mut object = Object::new();
                for (name, value) in members {
                    object.insert(name, value);
                }
                Value::from(object)
            }),
        ]
    })
}

/// The registered claim names (RFC 7519 §4.1), in the ADR 0027 §1 order.
const REGISTERED: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// Up to five public or private claims (RFC 7519 §4.2–§4.3): any name but a
/// registered one, any value of depth ≤ 4.
fn other_claims() -> impl Strategy<Value = Vec<(String, Value)>> {
    vec(
        (
            any_string().prop_filter("not registered", |n| !REGISTERED.contains(&n.as_str())),
            json_value(),
        ),
        0..5,
    )
}

fn audience(value: impl Strategy<Value = String> + Clone) -> impl Strategy<Value = Audience> {
    prop_oneof![
        value.clone().prop_map(Audience::One),
        vec(value, 0..4).prop_map(Audience::Many),
    ]
}

/// A Claims Set from its parts.
#[allow(clippy::too_many_arguments)]
fn claims_of(
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Audience>,
    exp: Option<f64>,
    nbf: Option<f64>,
    iat: Option<f64>,
    jti: Option<String>,
    other: Vec<(String, Value)>,
) -> Claims {
    let date = |v: Option<f64>| v.map(|v| NumericDate::from_f64(v).expect("in range"));
    let mut c = Claims::new();
    c.iss = iss;
    c.sub = sub;
    c.aud = aud;
    c.exp = date(exp);
    c.nbf = date(nbf);
    c.iat = date(iat);
    c.jti = jti;
    for (name, value) in other {
        c.insert(name, value).expect("not a registered name");
    }
    c
}

/// Any Claims Set: every registered claim optional, of any value of its
/// type (ADR 0027 §1–§2), and random other claims.
fn any_claims() -> impl Strategy<Value = Claims> {
    (
        (
            proptest::option::of(any_string()),
            proptest::option::of(any_string()),
            proptest::option::of(audience(any_string())),
            proptest::option::of(date_double()),
        ),
        (
            proptest::option::of(date_double()),
            proptest::option::of(date_double()),
            proptest::option::of(any_string()),
            other_claims(),
        ),
    )
        .prop_map(|((iss, sub, aud, exp), (nbf, iat, jti, other))| {
            claims_of(iss, sub, aud, exp, nbf, iat, jti, other)
        })
}
// ---------------------------------------------------------------------------
// 2. Claims round trip (RFC 7519 §4; ADR 0027 §1)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// ADR 0027 §1: `Claims::from_json(to_json(c)) == c` for any Claims Set,
    /// and serializing the parsed set gives the same octets (registered
    /// claims in the fixed order, the others in insertion order, `aud` in
    /// its form).
    #[test]
    fn claims_json_round_trip(c in any_claims()) {
        let json = c.to_json();
        let back = Claims::from_json(json.as_bytes());
        prop_assert_eq!(back.as_ref(), Ok(&c), "{}", json);
        let back = back.unwrap();
        prop_assert_eq!(back.to_json(), json);
        let names: Vec<&str> = back.other_claims().iter().map(|(n, _)| n).collect();
        let expected: Vec<&str> = c.other_claims().iter().map(|(n, _)| n).collect();
        prop_assert_eq!(names, expected, "insertion order");
    }
}

// ---------------------------------------------------------------------------
// Keys (fixed; no key is generated)
// ---------------------------------------------------------------------------

/// RFC 7515 Appendix A.1.1: the 64-octet HMAC key of RFC 7519 §3.1.
const RFC7515_A1_K: &str =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

/// Ed25519 key pairs `(x, d)`: RFC 8037 A.1 (RFC 8032 §7.1 TEST 1), and
/// RFC 8032 §7.1 TEST 2 and TEST 3.
const ED25519: [(&str, &str); 3] = [
    (common::ED25519_X, common::ED25519_D),
    (
        "PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw",
        "TM0Imyj_ltqdtsNG7BFOD1uKMZ81q6Yk2oz27U-4pvs",
    ),
    (
        "_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU",
        "xaqN9D-fg3vtt0QvMdy3sWbThTUHbwlLhc46LgtEWPc",
    ),
];

fn jwk(json: &str) -> Jwk {
    Jwk::from_json(json.as_bytes()).unwrap_or_else(|e| panic!("fixture key: {e}"))
}

/// An HMAC key of `octets` (RFC 7518 §3.2; RFC 7517 §6.4).
fn oct_k(octets: &[u8]) -> String {
    b64url_encode(octets)
}

/// The HMAC keys of the HS256 properties: RFC 7515 A.1.1, and fixed octet
/// patterns at least the SHA-256 output long (RFC 7518 §3.2).
fn hmac_k(i: usize) -> String {
    match i % 3 {
        0 => RFC7515_A1_K.to_owned(),
        1 => oct_k(&(0u8..32).collect::<Vec<_>>()),
        _ => oct_k(&[0xa5; 48]),
    }
}

fn ed25519_private(i: usize) -> Jwk {
    let (x, d) = ED25519[i % ED25519.len()];
    jwk(&format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}","d":"{d}"}}"#
    ))
}

/// The signer of the verdict and nested properties: HS256 with HMAC key
/// `key`, or EdDSA with Ed25519 key `key` (RFC 7518 §3.2, RFC 8037 §3.1),
/// and the key its verifier holds.
#[derive(Debug, Clone, Copy)]
struct Signer {
    eddsa: bool,
    key: usize,
}

impl Signer {
    fn alg(self) -> SigningAlg {
        if self.eddsa {
            SigningAlg::EdDSA
        } else {
            SigningAlg::HS256
        }
    }

    fn signing_key(self) -> Jwk {
        if self.eddsa {
            ed25519_private(self.key)
        } else {
            jwk(&format!(r#"{{"kty":"oct","k":"{}"}}"#, hmac_k(self.key)))
        }
    }

    fn verifying_key(self) -> Jwk {
        let key = self.signing_key();
        if self.eddsa {
            key.to_public().expect("Ed25519 public half")
        } else {
            key
        }
    }
}

fn signer() -> impl Strategy<Value = Signer> {
    (any::<bool>(), 0usize..3).prop_map(|(eddsa, key)| Signer { eddsa, key })
}

// ---------------------------------------------------------------------------
// 3. The verdict model (ADR 0027 §9 J4–J10)
// ---------------------------------------------------------------------------

/// The model of `iat` with a maximum age (RFC 7519 §4.1.6, ADR 0027 §3):
/// rejected iff `iat > now + leeway` or `iat < now − max_age − leeway`.
fn model_iat_rejected(iat: f64, now: i64, max_age: u32, leeway: u32) -> bool {
    let (now, max_age, leeway) = (i128::from(now), i128::from(max_age), i128::from(leeway));
    cmp_exact(iat, now + leeway) == Ordering::Greater
        || cmp_exact(iat, now - max_age - leeway) == Ordering::Less
}

/// The extra required names the verdict policy draws from: the registered
/// names, an RFC 9068 §2.2 name and a private one.
const REQUIRABLE: [&str; 9] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "client_id",
    "x-tenant",
];

/// A random JWT policy, as data (ADR 0027 §3–§5).
#[derive(Debug, Clone)]
struct PolicySpec {
    /// `None` keeps the default (60 s, ADR 0007).
    leeway: Option<u32>,
    issuers: Vec<&'static str>,
    audiences: Vec<&'static str>,
    subject: Option<&'static str>,
    max_age: Option<u32>,
    required: Vec<&'static str>,
    allow_missing_exp: bool,
    ignore_audience: bool,
}

impl PolicySpec {
    fn leeway(&self) -> u32 {
        self.leeway.unwrap_or(Policy::DEFAULT_LEEWAY)
    }

    fn build<'a>(&self, clock: &'a FixedClock, algs: &'a [SigningAlg]) -> Policy<'a> {
        let mut p = Policy::new(clock, algs).unwrap();
        if let Some(leeway) = self.leeway {
            p = p.leeway(leeway).unwrap();
        }
        p = p.issuers(&self.issuers).audiences(&self.audiences);
        if let Some(sub) = self.subject {
            p = p.subject(sub);
        }
        if let Some(max_age) = self.max_age {
            p = p.max_age(max_age);
        }
        for name in &self.required {
            p = p.require(name);
        }
        if self.allow_missing_exp {
            p = p.allow_missing_exp();
        }
        if self.ignore_audience {
            p = p.ignore_audience();
        }
        p
    }
}

fn policy_spec() -> impl Strategy<Value = PolicySpec> {
    let names = |pool: Vec<&'static str>| vec(select(pool), 0..3);
    (
        (
            proptest::option::of(prop_oneof![0u32..=600, select(vec![0u32, 600])]),
            names(vec!["i1", "i2"]),
            names(vec!["a1", "a2"]),
            proptest::option::of(select(vec!["s1", "s2"])),
        ),
        (
            proptest::option::of(prop_oneof![0u32..=1200, select(vec![0u32, 1, u32::MAX])]),
            vec(select(REQUIRABLE.to_vec()), 0..4),
            any::<bool>(),
            any::<bool>(),
        ),
    )
        .prop_map(
            |(
                (leeway, issuers, audiences, subject),
                (max_age, required, allow_missing_exp, ignore_audience),
            )| PolicySpec {
                leeway,
                issuers,
                audiences,
                subject,
                max_age,
                required,
                allow_missing_exp,
                ignore_audience,
            },
        )
}

/// What the model predicts: success, or one error. A detail is compared
/// only where ADR 0027 names it (`InvalidClaim("<registered name>")`);
/// an extra required name is compared by code alone, since the detail is
/// a `&'static str` that cannot carry the caller's name (ADR 0027 §9: the
/// details are diagnostic, the codes are the contract).
#[derive(Debug, Clone, PartialEq)]
enum Want {
    Ok,
    Exactly(Error),
    Code(&'static str),
}

impl Want {
    fn matches<T>(&self, got: &polyjose::Result<T>) -> bool {
        match (self, got) {
            (Want::Ok, Ok(_)) => true,
            (Want::Exactly(want), Err(e)) => want == e,
            (Want::Code(code), Err(e)) => *code == e.code(),
            _ => false,
        }
    }
}

/// ADR 0027 §9 J4–J10 for a Claims Set that verified (steps 1–J3 pass:
/// the token is issued by `jwt::sign` with an allowed algorithm and the
/// verifier's key, and its claims are well typed).
fn model_verdict(c: &Claims, p: &PolicySpec, now: i64) -> Want {
    let leeway = p.leeway();
    // J4 (ADR 0027 §3–§4, §9): presence in the order iss, sub, aud, exp,
    // nbf, iat, jti, then the caller's other names in the order given.
    let present = [
        c.iss.is_some(),
        c.sub.is_some(),
        c.aud.is_some(),
        c.exp.is_some(),
        c.nbf.is_some(),
        c.iat.is_some(),
        c.jti.is_some(),
    ];
    let implied = [
        !p.issuers.is_empty(),   // §4: a configured issuer requires iss
        p.subject.is_some(),     // §4: an expected subject requires sub
        !p.audiences.is_empty(), // §4: a configured audience requires aud
        !p.allow_missing_exp,    // §3, ADR 0007: exp required by default
        false,                   // nbf: never implied
        p.max_age.is_some(),     // §3: max_age requires iat
        false,                   // jti: never implied
    ];
    for (i, name) in REGISTERED.iter().enumerate() {
        if !present[i] && (implied[i] || p.required.contains(name)) {
            return Want::Exactly(Error::InvalidClaim(name));
        }
    }
    for name in &p.required {
        if !REGISTERED.contains(name) && c.get(name).is_none() {
            return Want::Code(Error::InvalidClaim("required").code());
        }
    }
    // J5: exp (RFC 7519 §4.1.4).
    if let Some(exp) = c.exp
        && model_expired(exp.as_f64(), now, leeway)
    {
        return Want::Exactly(Error::TokenExpired);
    }
    // J6: nbf (RFC 7519 §4.1.5).
    if let Some(nbf) = c.nbf
        && model_not_yet_valid(nbf.as_f64(), now, leeway)
    {
        return Want::Exactly(Error::TokenNotYetValid);
    }
    // J7: iat, only with max_age (RFC 7519 §4.1.6; erratum 7720).
    if let (Some(max_age), Some(iat)) = (p.max_age, c.iat)
        && model_iat_rejected(iat.as_f64(), now, max_age, leeway)
    {
        return Want::Exactly(Error::InvalidClaim("iat"));
    }
    // J8: iss, exact (RFC 7519 §4.1.1, §7.3; RFC 8725 §3.8).
    if !p.issuers.is_empty() && !c.iss.as_deref().is_some_and(|i| p.issuers.contains(&i)) {
        return Want::Exactly(Error::InvalidClaim("iss"));
    }
    // J9: sub (RFC 7519 §4.1.2).
    if let Some(sub) = p.subject
        && c.sub.as_deref() != Some(sub)
    {
        return Want::Exactly(Error::InvalidClaim("sub"));
    }
    // J10: aud (RFC 7519 §4.1.3), including the unconfigured audience.
    let aud_ok = if p.audiences.is_empty() {
        c.aud.is_none() || p.ignore_audience
    } else {
        c.aud.as_ref().is_some_and(|aud| {
            aud.values()
                .iter()
                .any(|v| p.audiences.contains(&v.as_str()))
        })
    };
    if !aud_ok {
        return Want::Exactly(Error::InvalidClaim("aud"));
    }
    Want::Ok
}

/// Claims for the verdict model: small value pools, so issuer, subject and
/// audience match about half the time, and dates within a few seconds of
/// each boundary.
fn verdict_claims(now: i64, leeway_hint: u32) -> impl Strategy<Value = Claims> {
    let t = i128::from(now);
    let l = i128::from(leeway_hint);
    let date = move || {
        proptest::option::of(prop_oneof![
            date_near(t - l),
            date_near(t + l),
            date_near(t),
            date_near(t - 1200),
        ])
    };
    let value = |pool: Vec<&'static str>| select(pool).prop_map(str::to_owned);
    (
        (
            proptest::option::of(value(vec!["i1", "i2", "i3"])),
            proptest::option::of(value(vec!["s1", "s2"])),
            proptest::option::of(audience(value(vec!["a1", "a2", "a3"]))),
            date(),
        ),
        (
            date(),
            date(),
            proptest::option::of(value(vec!["id"])),
            proptest::option::of(json_value()),
            proptest::option::of(json_value()),
        ),
    )
        .prop_map(
            |((iss, sub, aud, exp), (nbf, iat, jti, client_id, tenant))| {
                let mut other = Vec::new();
                if let Some(v) = client_id {
                    other.push(("client_id".to_owned(), v));
                }
                if let Some(v) = tenant {
                    other.push(("x-tenant".to_owned(), v));
                }
                claims_of(iss, sub, aud, exp, nbf, iat, jti, other)
            },
        )
}

/// The algorithms the verdict, selection and nested policies allow.
const ALLOWED: [SigningAlg; 4] = [
    SigningAlg::HS256,
    SigningAlg::EdDSA,
    SigningAlg::Ed25519,
    SigningAlg::ES256,
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// ADR 0027 §9 J4–J10: `jwt::verify` of a token issued by `jwt::sign`
    /// returns exactly what the model predicts, and on success the claims
    /// it signed.
    #[test]
    fn verify_matches_the_verdict_model(
        (signer, spec, now, claims) in (signer(), policy_spec(), now_secs())
            .prop_flat_map(|(signer, spec, now)| {
                let claims = verdict_claims(now, spec.leeway());
                (Just(signer), Just(spec), Just(now), claims)
            }),
    ) {
        let token = jwt::sign(&claims, &IssueOptions::new(signer.alg()), &signer.signing_key())
            .expect("issued");
        let clock = FixedClock(now);
        let policy = spec.build(&clock, &ALLOWED);
        let verifier = signer.verifying_key();
        let got = jwt::verify(&token, Keys::One(&verifier), &policy);
        let want = model_verdict(&claims, &spec, now);
        prop_assert!(want.matches(&got), "want {:?}, got {:?}\nclaims {}\npolicy {:?}", want, got, claims.to_json(), spec);
        if let Ok(v) = got {
            prop_assert_eq!(&v.claims, &claims);
            prop_assert_eq!(v.alg, signer.alg());
            prop_assert_eq!(v.key_index, None);
        }
    }
}

// ---------------------------------------------------------------------------
// 4. The selection model (ADR 0029 §2, §4)
// ---------------------------------------------------------------------------

/// RFC 7515 Appendix A.3: the P-256 key pair `(x, y, d)`.
const RFC7515_A3: (&str, &str, &str) = (
    "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
);

/// The key material of a set member: a fixed pool, so the same material
/// can appear more than once in a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Material {
    /// An HMAC key from [`hmac_k`] (at least 32 octets).
    Oct(usize),
    /// A 16-octet HMAC key: too short for HS256 (RFC 7518 §3.2).
    ShortOct,
    /// An Ed25519 key from [`ED25519`].
    Ed25519(usize),
    /// A P-256 key: RFC 7515 A.3 or the generator (`common`).
    P256(usize),
    /// A P-384 key (`common`), which serves none of the token algorithms.
    P384,
}

impl Material {
    fn p256(i: usize) -> (&'static str, &'static str, &'static str) {
        if i.is_multiple_of(2) {
            RFC7515_A3
        } else {
            let g = common::generator("P-256");
            (g.x, g.y, g.d)
        }
    }

    /// The public JWK members (`oct` keys are secret by nature,
    /// ADR 0029 §3).
    fn public_members(self) -> String {
        match self {
            Material::Oct(i) => format!(r#""kty":"oct","k":"{}""#, hmac_k(i)),
            Material::ShortOct => format!(r#""kty":"oct","k":"{}""#, oct_k(&[0x42; 16])),
            Material::Ed25519(i) => {
                let (x, _) = ED25519[i % ED25519.len()];
                format!(r#""kty":"OKP","crv":"Ed25519","x":"{x}""#)
            }
            Material::P256(i) => {
                let (x, y, _) = Self::p256(i);
                format!(r#""kty":"EC","crv":"P-256","x":"{x}","y":"{y}""#)
            }
            Material::P384 => {
                let g = common::generator("P-384");
                format!(r#""kty":"EC","crv":"P-384","x":"{}","y":"{}""#, g.x, g.y)
            }
        }
    }

    /// The signing JWK, with `kid` (copied into the JWS header by
    /// `jwt::sign`, ADR 0027 §8).
    fn signing_key(self, kid: Option<&str>) -> Jwk {
        let private = match self {
            Material::Ed25519(i) => format!(r#","d":"{}""#, ED25519[i % ED25519.len()].1),
            Material::P256(i) => format!(r#","d":"{}""#, Self::p256(i).2),
            _ => String::new(),
        };
        let kid = kid.map_or(String::new(), |kid| format!(r#","kid":"{kid}""#));
        jwk(&format!("{{{}{private}{kid}}}", self.public_members()))
    }

    /// Whether the material serves `alg` (ADR 0029 §2 step 1, the
    /// ADR 0026 §2 step 8 family table).
    fn serves(self, alg: &str) -> bool {
        match self {
            Material::Oct(_) | Material::ShortOct => alg == "HS256",
            Material::Ed25519(_) => alg == "EdDSA" || alg == "Ed25519",
            Material::P256(_) => alg == "ES256",
            Material::P384 => alg == "ES384",
        }
    }

    /// The equivalence of key material: the same fixture verifies the
    /// same signatures.
    fn same(self, other: Material) -> bool {
        match (self, other) {
            (Material::Oct(a), Material::Oct(b)) => a % 3 == b % 3,
            (Material::Ed25519(a), Material::Ed25519(b)) => a % 3 == b % 3,
            (Material::P256(a), Material::P256(b)) => a % 2 == b % 2,
            (a, b) => a == b,
        }
    }
}

/// A JWK Set member, as data: material plus the RFC 7517 §4 parameters
/// that ADR 0029 §2 filters on.
#[derive(Debug, Clone)]
struct Member {
    material: Material,
    kid: Option<&'static str>,
    key_use: Option<&'static str>,
    key_ops: Option<Vec<&'static str>>,
    alg: Option<&'static str>,
}

impl Member {
    fn json(&self) -> String {
        let mut json = format!("{{{}", self.material.public_members());
        if let Some(kid) = self.kid {
            json += &format!(r#","kid":"{kid}""#);
        }
        if let Some(key_use) = self.key_use {
            json += &format!(r#","use":"{key_use}""#);
        }
        if let Some(ops) = &self.key_ops {
            let ops: Vec<String> = ops.iter().map(|op| format!(r#""{op}""#)).collect();
            json += &format!(r#","key_ops":[{}]"#, ops.join(","));
        }
        if let Some(alg) = self.alg {
            json += &format!(r#","alg":"{alg}""#);
        }
        json + "}"
    }

    /// ADR 0029 §2: the candidate filter, in its order.
    fn is_candidate(&self, alg: &str, kid: Option<&str>) -> bool {
        self.material.serves(alg) // 1. family
            && self.alg.is_none_or(|a| a == alg) // 2. JWK alg, exact (EdDSA ≠ Ed25519)
            && self.key_use.is_none_or(|u| u == "sig") // 3. use
            && self.key_ops.as_ref().is_none_or(|ops| ops.contains(&"verify")) // 4. key_ops
            && kid.is_none_or(|kid| self.kid == Some(kid)) // 5. kid, exact
    }
}

fn material() -> impl Strategy<Value = Material> {
    prop_oneof![
        3 => (0usize..3).prop_map(Material::Oct),
        1 => Just(Material::ShortOct),
        3 => (0usize..3).prop_map(Material::Ed25519),
        2 => (0usize..2).prop_map(Material::P256),
        1 => Just(Material::P384),
    ]
}

/// A signing material and the header `alg` it signs with: HS256, EdDSA or
/// Ed25519 (RFC 9864), ES256.
fn signing_material() -> impl Strategy<Value = (Material, &'static str)> {
    prop_oneof![
        3 => (0usize..3).prop_map(|i| (Material::Oct(i), "HS256")),
        3 => ((0usize..3), select(vec!["EdDSA", "Ed25519"]))
            .prop_map(|(i, alg)| (Material::Ed25519(i), alg)),
        1 => (0usize..2).prop_map(|i| (Material::P256(i), "ES256")),
    ]
}

fn kid() -> impl Strategy<Value = Option<&'static str>> {
    proptest::option::of(select(vec!["a", "b", "c"]))
}

fn member(material: impl Strategy<Value = Material>) -> impl Strategy<Value = Member> {
    (
        material,
        kid(),
        proptest::option::of(select(vec!["sig", "enc"])),
        proptest::option::of(select(vec![
            vec![],
            vec!["verify"],
            vec!["sign"],
            vec!["sign", "verify"],
            vec!["encrypt"],
        ])),
        proptest::option::weighted(
            0.3,
            select(vec!["HS256", "HS384", "EdDSA", "Ed25519", "ES256", "ES384"]),
        ),
    )
        .prop_map(|(material, kid, key_use, key_ops, alg)| Member {
            material,
            kid,
            key_use,
            key_ops,
            alg,
        })
}

/// A selection case: the set's members (the signer's own member at
/// `signer_at`), the signing material, header `alg` and `kid`, and the
/// candidate bound (`None`: the default 8, ADR 0029 §4).
#[derive(Debug, Clone)]
struct SelectionCase {
    members: Vec<Member>,
    signer: Material,
    alg: &'static str,
    header_kid: Option<&'static str>,
    limit: Option<usize>,
}

fn selection_case() -> impl Strategy<Value = SelectionCase> {
    (
        signing_material(),
        kid(),
        vec(member(material()), 0..10),
        any::<prop::sample::Index>(),
        proptest::option::of(0usize..=10),
    )
        .prop_flat_map(|((signer, alg), header_kid, decoys, at, limit)| {
            let own = member(Just(signer));
            (Just((signer, alg, header_kid, decoys, at, limit)), own)
        })
        .prop_map(|((signer, alg, header_kid, mut members, at, limit), own)| {
            let at = at.index(members.len() + 1);
            members.insert(at, own);
            SelectionCase {
                members,
                signer,
                alg,
                header_kid,
                limit,
            }
        })
}

/// The selection model's prediction: the index (in the imported set) of
/// the key that verifies, or the error.
fn model_selection(imported: &[&Member], case: &SelectionCase) -> Result<usize, Error> {
    let limit = case.limit.unwrap_or(Policy::DEFAULT_MAX_KEY_CANDIDATES);
    let candidates: Vec<(usize, &Member)> = imported
        .iter()
        .enumerate()
        .filter(|(_, m)| m.is_candidate(case.alg, case.header_kid))
        .map(|(i, m)| (i, *m))
        .collect();
    // ADR 0029 §4: none, or more than the bound, before any signature.
    if candidates.is_empty() || candidates.len() > limit {
        return Err(Error::NoMatchingKey);
    }
    // ADR 0029 §4: in set order, the first that verifies wins.
    if let Some((i, _)) = candidates
        .iter()
        .find(|(_, m)| m.material.same(case.signer))
    {
        return Ok(*i);
    }
    // Every candidate failed: ADR 0026 §3 ranking, InvalidSignature >
    // InvalidKey (a too-short HMAC key, RFC 7518 §3.2).
    if candidates
        .iter()
        .any(|(_, m)| m.material != Material::ShortOct)
    {
        Err(Error::InvalidSignature)
    } else {
        Err(Error::InvalidKey("hmac key too short"))
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// ADR 0029 §2, §4: `jwt::verify` against a JWK Set of up to ten
    /// members succeeds iff the model's filter admits a key of the
    /// signer's material within `max_key_candidates`, and reports that
    /// member's index and `kid`; otherwise it fails with the model's
    /// `NoMatchingKey`, `InvalidSignature` or `InvalidKey`.
    ///
    /// Which members a set keeps is ADR 0029 §3 and 0001-T07's rule
    /// (invalid members are skipped, RFC 7517 §5); the model takes it from
    /// `Jwk::from_json` of each member and checks the set agrees.
    #[test]
    fn verify_with_a_set_matches_the_selection_model(case in selection_case()) {
        let json = format!(
            r#"{{"keys":[{}]}}"#,
            case.members.iter().map(Member::json).collect::<Vec<_>>().join(",")
        );
        let set = JwkSet::from_json(json.as_bytes()).expect("a set without RSA private keys");
        let imported: Vec<&Member> = case
            .members
            .iter()
            .filter(|m| Jwk::from_json(m.json().as_bytes()).is_ok())
            .collect();
        prop_assert_eq!(set.len(), imported.len(), "{}", json);
        prop_assert_eq!(set.skipped(), case.members.len() - imported.len());

        let mut claims = Claims::new();
        claims.sub = Some("selection".into());
        claims.exp = NumericDate::from_secs(2_000_000_000);
        let alg = SigningAlg::from(case.alg);
        let token = jwt::sign(
            &claims,
            &IssueOptions::new(alg.clone()),
            &case.signer.signing_key(case.header_kid),
        )
        .expect("issued");

        let clock = FixedClock(1_900_000_000);
        let mut policy = Policy::new(&clock, &ALLOWED).unwrap();
        if let Some(limit) = case.limit {
            policy = policy.max_key_candidates(limit);
        }
        let got = jwt::verify(&token, Keys::Set(&set), &policy);
        let want = model_selection(&imported, &case);
        match (&want, &got) {
            (Ok(index), Ok(v)) => {
                prop_assert_eq!(v.key_index, Some(*index), "{}", json);
                prop_assert_eq!(v.kid.as_deref(), imported[*index].kid);
                prop_assert_eq!(&v.alg, &alg);
                prop_assert_eq!(&v.claims, &claims);
            }
            (Err(want), Err(got)) => prop_assert_eq!(want.code(), got.code(), "{}", json),
            _ => prop_assert!(false, "want {:?}, got {:?}\nset {}\ncase {:?}", want, got.map(|v| v.key_index), json, case),
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Nested round trip (RFC 7519 §5.2, §11.2; ADR 0027 §7)
// ---------------------------------------------------------------------------

/// The `dir` key for A256GCM: 32 fixed octets (RFC 7518 §4.5, §5.3).
fn dir_key() -> Jwk {
    jwk(&format!(r#"{{"kty":"oct","k":"{}"}}"#, oct_k(&[0x5a; 32])))
}

/// The ECDH-ES+A128KW recipient: the RFC 7515 A.3 P-256 key pair
/// (RFC 7518 §4.6).
fn p256_recipient() -> Jwk {
    let (x, y, d) = RFC7515_A3;
    jwk(&format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}","d":"{d}"}}"#
    ))
}

/// Claims that pass a policy with `allow_missing_exp` and
/// `ignore_audience` at `now`: any registered strings and audience, any
/// `iat`, an `exp` after and an `nbf` at or before `now`, and random other
/// claims.
fn nested_claims(now: i64) -> impl Strategy<Value = Claims> {
    let t = now as f64;
    (
        (
            proptest::option::of(any_string()),
            proptest::option::of(any_string()),
            proptest::option::of(audience(any_string())),
            proptest::option::of(
                (1i64..=1_000_000, fraction()).prop_map(move |(d, f)| t + d as f64 + f),
            ),
        ),
        (
            proptest::option::of(
                (0i64..=1_000_000, fraction()).prop_map(move |(d, f)| t - d as f64 - f.abs()),
            ),
            proptest::option::of(date_double()),
            proptest::option::of(any_string()),
            other_claims(),
        ),
    )
        .prop_map(|((iss, sub, aud, exp), (nbf, iat, jti, other))| {
            claims_of(iss, sub, aud, exp, nbf, iat, jti, other)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// RFC 7519 §11.2 sign-then-encrypt: any claims through `jwt::sign`
    /// (HS256 or EdDSA), `encrypt_nested` with `dir` + A256GCM or
    /// ECDH-ES+A128KW, then `decrypt_nested`, come back unchanged, with
    /// `cty: JWT` on the outer header (RFC 7519 §5.2).
    #[test]
    fn nested_round_trip_returns_the_claims(
        (signer, ecdh, enc, now, claims) in (
            signer(),
            any::<bool>(),
            select(vec![ContentEncAlg::A128GCM, ContentEncAlg::A256GCM]),
            0i64..=4_102_444_800,
        )
            .prop_flat_map(|(signer, ecdh, enc, now)| {
                (Just(signer), Just(ecdh), Just(enc), Just(now), nested_claims(now))
            }),
    ) {
        let inner = jwt::sign(&claims, &IssueOptions::new(signer.alg()), &signer.signing_key())
            .expect("issued");
        let (recipient_key, decrypt_key, alg, enc) = if ecdh {
            let key = p256_recipient();
            (key.to_public().unwrap(), key, KeyMgmtAlg::EcdhEsA128KW, enc)
        } else {
            (dir_key(), dir_key(), KeyMgmtAlg::Dir, ContentEncAlg::A256GCM)
        };
        let encryptor = Encryptor::new(enc.clone()).recipient(Recipient::new(alg.clone(), &recipient_key));
        let token = jwt::encrypt_nested(&inner, &encryptor).expect("nested");
        prop_assert_eq!(token.split('.').count(), 5);

        let decrypt_policy = DecryptPolicy::new(&[alg], core::slice::from_ref(&enc)).unwrap();
        let clock = FixedClock(now);
        let policy = Policy::new(&clock, &ALLOWED)
            .unwrap()
            .allow_missing_exp()
            .ignore_audience();
        let verifier = signer.verifying_key();
        let v = jwt::decrypt_nested(&token, &decrypt_key, &decrypt_policy, Keys::One(&verifier), &policy)
            .unwrap_or_else(|e| panic!("{e}: {}", claims.to_json()));
        prop_assert_eq!(&v.inner.claims, &claims);
        prop_assert_eq!(&v.inner.alg, &signer.alg());
        prop_assert_eq!(v.outer_header.cty.as_deref(), Some("JWT"));
        prop_assert_eq!(v.outer_header.enc.as_ref(), Some(&enc));
        prop_assert_eq!(v.recipient, 0);
    }
}

// ---------------------------------------------------------------------------
// Deterministic checks
// ---------------------------------------------------------------------------

/// `Policy::max_key_candidates` rustdoc and ADR 0029 §1, §4: the bound
/// applies to a JWK Set only. With `max_key_candidates(0)`, a single key
/// (`Keys::One`) verifies exactly as under the default policy, while the
/// same key as a one-member set (`Keys::Set`) is `NoMatchingKey`.
#[test]
fn max_key_candidates_zero_does_not_affect_a_single_key() {
    let clock = FixedClock(1_300_819_320);
    let mut claims = Claims::new();
    claims.iss = Some("joe".into());
    claims.exp = NumericDate::from_secs(1_300_819_380);
    for (signer, kid) in [
        (
            Signer {
                eddsa: false,
                key: 0,
            },
            None,
        ),
        (
            Signer {
                eddsa: true,
                key: 0,
            },
            None,
        ),
        (
            Signer {
                eddsa: true,
                key: 1,
            },
            Some("k1"),
        ),
    ] {
        let alg = signer.alg();
        let mut signing = signer.signing_key();
        let mut verifying = signer.verifying_key();
        if let Some(kid) = kid {
            // The key's kid goes into the header (ADR 0027 §8); with
            // `Keys::One` it is not compared (ADR 0029 §1).
            let with_kid = |key: &Jwk| {
                let json = key.to_json();
                jwk(&format!(
                    r#"{},"kid":"{kid}"}}"#,
                    json.strip_suffix('}').unwrap()
                ))
            };
            signing = with_kid(&signing);
            verifying = with_kid(&verifying);
        }
        let token = jwt::sign(&claims, &IssueOptions::new(alg.clone()), &signing).unwrap();

        let default = Policy::new(&clock, &ALLOWED).unwrap();
        let zero = Policy::new(&clock, &ALLOWED).unwrap().max_key_candidates(0);
        let baseline = jwt::verify(&token, Keys::One(&verifying), &default).unwrap();
        let bounded = jwt::verify(&token, Keys::One(&verifying), &zero).unwrap();
        assert_eq!(bounded, baseline, "{alg:?}");
        assert_eq!(bounded.key_index, None);
        assert_eq!(bounded.kid.as_deref(), kid);
        assert_eq!(bounded.claims, claims);

        // A wrong key is still the same error with either policy.
        let other = Signer {
            key: signer.key + 1,
            ..signer
        }
        .verifying_key();
        assert_eq!(
            jwt::verify(&token, Keys::One(&other), &zero).unwrap_err(),
            jwt::verify(&token, Keys::One(&other), &default).unwrap_err(),
        );

        // The contrast: the same key as a JWK Set is bounded (ADR 0029 §4).
        let set = JwkSet::from_json(
            format!(r#"{{"keys":[{}]}}"#, verifying.to_json().as_str()).as_bytes(),
        )
        .unwrap();
        assert_eq!(set.len(), 1);
        assert_eq!(
            jwt::verify(&token, Keys::Set(&set), &zero).unwrap_err(),
            Error::NoMatchingKey
        );
        assert_eq!(
            jwt::verify(&token, Keys::Set(&set), &default)
                .unwrap()
                .key_index,
            Some(0)
        );
    }
}
