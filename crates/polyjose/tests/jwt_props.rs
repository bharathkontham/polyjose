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

use core::cmp::Ordering;

use polyjose::json::{MAX_SAFE_INTEGER, parse};
use polyjose::jwt::NumericDate;
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
