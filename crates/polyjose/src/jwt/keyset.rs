//! Verifying a compact JWS against a JWK Set: candidate selection by
//! `alg` and `kid`, a bounded try-in-order, and `NoMatchingKey`
//! (ADR 0029; RFC 7515 §4.1.4, §6; RFC 7517 §4.2–§4.5, §5).

use crate::error::{Error, Result};
use crate::jwk::JwkSet;
use crate::jws::Verified;

use super::Policy;

/// Verifies the compact JWS `token` against the members of `set`
/// (ADR 0029 §2–§4), returning the verified JWS and the selected
/// member's index in [`JwkSet::keys`].
///
/// The candidates are [`JwkSet::verification_candidates`] for the JWS
/// Protected Header's `alg` and `kid` (ADR 0029 §2; read from the
/// protected header only, ADR 0049 §2), after ADR 0026 §2 steps 1–7 have
/// passed. Zero candidates, or more than
/// [`Policy::max_key_candidates`], → [`Error::NoMatchingKey`] before any
/// signature is computed (ADR 0029 §4). Otherwise each candidate runs
/// ADR 0026 steps 8–9 in set order and the first success wins; if all
/// fail, the error is ranked per ADR 0026 §3 (ties to the lowest index).
///
/// **Not implemented yet** (feature 0004 T05): returns
/// [`Error::UnsupportedAlgorithm`].
pub(crate) fn verify_with_set(
    token: &str,
    set: &JwkSet,
    p: &Policy<'_>,
) -> Result<(Verified, usize)> {
    let _ = (token, set, p);
    Err(Error::UnsupportedAlgorithm)
}
