//! Test-only, per-thread operation counters.
//!
//! They turn "this untrusted-input path is O(n log n)" into a deterministic
//! assertion without wall-clock timing. Each counter is thread-local, so
//! tests running in parallel never see each other's counts.
//!
//! This is the only file in polyjose allowed to hold thread-local state.
//! The inner `#![cfg(test)]` keeps it out of every non-test build however
//! it is reached, and `rng::tests::no_global_or_thread_local_state_can_switch_the_rng`
//! checks that and its single `#[cfg(test)]` declaration in `lib.rs`
//! before exempting it (ADR 0005: no global switch for the RNG).
#![cfg(test)]

/// Member-name comparisons made by `json::Object` (its `same_name` and
/// `cmp_names`), counted by `Object::count_name_comparisons`.
pub(crate) mod name_comparisons {
    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn tick() {
        COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }

    pub(crate) fn get() -> u64 {
        COUNT.with(Cell::get)
    }
}

/// Value comparisons made by the `key_ops` duplicate check (`jwk`'s
/// `KeyOpName` ordering).
pub(crate) mod key_op_comparisons {
    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn tick() {
        COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }

    /// Runs `f` and returns its result with the number of comparisons
    /// made on this thread while it ran.
    pub(crate) fn count<R>(f: impl FnOnce() -> R) -> (R, u64) {
        let before = COUNT.with(Cell::get);
        let result = f();
        (result, COUNT.with(Cell::get) - before)
    }
}

// The JWE counters (feature 0003). Each is ticked by one family task, which
// calls `tick()` under `#[cfg(test)]` and asserts with `count` in its own
// unit tests, without editing this file.

/// AES-CBC decryptions started by A*CBC-HS* (`jwe/enc_cbc_hmac.rs`, T03),
/// ticked right before the CBC decryption: a tag that fails the HMAC check
/// must leave it at 0 (RFC 7518 §5.2.2.2).
pub(crate) mod cbc_hmac_decryptions {
    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn tick() {
        COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }

    /// Runs `f` and returns its result with the number of ticks on this
    /// thread while it ran.
    pub(crate) fn count<R>(f: impl FnOnce() -> R) -> (R, u64) {
        let before = COUNT.with(Cell::get);
        let result = f();
        (result, COUNT.with(Cell::get) - before)
    }
}

/// PBKDF2 derivations started by PBES2 (`jwe/pbes2.rs`, T12): a `p2c` over
/// the policy bound must leave it at 0 (RFC 7518 §4.8, ADR 0023).
pub(crate) mod pbkdf2_derivations {
    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn tick() {
        COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }

    /// Runs `f` and returns its result with the number of ticks on this
    /// thread while it ran.
    pub(crate) fn count<R>(f: impl FnOnce() -> R) -> (R, u64) {
        let before = COUNT.with(Cell::get);
        let result = f();
        (result, COUNT.with(Cell::get) - before)
    }
}

/// Diffie-Hellman agreements computed for ECDH-ES (`jwe/ecdh_nist.rs` and
/// `jwe/ecdh_x25519.rs`, T13 and T07): an invalid `epk` must leave it at 0
/// (RFC 7518 §4.6, RFC 8725 §3.4).
pub(crate) mod ecdh_agreements {
    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn tick() {
        COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }

    /// Runs `f` and returns its result with the number of ticks on this
    /// thread while it ran.
    pub(crate) fn count<R>(f: impl FnOnce() -> R) -> (R, u64) {
        let before = COUNT.with(Cell::get);
        let result = f();
        (result, COUNT.with(Cell::get) - before)
    }
}

/// RSA-OAEP-256 Encrypted Key decryptions (`jwe/rsa_oaep.rs`, feature
/// 0020): ticked once per decryption, whatever its outcome, so a test can
/// show that a malformed Encrypted Key takes the same path as a valid one
/// (RFC 7516 §11.5).
pub(crate) mod rsa_oaep_unwraps {
    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn tick() {
        COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }

    /// Runs `f` and returns its result with the number of ticks on this
    /// thread while it ran.
    pub(crate) fn count<R>(f: impl FnOnce() -> R) -> (R, u64) {
        let before = COUNT.with(Cell::get);
        let result = f();
        (result, COUNT.with(Cell::get) - before)
    }
}

/// Content decryptions run by JWE (`jwe/content.rs`, feature 0020): with
/// [`rsa_oaep_unwraps`], it shows that a malformed RSA-OAEP-256 Encrypted
/// Key still reaches the content decryption (RFC 7516 §11.5).
pub(crate) mod content_decryptions {
    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn tick() {
        COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }

    /// Runs `f` and returns its result with the number of ticks on this
    /// thread while it ran.
    pub(crate) fn count<R>(f: impl FnOnce() -> R) -> (R, u64) {
        let before = COUNT.with(Cell::get);
        let result = f();
        (result, COUNT.with(Cell::get) - before)
    }
}

/// Inflate calls made by JWE `zip` (`jwe/zip.rs`, T15): a JWE whose tag
/// fails must leave it at 0, since decompression comes after tag
/// verification (RFC 7516 §5.2 step 17).
pub(crate) mod inflate_calls {
    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn tick() {
        COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }

    /// Runs `f` and returns its result with the number of ticks on this
    /// thread while it ran.
    pub(crate) fn count<R>(f: impl FnOnce() -> R) -> (R, u64) {
        let before = COUNT.with(Cell::get);
        let result = f();
        (result, COUNT.with(Cell::get) - before)
    }
}

/// JWS Signatures checked through the counting `Families` double of
/// `jws/compact.rs`'s tests (feature 0004, T05a): `precheck_compact` must
/// leave it at 0, and `finish_compact` reaches it once per key that passed
/// key binding (ADR 0026 §2 steps 8–9, ADR 0027 §9).
pub(crate) mod jws_family_verifies {
    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn tick() {
        COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }

    /// Runs `f` and returns its result with the number of ticks on this
    /// thread while it ran.
    pub(crate) fn count<R>(f: impl FnOnce() -> R) -> (R, u64) {
        let before = COUNT.with(Cell::get);
        let result = f();
        (result, COUNT.with(Cell::get) - before)
    }
}

/// JWS Signatures computed through the same double: verification must
/// leave it at 0.
pub(crate) mod jws_family_signs {
    use core::cell::Cell;

    std::thread_local! {
        static COUNT: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn tick() {
        COUNT.with(|c| c.set(c.get().saturating_add(1)));
    }

    /// Runs `f` and returns its result with the number of ticks on this
    /// thread while it ran.
    pub(crate) fn count<R>(f: impl FnOnce() -> R) -> (R, u64) {
        let before = COUNT.with(Cell::get);
        let result = f();
        (result, COUNT.with(Cell::get) - before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jws_counters_count_only_their_own_ticks_while_f_runs() {
        let ((), n) = jws_family_verifies::count(|| {
            jws_family_verifies::tick();
            jws_family_signs::tick();
        });
        assert_eq!(n, 1);
        assert_eq!(jws_family_signs::count(jws_family_signs::tick).1, 1);
        assert_eq!(jws_family_signs::count(jws_family_verifies::tick).1, 0);
    }

    #[test]
    fn jwe_counters_count_only_their_own_ticks_while_f_runs() {
        cbc_hmac_decryptions::tick();
        let ((), n) = cbc_hmac_decryptions::count(|| {
            cbc_hmac_decryptions::tick();
            cbc_hmac_decryptions::tick();
            pbkdf2_derivations::tick();
        });
        assert_eq!(n, 2);
        assert_eq!(pbkdf2_derivations::count(|| ()).1, 0);
        let (value, n) = pbkdf2_derivations::count(|| {
            pbkdf2_derivations::tick();
            7
        });
        assert_eq!((value, n), (7, 1));
        assert_eq!(ecdh_agreements::count(ecdh_agreements::tick).1, 1);
        assert_eq!(inflate_calls::count(inflate_calls::tick).1, 1);
        assert_eq!(inflate_calls::count(ecdh_agreements::tick).1, 0);
    }
}
