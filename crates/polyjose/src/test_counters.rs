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
