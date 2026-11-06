//! Where JWT validation gets the current time: an injected [`Clock`]
//! (ADR 0028). This is the only file of `jwt` allowed to read a platform
//! clock (ADR 0028 §5; asserted by a test below).

use crate::error::{Error, Result};
use crate::json::MAX_SAFE_INTEGER;

/// The source of "the current date/time" that JWT validation compares
/// `exp`, `nbf` and `iat` with (RFC 7519 §4.1.4–§4.1.6; ADR 0028).
///
/// polyjose never reads a clock implicitly: a [`Policy`](super::Policy)
/// cannot be built without one (ADR 0028 §3). Use [`SystemClock`] in
/// production where std has a clock, a clock over `Date.now()` in a
/// browser (the WASM binding supplies one), and [`FixedClock`] in tests or
/// to validate "as of" a past instant.
///
/// ```
/// use polyjose::jwt::{Clock, FixedClock};
///
/// let clock = FixedClock(1300819380);
/// assert_eq!(clock.now()?, 1300819380);
/// # Ok::<(), polyjose::Error>(())
/// ```
pub trait Clock: Send + Sync {
    /// Whole seconds since 1970-01-01T00:00:00Z, ignoring leap seconds
    /// (RFC 7519 §2). A sub-second clock floors its time.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidClaim`]`("clock")` when the time is unavailable,
    /// for example a system clock set before the epoch or a binding
    /// callback that throws (ADR 0028 §1). A clock never panics.
    ///
    /// Validation also rejects a time outside ±(2^53 − 1) with that error,
    /// whatever the clock returns (ADR 0028 §1, ADR 0027 §2).
    fn now(&self) -> Result<i64>;
}

/// A clock that always returns the same instant, in whole seconds since
/// the epoch (ADR 0028 §2).
///
/// For tests and conformance vectors, which must give the same verdict on
/// every day (RFC 7519 §3.1's example expired in 2011), and for callers
/// validating a token as of a past time. **Not for production
/// validation:** a fixed clock never advances, so tokens it accepts never
/// expire.
///
/// [`now`](Clock::now) fails with [`Error::InvalidClaim`]`("clock")` if
/// the instant is outside ±(2^53 − 1), the NumericDate range
/// (ADR 0027 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock(pub i64);

impl Clock for FixedClock {
    fn now(&self) -> Result<i64> {
        in_range(self.0)
    }
}

/// The operating system's wall clock: `std::time::SystemTime` relative to
/// the Unix epoch, floored to whole seconds (RFC 7519 §2; ADR 0028 §2).
///
/// Not available on `wasm32-unknown-unknown`, where std has no clock and
/// reading it panics (ADR 0028, Context): there the type does not exist,
/// so a missing clock is a compile error, never a runtime panic. Browser
/// callers pass a clock over `Date.now()` instead.
///
/// [`now`](Clock::now) fails with [`Error::InvalidClaim`]`("clock")` if
/// the system time is before the epoch or beyond ±(2^53 − 1) seconds.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Clock for SystemClock {
    fn now(&self) -> Result<i64> {
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::InvalidClaim("clock"))?;
        let secs =
            i64::try_from(since_epoch.as_secs()).map_err(|_| Error::InvalidClaim("clock"))?;
        in_range(secs)
    }
}

/// Reads `clock`, rejecting a time outside ±(2^53 − 1) whatever the
/// clock's implementation (ADR 0028 §1). Validation reads the time only
/// through this.
///
/// # Errors
///
/// [`Error::InvalidClaim`]`("clock")`, or the clock's own error.
pub(crate) fn now_checked(clock: &dyn Clock) -> Result<i64> {
    in_range(clock.now()?)
}

/// `secs` if it is within ±(2^53 − 1) (ADR 0028 §1, RFC 7493 §2.2).
fn in_range(secs: i64) -> Result<i64> {
    if secs.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs() {
        Ok(secs)
    } else {
        Err(Error::InvalidClaim("clock"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock whose source returns any value, for the range check.
    struct Raw(i64);

    impl Clock for Raw {
        fn now(&self) -> Result<i64> {
            Ok(self.0)
        }
    }

    /// A clock whose source fails, as a binding callback might.
    struct Failing;

    impl Clock for Failing {
        fn now(&self) -> Result<i64> {
            Err(Error::InvalidClaim("clock"))
        }
    }

    #[test]
    fn fixed_clock_returns_its_instant() {
        for t in [0, 1_300_819_380, -1, MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER] {
            assert_eq!(FixedClock(t).now(), Ok(t));
        }
    }

    #[test]
    fn fixed_clock_outside_the_safe_range_is_an_error() {
        // ADR 0028 §1: the same ±(2^53 − 1) range as a NumericDate.
        for t in [
            MAX_SAFE_INTEGER + 1,
            -MAX_SAFE_INTEGER - 1,
            i64::MAX,
            i64::MIN,
        ] {
            assert_eq!(FixedClock(t).now(), Err(Error::InvalidClaim("clock")));
        }
    }

    #[test]
    fn now_checked_bounds_any_clock() {
        assert_eq!(now_checked(&Raw(42)), Ok(42));
        assert_eq!(now_checked(&Raw(MAX_SAFE_INTEGER)), Ok(MAX_SAFE_INTEGER));
        assert_eq!(
            now_checked(&Raw(MAX_SAFE_INTEGER + 1)),
            Err(Error::InvalidClaim("clock"))
        );
        assert_eq!(
            now_checked(&Raw(i64::MIN)),
            Err(Error::InvalidClaim("clock"))
        );
        assert_eq!(now_checked(&Failing), Err(Error::InvalidClaim("clock")));
    }

    #[test]
    fn clock_is_object_safe_send_and_sync() {
        fn shared<T: Send + Sync + ?Sized>(_: &T) {}
        let clock: &dyn Clock = &FixedClock(7);
        shared(clock);
        assert_eq!(clock.now(), Ok(7));
    }

    /// `SystemClock` exists where std has a clock, and is a `Clock`. Its
    /// `now` is never called: no test reads the wall clock (ADR 0028 §5,
    /// pipeline rule 8).
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    #[test]
    fn system_clock_is_a_clock() {
        fn is_clock<T: Clock + Default + Copy + core::fmt::Debug>() {}
        is_clock::<SystemClock>();
        assert_eq!(format!("{SystemClock:?}"), "SystemClock");
    }

    /// Every source file of `jwt` other than this one, by name. A new file
    /// must be added here: [`the_scan_covers_every_jwt_source_file`]
    /// fails otherwise.
    const OTHER_SOURCES: &[(&str, &str)] = &[
        ("mod.rs", include_str!("mod.rs")),
        ("numeric_date.rs", include_str!("numeric_date.rs")),
        ("policy.rs", include_str!("policy.rs")),
        ("typ.rs", include_str!("typ.rs")),
    ];

    /// Names of platform time sources that must not appear outside this
    /// file (ADR 0028 §5).
    const TIME_SOURCES: &[&str] = &["SystemTime", "UNIX_EPOCH", "Instant"];

    #[test]
    fn no_other_jwt_file_reads_a_platform_clock() {
        for (name, source) in OTHER_SOURCES {
            for needle in TIME_SOURCES {
                assert!(
                    !source.contains(needle),
                    "{name} names {needle}: only clock.rs may read the time (ADR 0028 §5)"
                );
            }
        }
    }

    #[test]
    fn the_scan_covers_every_jwt_source_file() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/jwt");
        let mut on_disk: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name != "clock.rs")
            .collect();
        on_disk.sort();
        let mut scanned: Vec<String> = OTHER_SOURCES
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        scanned.sort();
        assert_eq!(scanned, on_disk);
    }
}
