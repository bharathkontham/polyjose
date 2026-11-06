//! Real curve points for JWK test fixtures.
//!
//! JWK import checks that EC points are on their curve and that `d` is in
//! [1, n − 1] (ADR 0041 §4), so fixtures that only need *some* valid key use
//! these instead of repeated octets. Each entry is a consistent key pair:
//! the public point is d·G. The values were computed independently of
//! polyjose and of RustCrypto (Python big-integer arithmetic over the
//! published SEC 2 / FIPS 186-5 curve parameters, checking n·G = identity).
//! Not every test file uses every item.
#![allow(
    dead_code,
    reason = "a shared fixture module; each test crate uses a subset"
)]

/// The Wycheproof JWE reader (0003 T16's `tests/jwe_wycheproof.rs`).
pub mod jwe_wycheproof;

/// One EC key pair, base64url of the fixed-length big-endian octets.
pub struct EcKeyPair {
    pub crv: &'static str,
    /// The coordinate and scalar length in octets (RFC 7518 §6.2.1.2).
    pub len: usize,
    pub x: &'static str,
    pub y: &'static str,
    pub d: &'static str,
}

/// The generator G of each curve, with d = 1.
pub const GENERATORS: [EcKeyPair; 4] = [
    EcKeyPair {
        crv: "P-256",
        len: 32,
        x: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        y: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
    },
    EcKeyPair {
        crv: "P-384",
        len: 48,
        x: "qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3",
        y: "NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f",
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
    },
    EcKeyPair {
        crv: "P-521",
        len: 66,
        x: "AMaFjga3BATpzZ4-y2YjlbRCnGSBOQU_tSH4KK9ga009uqFLXnfv51ko_h3BJ6L_qN4zSLPBhWpCm_l-fjHC5b1m",
        y: "ARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple9CZAxVC5AT-tB2E1PHCGonLCQIi-lHaf0WZQ",
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
    },
    EcKeyPair {
        crv: "secp256k1",
        len: 32,
        x: "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g",
        y: "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg",
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
    },
];

/// For each curve, a point k·G whose `x` begins with a zero octet (two for
/// P-521), with its small `d` = k, so both keep leading zero octets in their
/// fixed-length encoding (RFC 8812 §3.1, RFC 7518 §6.2.2.1).
pub const LEADING_ZEROS: [EcKeyPair; 4] = [
    EcKeyPair {
        crv: "P-256",
        len: 32,
        x: "AFVDiUrz0A7X10Cr29dclrBod7eH219w7qeLkKjXwAo",
        y: "u0yFo9jqKe-q-iRAaRLdhNWxTcMr9lbvbGvVil2UP5I",
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXs",
    },
    EcKeyPair {
        crv: "P-384",
        len: 48,
        x: "AE0QSybuVnH3LBDJhoQdPmXSheJRYWG3uqNBsSYxueMrbw1YlthDHFHV2To3y8kO",
        y: "8RoeP4t7kFOO5CzADuk0puLuJVQWB9j7ZceosR4viGhTiG7vOGXskzIAufJVmfKf",
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADF",
    },
    EcKeyPair {
        crv: "P-521",
        len: 66,
        x: "AABgqI2FlqLGWXstxORl39fnSgvLe4Y_VvIcFBSllYtipJWZb9hrjp54pnEseIfnXfzpcqBOEsuc-eAy_yrBr_8Z",
        y: "ATPR_AqtuggGE1eNKYDHf-Y8t80KYNGt8rLlCNmsniqLHQxTiNHLsF8OLFjQHLzAWUWSk9SYKLYfR8Hy7euJFFKK",
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAER",
    },
    EcKeyPair {
        crv: "secp256k1",
        len: 32,
        x: "AOOuGXRWbKBsxRbUfg-xZaZ0o9q8_KFeci8ONFD0WIk",
        y: "Kuq-fkUxUQEWIX8Hv00HMA3pfkh0-B9TNCCnLusL1qQ",
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJk",
    },
];

/// The generator key pair of `crv`.
pub fn generator(crv: &str) -> &'static EcKeyPair {
    GENERATORS
        .iter()
        .find(|k| k.crv == crv)
        .unwrap_or_else(|| panic!("no EC fixture for {crv}"))
}

/// The RFC 8037 Appendix A.1/A.2 Ed25519 key pair.
pub const ED25519_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
pub const ED25519_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
