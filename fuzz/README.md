# fuzz

cargo-fuzz targets for the core's parsers: `der_pem`, `inflate`, `jose_header`, `json`, `jwe`, `jwk`, `jws` and `jwt` (`fuzz_targets/`, shared harness in `src/lib.rs`).

**Why it is separate:** cargo-fuzz needs a nightly toolchain and sanitizer flags, so this is its own Cargo workspace with its own `Cargo.lock`, on the nightly pinned in `nightly-toolchain`. The main workspace stays on stable.

- `seeds/<target>/`: committed seed inputs, taken from the conformance vectors. A run copies them into `corpus/<target>/` (git-ignored), so the seeds never grow.
- `jose.dict`: a libFuzzer dictionary of JOSE tokens.

Run every target for a fixed time, before a release: `scripts/fuzz.sh [--seconds N] [target ...]` (setup: `cargo install cargo-fuzz --version '=0.13.2' --locked` and `rustup toolchain install "$(cat fuzz/nightly-toolchain)"`). One target by hand, from this folder: `cargo +$(cat nightly-toolchain) fuzz run <target> -- -max_total_time=60`.

A crash input or stack trace is a vulnerability report until it is fixed: report it as [SECURITY.md](../SECURITY.md) says, not in a public issue.
