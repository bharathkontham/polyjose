# Contributing

- Branch from `main` and open a PR. Use Conventional Commits (`feat(jws): …`) and keep each commit small and passing.
- Every behaviour change needs tests. Algorithm work needs the RFC test vectors and conformance vectors in `conformance/vectors/`.
- No new crypto dependency without discussion: pure-Rust crates only (see `deny.toml`). Never implement a primitive yourself.
- Run `scripts/test-all.sh rust` before opening a PR (plus the platforms you touched).
