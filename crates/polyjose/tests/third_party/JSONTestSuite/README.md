# JSONTestSuite (vendored)

- Upstream: https://github.com/nst/JSONTestSuite
- Commit: `1ef36fa01286573e846ac449e8683f8833c5b26a` (2024-11-22, "Merge pull request #139 from hsjoihs/patch-hsjoihs")
- Vendored: `test_parsing/` only (318 files), byte for byte, on 2026-11-05.
- License: MIT, Copyright (c) 2016 Nicolas Seriot. See `LICENSE` in this directory.

File name prefixes (upstream convention):

- `y_`: the parser must accept the text.
- `n_`: the parser must reject the text.
- `i_`: RFC 8259 leaves the result to the implementation.

`crates/polyjose/tests/json_test_suite.rs` runs every file through
`polyjose::json::parse` and records the expected result for each `i_` case.

To update: clone upstream at a new commit, replace `test_parsing/`, update
the commit above, and re-check the `i_` table and the exceptions in the
runner.
