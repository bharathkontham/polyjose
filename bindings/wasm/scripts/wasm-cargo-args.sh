# shellcheck shell=bash
# The shipped @polyjose/wasm build's extra Cargo arguments, passed after `--` to wasm-pack: ADR 0059
# (superseding ADR 0031 §3 in part) overrides the workspace release profile's opt-level to "z" on
# this command line only. build-package.sh explains why. Sourced, not run, by build-package.sh (the
# shipped build) and test.sh (tests/memory.rs at the shipped opt-level), so both use one definition.
#
# Guarded (feature 0006 F06, security audit L2): scripts/check-no-cargo-config.sh allows exactly
# this line in exactly this file, and no other assignment of WASM_CARGO_ARGS or other command-line
# Cargo configuration under bindings/; scripts/check-rsa-symbols.sh builds polyjose-wasm for wasm32
# with its words. Keep it one line of plain quoted words. Changing it needs an ADR superseding
# ADR 0059 and the same change to check-no-cargo-config.sh's `allowed_line`.
# shellcheck disable=SC2034 # read by the scripts that source this file
WASM_CARGO_ARGS=(--config 'profile.release.opt-level="z"')
