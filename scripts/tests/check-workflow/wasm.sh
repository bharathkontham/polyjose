#!/usr/bin/env bash
# The negative tests of the WASM package's workflow check (feature 0006 T05, T06; ADR 0044,
# ADR 0037 §1, §2): runs `bindings/wasm/scripts/check-workflow.sh --self-test`, which checks the real
# .github/workflows/binding-wasm.yml and fails each of its scratch copies that adds a PR, push or
# schedule trigger, a secret or token, write permissions, a publish step or an unpinned action. The
# self-test lives with the script (T05); this wrapper puts it among scripts/tests/<gate>/*.sh, so
# scripts/test-all.sh's negative-test step runs it.
#
# Exits with the self-test's status (0 passed, 1 a case failed, 2 a setup error). Its output passes
# through unchanged, including a `SKIPPED (actionlint missing)` last line when actionlint isn't
# installed (the text cases still ran and passed). Usage: scripts/tests/check-workflow/wasm.sh.
# Runs on macOS /bin/bash 3.2 and Linux bash.
set -uo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd -P) || exit 2
exec "$repo/bindings/wasm/scripts/check-workflow.sh" --self-test </dev/null
