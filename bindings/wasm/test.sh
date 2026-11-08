#!/usr/bin/env bash
# The WASM platform's test suite (feature 0006 T02, T04, F08; ADR 0008 layer 4, ADR 0031 §3, ADR 0034),
# run by scripts/test-all.sh's `wasm` platform (its dispatch rules: the exit status decides PASS or
# FAIL, and `SKIPPED (<reason>)` as the last line with exit 0 is reported as SKIPPED).
#
#   bindings/wasm/test.sh
#
#   1. tests/vector_index.rs on the host: the runner's embedded vector index lists exactly the
#      files under conformance/vectors/ (a stale index would run fewer vectors);
#   2. `wasm-pack test --node`: the adapter's wasm-bindgen-test suites in Node (tests/conformance.rs,
#      tests/engine.rs and tests/memory.rs, dev profile), and the conformance results line ->
#      target/conformance/wasm-node.json;
#   3. `wasm-pack test --headless --chrome --chromedriver <driver> --features browser`: the same in
#      headless Chrome -> target/conformance/wasm-chrome.json, with the chromedriver of
#      scripts/chromedriver.sh (a driver of another major version refuses Chrome);
#   3b. `wasm-pack test --release --node -- <WASM_CARGO_ARGS> --test memory`: tests/memory.rs once
#      more, in Node, at the opt-level the shipped .wasm is built with (ADR 0059: the arguments
#      come from scripts/wasm-cargo-args.sh, the one definition build-package.sh uses too, so
#      the two cannot drift; 0006 F06). Its stack counts depend on code generation, and the release column of its
#      KNOWN table (the package's stack exceptions, review S2 and audit L3) only shows in this
#      build. It prints how long it took (18 s here with a warm target dir, 2026-11-07). A Chrome
#      run of the same build is left out: it measures the same module, whose counts F03 found
#      equal in both engines, and would add about 10 s;
#   4. always: scripts/build-package.sh (the tarball, with the ADR 0059 size override and the 1 MiB
#      check), then test-pkg/run.sh (wasm-pkg-node, -chrome, -workerd). A missing or
#      non-executable run.sh is a FAIL, never a silent drop of those three runners (review N6).
#
# A wasm-pack run of steps 2 and 3 passes only if it exits 0, prints exactly one
# POLYJOSE-CONFORMANCE-RESULTS line and ran at least one test in each of tests/conformance.rs,
# tests/engine.rs and tests/memory.rs; the run of step 3b, only if it exits 0 and ran at least one
# test in tests/memory.rs. A run whose tests all skip ("only configured to run in…", or a stray
# argument taken as a test filter: "no tests to run!") exits 0 too, and must fail here (0006
# research §7). The results line is written even when the run fails, so the parity check sees what
# failed.
#
# Argument order matters to wasm-pack 0.15.1: its own options (--release, --chromedriver) come
# first, since everything from the first cargo option (--features) on is passed to cargo, and so is
# everything after a first `--` (step 3b's --config and --test; a Chrome form would put them after
# --features: `--headless --chrome --features browser --test memory`); and the runner's
# --nocapture (which prints the results line of a passing test) goes after `-- --` when no cargo
# option precedes it, and after `--` when one does.
#
# Without Chrome (scripts/chromedriver.sh and test-pkg/src/chrome.ts find none) the two Chrome
# runners are waived, each with a line in scripts/test-all.sh's exact form (ADR 0060 §7, feature
# 0013 F05; wasm-chrome and wasm-pkg-chrome are the `?` runners of its `wasm` line):
#   SKIPPED-RUNNER (wasm-chrome: host:no-chrome)        printed here
#   SKIPPED-RUNNER (wasm-pkg-chrome: host:no-chrome)    printed by test-pkg/run.sh
# and the platform still passes on the other three runners, which must run and write their files.
# test-all.sh then reports the two runners SKIPPED under parity, never as passing (pipeline rule 9).
# A workerd (miniflare) failure is a failure, never a waiver.
#
# Ends with `wasm: PASS (…)`, or `SKIPPED (wasm-pack missing)`, or exits 1. Results files left by
# an earlier run are removed first. Don't run it at the same time as bindings/js/test.sh: build-package.sh rebuilds
# bindings/js/dist. Runs on macOS /bin/bash 3.2 and Linux bash.
set -uo pipefail
export LC_ALL=C

me=wasm
here=$(cd "$(dirname "$0")" && pwd -P) || exit 1
repo=$(cd "$here/../.." && pwd -P) || exit 1
results=$repo/target/conformance
marker='POLYJOSE-CONFORMANCE-RESULTS '
cd "$here" || exit 1

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "SKIPPED (wasm-pack missing)"
  exit 0
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/wasm-test.XXXXXX") || { echo "$me: mktemp failed"; exit 1; }
# Fail closed on a syntax error under bash 3.2 (feature 0013 F10; see scripts/test-all.sh): an exit
# before the last line, with status 0, becomes 2.
completed=""
trap 'rc=$?; rm -rf "$work"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "wasm/test.sh: stopped before its last line (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT

failures=()
fail() { echo "$me: FAIL: $*"; failures+=("$1"); }

mkdir -p "$results" || { echo "$me: could not create $results"; exit 1; }
rm -f "$results/wasm-node.json" "$results/wasm-chrome.json"

# --- 1. The vector index ---------------------------------------------------------------------

echo "==> $me: the vector index (cargo test -p polyjose-wasm --test vector_index)"
cargo test -p polyjose-wasm --test vector_index || fail "vector index"

# --- 2, 3. wasm-pack runs --------------------------------------------------------------------

# tests_ran <log> <test file>: whether the run of tests/<file>.rs reported at least one test.
# Cargo's own target lines are indented ("     Running tests/x.rs (…)"); the browser runner's
# "Running headless tests in Chrome on …" is not, and belongs to the current target.
tests_ran() {
  awk -v want="tests/$2.rs" '
    /^[[:space:]]+Running / { current = index($0, "Running " want " ") > 0; next }
    current && /^running [0-9]+ tests?$/ { if ($2 + 0 > 0) found = 1 }
    END { exit !found }' "$1"
}

# wasm_pack_run <runner> <wasm-pack arguments...>: one run, checked, its results line written to
# target/conformance/<runner>.json.
wasm_pack_run() {
  local runner=$1 log rc=0 lines t
  shift
  log="$work/$runner.log"
  echo "==> $me: $runner: wasm-pack test $*"
  wasm-pack test "$@" >"$log" 2>&1 || rc=$?
  # The results line is ~150 KB; everything else is shown.
  grep -v "^$marker" "$log"
  lines=$(grep -c "^$marker" "$log" || true)
  if [ "$lines" -ge 1 ]; then
    grep "^$marker" "$log" | head -n 1 | sed "s/^$marker//" >"$work/$runner.json"
    mv "$work/$runner.json" "$results/$runner.json" || fail "$runner: could not write $results/$runner.json"
    echo "$me: $runner: wrote ${results#"$repo"/}/$runner.json"
  fi
  [ "$rc" -eq 0 ] || fail "$runner: wasm-pack test exited $rc"
  [ "$lines" -eq 1 ] || fail "$runner: $lines results line(s), expected exactly 1 (did the conformance test run?)"
  for t in conformance engine memory; do
    tests_ran "$log" "$t" || fail "$runner: tests/$t.rs ran no test (all skipped or filtered out)"
  done
}

wasm_pack_run wasm-node --node -- -- --nocapture

chrome_skip=""
driver_out="$work/chromedriver.out"
if ! scripts/chromedriver.sh >"$driver_out"; then
  fail "wasm-chrome: scripts/chromedriver.sh could not provide a chromedriver for the installed Chrome"
else
  driver=$(tail -n 1 "$driver_out")
  case $driver in
    "SKIPPED ("?*")")
      chrome_skip=${driver#SKIPPED (}; chrome_skip=${chrome_skip%)}
      echo "$me: wasm-chrome not run: $chrome_skip"
      echo "SKIPPED-RUNNER (wasm-chrome: host:no-chrome)" ;;
    /*) wasm_pack_run wasm-chrome --headless --chrome --chromedriver "$driver" --features browser -- --nocapture ;;
    *) fail "wasm-chrome: scripts/chromedriver.sh printed \"$driver\", not a path or SKIPPED (<reason>)" ;;
  esac
fi

# --- 3b. tests/memory.rs at the shipped opt-level (ADR 0059) ---------------------------------

# memory_release_run <wasm-pack arguments...>: one run of tests/memory.rs, checked. It runs no
# conformance test, so it writes no results file and is not a parity runner.
memory_release_run() {
  local log="$work/memory-release.log" rc=0 start=$SECONDS
  echo "==> $me: tests/memory.rs at the shipped opt-level: wasm-pack test $*"
  wasm-pack test "$@" >"$log" 2>&1 || rc=$?
  cat "$log"
  [ "$rc" -eq 0 ] || fail "memory (release, opt-level z): wasm-pack test exited $rc"
  tests_ran "$log" memory || fail "memory (release, opt-level z): tests/memory.rs ran no test (all skipped or filtered out)"
  echo "$me: tests/memory.rs at the shipped opt-level took $((SECONDS - start)) s"
}

# The shipped build's extra Cargo arguments, from their one definition (ADR 0059; 0006 F06).
# shellcheck source=scripts/wasm-cargo-args.sh
if . "$here/scripts/wasm-cargo-args.sh"; then
  memory_release_run --release --node -- "${WASM_CARGO_ARGS[@]}" --test memory
else
  fail "memory (release, opt-level z): cannot read scripts/wasm-cargo-args.sh"
fi

# --- 4. The package tests (T04) --------------------------------------------------------------

# Unconditional: the T04 toggle (`if [ -e test-pkg/run.sh ]`) is gone, so no state of the tree
# drops the three package runners (review N6).
pkg_chrome_skip=""
echo "==> $me: the package (scripts/build-package.sh)"
if ! scripts/build-package.sh; then
  fail "wasm-pkg: scripts/build-package.sh failed"
else
  echo "==> $me: the package tests (test-pkg/run.sh)"
  test-pkg/run.sh </dev/null 2>&1 | tee "$work/test-pkg.out"
  rc=${PIPESTATUS[0]}
  if [ "$rc" -ne 0 ]; then
    [ -f test-pkg/run.sh ] && [ -x test-pkg/run.sh ] || echo "$me: test-pkg/run.sh is missing or not executable"
    fail "wasm-pkg: test-pkg/run.sh exited $rc"
  else
    line=$(sed -n 's/^[[:space:]]*chrome: \(SKIPPED (.*)\)[[:space:]]*$/\1/p' "$work/test-pkg.out" | tail -n 1)
    waiver=$(grep -c '^SKIPPED-RUNNER (wasm-pkg-chrome: host:no-chrome)$' "$work/test-pkg.out" || true)
    if [ -n "$line" ]; then
      pkg_chrome_skip=${line#SKIPPED (}; pkg_chrome_skip=${pkg_chrome_skip%)}
      # Chrome is either missing for both runs or for neither: an installed Chrome must run.
      [ -n "$chrome_skip" ] || fail "wasm-pkg-chrome: test-pkg/run.sh skipped Chrome ($pkg_chrome_skip), but Chrome is installed"
      [ "$waiver" -eq 1 ] || fail "wasm-pkg-chrome: test-pkg/run.sh skipped Chrome without exactly one SKIPPED-RUNNER (wasm-pkg-chrome: host:no-chrome) line"
    else
      [ "$waiver" -eq 0 ] || fail "wasm-pkg-chrome: test-pkg/run.sh printed a SKIPPED-RUNNER line, but its Chrome run was not skipped"
    fi
  fi
fi

# --- Result ----------------------------------------------------------------------------------

# Every runner that was not waived wrote its results file (scripts/test-all.sh requires each one
# of a passing platform, ADR 0060 §7), so a run that wrote none fails here, by name, too.
ran="wasm-node wasm-pkg-node wasm-pkg-workerd"
[ -n "$chrome_skip" ] || ran="$ran wasm-chrome"
[ -n "$pkg_chrome_skip" ] || ran="$ran wasm-pkg-chrome"
for runner in $ran; do
  [ -f "$results/$runner.json" ] || fail "$runner: no ${results#"$repo"/}/$runner.json"
done

echo
status=0
if [ ${#failures[@]} -gt 0 ]; then
  echo "$me: FAILED: ${failures[*]}"
  status=1
elif [ -n "$chrome_skip" ]; then
  echo "$me: PASS (wasm-node, wasm-pkg-node, wasm-pkg-workerd; wasm-chrome and wasm-pkg-chrome not run, host:no-chrome)"
else
  echo "$me: PASS (wasm-node, wasm-chrome, wasm-pkg-node, wasm-pkg-chrome, wasm-pkg-workerd)"
fi
completed=1; exit "$status"
