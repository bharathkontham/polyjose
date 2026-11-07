#!/usr/bin/env bash
# The WASM platform's test suite (feature 0006 T02, T04; ADR 0008 layer 4, ADR 0031 §3, ADR 0034),
# run by scripts/test-all.sh's `wasm` platform (its dispatch rules: the exit status decides PASS or
# FAIL, and `SKIPPED (<reason>)` as the last line with exit 0 is reported as SKIPPED).
#
#   bindings/wasm/test.sh
#
#   1. tests/vector_index.rs on the host: the runner's embedded vector index lists exactly the
#      files under conformance/vectors/ (a stale index would run fewer vectors);
#   2. `wasm-pack test --node`: the adapter's wasm-bindgen-test suites in Node, and the
#      conformance results line -> target/conformance/wasm-node.json;
#   3. `wasm-pack test --headless --chrome --chromedriver <driver> --features browser`: the same in
#      headless Chrome -> target/conformance/wasm-chrome.json, with the chromedriver of
#      scripts/chromedriver.sh (a driver of another major version refuses Chrome);
#   4. when test-pkg/run.sh exists (T04): scripts/build-package.sh (the tarball, with the ADR 0059
#      size override and the 1 MiB check), then test-pkg/run.sh (wasm-pkg-node, -chrome, -workerd).
#
# A wasm-pack run passes only if it exits 0, prints exactly one POLYJOSE-CONFORMANCE-RESULTS line
# and ran at least one test in tests/conformance.rs and tests/engine.rs: a run whose tests all
# skip ("only configured to run in…", or a stray argument taken as a test filter: "no tests to
# run!") exits 0 too, and must fail here (0006 research §7). The results line is written even when
# the run fails, so the parity check sees what failed.
#
# Argument order matters to wasm-pack 0.15.1: its own options (--chromedriver) come first, since
# everything from the first cargo option (--features) on is passed to cargo; and the runner's
# --nocapture (which prints the results line of a passing test) goes after `-- --` when no cargo
# option precedes it, and after `--` when one does.
#
# Ends with `wasm: PASS (…)`, or `SKIPPED (<reason>)` when wasm-pack or Chrome is missing (the
# Node runs still run and must pass), or exits 1. Results files left by an earlier run are removed
# first. Don't run it at the same time as bindings/js/test.sh: build-package.sh rebuilds
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
trap 'rm -rf "$work"' EXIT

failures=()
fail() { echo "$me: FAIL: $*"; failures+=("$1"); }

mkdir -p "$results" || { echo "$me: could not create $results"; exit 1; }
rm -f "$results/wasm-node.json" "$results/wasm-chrome.json"

# --- 1. The vector index ---------------------------------------------------------------------

echo "==> $me: the vector index (cargo test -p polyjose-wasm --test vector_index)"
cargo test -p polyjose-wasm --test vector_index || fail "vector index"

# --- 2, 3. wasm-pack runs --------------------------------------------------------------------

# tests_ran <log> <test file>: whether the run of tests/<file>.rs reported at least one test.
tests_ran() {
  awk -v want="tests/$2.rs" '
    /^[[:space:]]*Running / { current = index($0, "Running " want " ") > 0; next }
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
  for t in conformance engine; do
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
    "SKIPPED ("?*")") chrome_skip=${driver#SKIPPED (}; chrome_skip=${chrome_skip%)} ;;
    /*) wasm_pack_run wasm-chrome --headless --chrome --chromedriver "$driver" --features browser -- --nocapture ;;
    *) fail "wasm-chrome: scripts/chromedriver.sh printed \"$driver\", not a path or SKIPPED (<reason>)" ;;
  esac
fi

# --- 4. The package tests (T04) --------------------------------------------------------------

pkg=""
pkg_chrome_skip=""
if [ -e test-pkg/run.sh ]; then
  echo "==> $me: the package (scripts/build-package.sh)"
  if ! scripts/build-package.sh; then
    fail "wasm-pkg: scripts/build-package.sh failed"
  else
    echo "==> $me: the package tests (test-pkg/run.sh)"
    test-pkg/run.sh </dev/null 2>&1 | tee "$work/test-pkg.out"
    rc=${PIPESTATUS[0]}
    if [ "$rc" -ne 0 ]; then
      fail "wasm-pkg: test-pkg/run.sh exited $rc"
    else
      pkg=", wasm-pkg-node, wasm-pkg-chrome, wasm-pkg-workerd"
      line=$(sed -n 's/^[[:space:]]*chrome: \(SKIPPED (.*)\)[[:space:]]*$/\1/p' "$work/test-pkg.out" | tail -n 1)
      if [ -n "$line" ]; then
        pkg=", wasm-pkg-node, wasm-pkg-workerd"
        pkg_chrome_skip=${line#SKIPPED (}; pkg_chrome_skip=${pkg_chrome_skip%)}
        # Chrome is either missing for both runs or for neither: an installed Chrome must run.
        [ -n "$chrome_skip" ] || fail "wasm-pkg-chrome: test-pkg/run.sh skipped Chrome ($pkg_chrome_skip), but Chrome is installed"
      fi
    fi
  fi
fi

# --- Result ----------------------------------------------------------------------------------

echo
if [ ${#failures[@]} -gt 0 ]; then
  echo "$me: FAILED: ${failures[*]}"
  exit 1
fi
if [ -n "$chrome_skip" ]; then
  echo "$me: wasm-node${pkg/, wasm-pkg-chrome/} passed; wasm-chrome and wasm-pkg-chrome not run"
  echo "SKIPPED ($chrome_skip)"
  exit 0
fi
echo "$me: PASS (wasm-node, wasm-chrome$pkg)"
