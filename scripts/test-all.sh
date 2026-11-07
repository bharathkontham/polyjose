#!/usr/bin/env bash
# Run polyjose's test suites on every platform (or the ones named as arguments).
# A platform whose toolchain or test suite is missing is reported as SKIPPED with the reason,
# never silently passed; a suite that exists always runs and can FAIL.
# wasm, node, android and apple run their binding's own script when it exists (bindings/wasm/test.sh,
# bindings/node/test.sh, platforms/android/test.sh, platforms/swift/test.sh; see dispatch below).
# After the suites, scripts/conformance-parity.sh compares their conformance results (ADR 0034 §5).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
platforms=("$@"); [ ${#platforms[@]} -eq 0 ] && platforms=(rust wasm node android apple)
summary=""; status=0
record() { summary="$summary
  $1: $2"; [ "$2" = FAIL ] && status=1; return 0; }
have() { command -v "$1" >/dev/null 2>&1; }
# True when bindings/wasm/Cargo.toml declares wasm-bindgen-test as a dev-dependency in any form
# (plain or target-specific [dev-dependencies], its own table, or renamed via `package =`),
# i.e. a wasm test suite exists.
has_wasm_suite() {
  awk '/^[[:space:]]*\[/ { dev = /dev-dependencies(\.[^]]*)?\]/; if (/dev-dependencies\."?wasm-bindgen-test"?\]/) found = 1; next }
       dev && /^[[:space:]]*"?wasm-bindgen-test"?[[:space:]]*[.=]/ { found = 1 }
       dev && /package[[:space:]]*=[[:space:]]*"wasm-bindgen-test"/ { found = 1 }
       END { exit !found }' bindings/wasm/Cargo.toml
}
run() { local name=$1; shift; echo "==> $name"; if "$@"; then record "$name" PASS; else record "$name" FAIL; fi; }
scratch=$(mktemp -d "${TMPDIR:-/tmp}/test-all.XXXXXX") || { echo "mktemp failed"; exit 2; }
trap 'rm -rf "$scratch"' EXIT
# Each binding feature owns its platform's suite as one script (feature 0013 T04, ADR 0030 §1), so
# the four can change their test commands without editing this file. platform_script prints it.
platform_script() {
  case $1 in
    wasm) echo bindings/wasm/test.sh ;;
    node) echo bindings/node/test.sh ;;
    android) echo platforms/android/test.sh ;;
    apple) echo platforms/swift/test.sh ;;
    *) return 1 ;;
  esac
}
# dispatch <platform>: runs the platform's script from the repository root, with no stdin, and
# returns 0; returns 1 if there is none, so the caller runs the inline commands below (and their
# SKIPPED reasons, 0001 T14). The script's exit status decides PASS or FAIL. A script that cannot
# run its suite (no simulator, no emulator) exits 0 with `SKIPPED (<reason>)` as its last non-blank
# line, which is reported as SKIPPED and never as passing (pipeline rule 9); a last line that starts
# with SKIPPED in any other form FAILs, and so does a script that exists but is not an executable
# file (falling back to the inline commands would hide that the platform's own suite never ran).
dispatch() {
  local name=$1 script out last rc
  script=$(platform_script "$name") || return 1
  [ -e "$script" ] || [ -L "$script" ] || return 1
  echo "==> $name ($script)"
  if [ ! -f "$script" ] || [ ! -x "$script" ]; then
    echo "$script exists but is not an executable file (chmod +x $script)"; record "$name" FAIL; return 0
  fi
  out="$scratch/$name.out"
  "./$script" </dev/null 2>&1 | tee "$out"; rc=${PIPESTATUS[0]}
  last=$(awk 'NF { line = $0 } END { sub(/\r$/, "", line); sub(/[ \t]+$/, "", line); print line }' "$out")
  if [ "$rc" -ne 0 ]; then echo "$script exited $rc"; record "$name" FAIL; return 0; fi
  case $last in
    "SKIPPED ("?*")") record "$name" "$last" ;;
    SKIPPED*) echo "$script: last line \"$last\" is not SKIPPED (<reason>)"; record "$name" FAIL ;;
    *) record "$name" PASS ;;
  esac
  return 0
}
# The negative tests of the gate scripts: every scripts/tests/<gate>/*.sh, each its own step
# ("negative: <gate>/<script>"), except lib.sh, the helpers they source. A script that is not
# executable FAILs (it would otherwise drop out unnoticed), and so does finding none at all.
# The gate scripts guard what CI relies on, e.g. check-deps.sh's ADR 0021 guard, which deny.toml's
# RUSTSEC-2023-0071 ignore depends on, so their own tests gate too.
run_negative_tests() {
  local t name found=0
  for t in scripts/tests/*/*.sh; do
    [ -e "$t" ] || continue # bash 3.2 has no nullglob by default: an unmatched glob stays literal
    case ${t##*/} in lib.sh) continue ;; esac
    found=1; name="negative: ${t#scripts/tests/}"
    if [ -x "$t" ]; then run "$name" "$t"
    else echo "$t is not executable"; record "$name" FAIL; fi
  done
  if [ "$found" -eq 0 ]; then echo "no negative tests found (scripts/tests/*/*.sh)"; record negative-tests FAIL; fi
}

# Conformance results files (ADR 0034 §2) left by an earlier run must never count in the parity
# check below: each run starts with an empty target/conformance/, which this run's suites refill.
results_dir=target/conformance
rm -rf "$results_dir" || { echo "could not clear $results_dir"; exit 2; }

for p in "${platforms[@]}"; do
  case $p in
    rust)
      # No cargo config file in the repository, and none set by a script or workflow; it could
      # change sources, rustflags or the rustc wrapper for every cargo command (needs only git).
      run no-cargo-config scripts/check-no-cargo-config.sh
      if have cargo; then run rust bash -c 'cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace'
      else record rust "SKIPPED (cargo missing)"; fi
      # The workspace run above uses default features; this one also covers polyjose's
      # off-by-default features, the test-vector source (ADR 0005) and JWE `deflate` (ADR 0017),
      # as CI does.
      if have cargo; then run rust-all-features bash -c 'cargo clippy -p polyjose --all-targets --all-features -- -D warnings && cargo test -p polyjose --all-features'
      else record rust-all-features "SKIPPED (cargo missing)"; fi
      # The core and the WASM binding build for the browser target, as in CI.
      if have cargo; then run wasm32-build cargo build --target wasm32-unknown-unknown -p polyjose -p polyjose-wasm
      else record wasm32-build "SKIPPED (cargo missing)"; fi
      # Again with JWE `zip: DEF`, polyjose's own DEFLATE codec (ADR 0017), which is off by default.
      if have cargo; then run wasm32-build-deflate cargo build --target wasm32-unknown-unknown -p polyjose -p polyjose-wasm --features polyjose/deflate
      else record wasm32-build-deflate "SKIPPED (cargo missing)"; fi
      # polyjose builds on its MSRV, the workspace rust-version (1.89 since 0003 Gate 1, ADR 0024
      # as amended). CI always runs this; locally it needs that toolchain installed, and is never
      # auto-installed here.
      msrv="$(sed -n 's/^rust-version = "\([0-9]*\.[0-9]*\)"$/\1/p' Cargo.toml).0"
      toolchains="$(rustup toolchain list 2>/dev/null || true)"
      if ! have cargo || ! have rustup; then record msrv "SKIPPED (cargo or rustup missing; CI runs it)"
      elif [ "$msrv" = .0 ]; then echo "msrv: no rust-version = \"X.Y\" line in Cargo.toml"; record msrv FAIL
      elif ! grep -q "^${msrv//./\\.}-" <<<"$toolchains"; then record msrv "SKIPPED (Rust $msrv not installed: rustup toolchain install $msrv --profile minimal; CI runs it)"
      else run msrv cargo "+$msrv" check -p polyjose --all-features; fi
      # Same deny invocation as CI: full graph, dev-dependencies and every feature included.
      if have cargo && have cargo-deny; then run deny cargo deny --all-features check
      else record deny "SKIPPED (cargo-deny missing; CI runs it)"; fi
      # Nothing that builds a binding can enable polyjose's deterministic test RNG (ADR 0005).
      if have cargo; then run test-vectors-off scripts/check-test-vectors-off.sh
      else record test-vectors-off "SKIPPED (cargo missing)"; fi
      # The core's runtime tree matches deps-allowlist.txt and CREDITS.md (ADR 0016, ADR 0020).
      if have cargo; then run deps scripts/check-deps.sh
      else record deps "SKIPPED (cargo missing)"; fi
      # The same ADR 0021 rule on compiled output (ADR 0049 §1), after the builds above and the
      # text scan in deps: polyjose's and each binding's own object code holds no RSA private-key,
      # signing or decryption symbol. Needs ar and nm (best: rustup component add llvm-tools).
      if have cargo; then run rsa-symbols scripts/check-rsa-symbols.sh
      else record rsa-symbols "SKIPPED (cargo missing)"; fi
      # The gate scripts' own negative tests (scripts/tests/*/*.sh), e.g. that check-deps.sh
      # still rejects RSA private-key use and the guarded groups' second paths.
      if have cargo; then run_negative_tests
      else record negative-tests "SKIPPED (cargo missing)"; fi ;;
    wasm)
      if dispatch wasm; then :
      elif ! have wasm-pack; then record wasm "SKIPPED (wasm-pack missing)"
      elif ! has_wasm_suite; then record wasm "SKIPPED (no wasm test suite yet: no wasm-bindgen-test dev-dependency in bindings/wasm/Cargo.toml)"
      else run wasm bash -c 'cd bindings/wasm && wasm-pack test --node && wasm-pack test --headless --chrome'; fi ;;
    node)
      # The independent RSA-OAEP-256 oracle (feature 0003 T11, ADR 0021): Node's built-in crypto
      # alone (no npm packages) checks every RSA-OAEP-256 conformance vector against its test-only
      # private key, which no Rust code reads. It needs only node, not the binding's toolchain.
      if have node; then run rsa-oaep-oracle node conformance/tools/rsa-oaep-oracle.mjs
      else record rsa-oaep-oracle "SKIPPED (node missing)"; fi
      # `npm pkg get` prints {} for a missing key; an unreadable package.json is not skipped, so it FAILs.
      if dispatch node; then :
      elif ! have npm || ! have cargo; then record node "SKIPPED (npm or cargo missing)"
      elif [ ! -f bindings/node/package-lock.json ]; then record node "SKIPPED (no node test suite yet: bindings/node/package-lock.json missing)"
      elif [ "$(cd bindings/node && npm pkg get scripts.test 2>/dev/null)" = "{}" ]; then record node "SKIPPED (no node test suite yet: no test script in bindings/node/package.json)"
      else run node bash -c 'cd bindings/node && npm ci && npm run build && npm test'; fi ;;
    android)
      if dispatch android; then :
      elif have cargo-ndk && [ -x platforms/android/gradlew ]; then run android bash -c 'cd platforms/android && ./gradlew test'
      else record android "SKIPPED (cargo-ndk or Gradle project missing)"; fi ;;
    apple)
      if dispatch apple; then :
      elif have swift && [ -f Package.swift ]; then run apple bash -c 'swift test'
      else record apple "SKIPPED (swift or Package.swift missing)"; fi ;;
    *) echo "unknown platform: $p"; exit 2 ;;
  esac
done

# Conformance parity (ADR 0034 §5), after every platform suite: scripts/conformance-parity.sh
# (feature 0013 T02) compares each runner's results file in target/conformance/ with the reference
# rust-core.json, which the rust platform writes, and prints `SKIPPED (no results: <runner>)` for
# each runner that wrote none; those lines go into the summary under parity. Without the script or
# the reference, parity is SKIPPED (pipeline rule 9: never counted as passing).
parity=scripts/conformance-parity.sh
if [ ! -e "$parity" ] && [ ! -L "$parity" ]; then record parity "SKIPPED ($parity missing)"
elif [ ! -f "$parity" ] || [ ! -x "$parity" ]; then
  echo "$parity exists but is not an executable file (chmod +x $parity)"; record parity FAIL
elif [ ! -f "$results_dir/rust-core.json" ]; then
  record parity "SKIPPED (no reference results: $results_dir/rust-core.json; the rust platform writes it)"
else
  echo "==> parity"
  "$parity" "$results_dir" </dev/null 2>&1 | tee "$scratch/parity.out"
  if [ "${PIPESTATUS[0]}" -eq 0 ]; then record parity PASS; else record parity FAIL; fi
  skipped_runners=$(sed -n 's/^[[:space:]]*\(SKIPPED (no results: .*)\)[[:space:]]*$/    \1/p' "$scratch/parity.out")
  [ -z "$skipped_runners" ] || summary="$summary
$skipped_runners"
fi

printf "\nSummary:%b\n" "$summary"
exit $status
