#!/usr/bin/env bash
# Run polyjose's test suites on every platform (or the ones named as arguments).
# A platform whose toolchain is missing is reported as SKIPPED, never silently passed.
set -uo pipefail
cd "$(dirname "$0")/.."
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

for p in "${platforms[@]}"; do
  case $p in
    rust)
      if have cargo; then run rust bash -c 'cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace'
      else record rust "SKIPPED (cargo missing)"; fi
      # Same deny invocation as CI: full graph, dev-dependencies and every feature included.
      if have cargo && have cargo-deny; then run deny cargo deny --all-features check
      else record deny "SKIPPED (cargo-deny missing; CI runs it)"; fi
      # No binding may enable polyjose's test-vectors feature (ADR 0005).
      if have cargo; then run test-vectors-off scripts/check-test-vectors-off.sh
      else record test-vectors-off "SKIPPED (cargo missing)"; fi ;;
    wasm)
      if ! have wasm-pack; then record wasm "SKIPPED (wasm-pack missing)"
      elif ! has_wasm_suite; then record wasm "SKIPPED (no wasm test suite yet: no wasm-bindgen-test dev-dependency in bindings/wasm/Cargo.toml)"
      else run wasm bash -c 'cd bindings/wasm && wasm-pack test --node && wasm-pack test --headless --chrome'; fi ;;
    node)
      # `npm pkg get` prints {} for a missing key; an unreadable package.json is not skipped, so it FAILs.
      if ! have npm || ! have cargo; then record node "SKIPPED (npm or cargo missing)"
      elif [ ! -f bindings/node/package-lock.json ]; then record node "SKIPPED (no node test suite yet: bindings/node/package-lock.json missing)"
      elif [ "$(cd bindings/node && npm pkg get scripts.test 2>/dev/null)" = "{}" ]; then record node "SKIPPED (no node test suite yet: no test script in bindings/node/package.json)"
      else run node bash -c 'cd bindings/node && npm ci && npm run build && npm test'; fi ;;
    android)
      if have cargo-ndk && [ -x platforms/android/gradlew ]; then run android bash -c 'cd platforms/android && ./gradlew test'
      else record android "SKIPPED (cargo-ndk or Gradle project missing)"; fi ;;
    apple)
      if have swift && [ -f Package.swift ]; then run apple bash -c 'swift test'
      else record apple "SKIPPED (swift or Package.swift missing)"; fi ;;
    *) echo "unknown platform: $p"; exit 2 ;;
  esac
done

printf "\nSummary:%b\n" "$summary"
exit $status
