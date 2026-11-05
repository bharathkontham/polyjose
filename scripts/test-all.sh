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
run() { local name=$1; shift; echo "==> $name"; if "$@"; then record "$name" PASS; else record "$name" FAIL; fi; }

for p in "${platforms[@]}"; do
  case $p in
    rust)
      if have cargo; then run rust bash -c 'cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace'
      else record rust "SKIPPED (cargo missing)"; fi
      # Same deny invocation as CI: full graph, dev-dependencies and every feature included.
      if have cargo && have cargo-deny; then run deny cargo deny --all-features check
      else record deny "SKIPPED (cargo-deny missing; CI runs it)"; fi ;;
    wasm)
      if have wasm-pack; then run wasm bash -c 'cd bindings/wasm && wasm-pack test --node && wasm-pack test --headless --chrome'
      else record wasm "SKIPPED (wasm-pack missing)"; fi ;;
    node)
      if have npm && have cargo; then run node bash -c 'cd bindings/node && npm ci && npm run build && npm test'
      else record node "SKIPPED (npm or cargo missing)"; fi ;;
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
