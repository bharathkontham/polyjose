#!/usr/bin/env bash
# Run polyjose's test suites on every platform (or the ones named as arguments).
# A platform whose toolchain or test suite is missing is reported as SKIPPED with the reason,
# never silently passed; a suite that exists always runs and can FAIL.
# wasm, node, android and apple run their binding's own script when it exists (bindings/wasm/test.sh,
# bindings/node/test.sh, platforms/android/test.sh, platforms/swift/test.sh; see dispatch below).
# After the suites, scripts/conformance-parity.sh compares their conformance results (ADR 0034 §5),
# and each platform that passed must have written the results files of its runners (results_runners).
# A platform script may waive one of its host-optional runners (marked ? in results_runners) with a
# line of its output, anywhere, of exactly this form:
#   SKIPPED-RUNNER (<runner>: host:<token>)      <token> is [a-z0-9-]+, e.g. host:no-chrome
# The runner is then reported SKIPPED under parity, never as passing. Any other line starting with
# SKIPPED-RUNNER, or one naming a required runner or a runner not on the platform's line, FAILs.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
platforms=("$@"); [ ${#platforms[@]} -eq 0 ] && platforms=(rust wasm node android apple)
summary=""; status=0
# passed and ran: the steps that reported PASS, and PASS or FAIL (not SKIPPED), as |<name>|...; a
# platform's status is that of its step of the same name (rust: the cargo fmt/clippy/test step).
passed="|"; ran="|"
record() {
  summary="$summary
  $1: $2"
  [ "$2" = FAIL ] && status=1
  [ "$2" = PASS ] && passed="$passed$1|"
  case $2 in PASS | FAIL) ran="$ran$1|" ;; esac
  return 0
}
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
# Fail closed (feature 0013 F10, pipeline rule 9): macOS /bin/bash 3.2 runs an EXIT trap with
# $? = 0 after a syntax error when errexit is on (bash 5 keeps 2), so a guard broken by an edit
# could exit 0. `completed` is set only by the last line; the trap keeps a non-zero status and
# turns 0 into 2 when the script stopped before it. Every scripts/*.sh with an EXIT trap does the
# same (scripts/tests/syntax/guards.sh).
completed=""
trap 'rc=$?; rm -rf "$scratch"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "test-all.sh: stopped before its last line (a syntax error?): failing closed" >&2; rc=2; }; exit "$rc"' EXIT
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
# The conformance runners each platform's suite must write (ADR 0034 §2; feature 0013 F05, review
# S3; ADR 0046 drops the tvOS simulator run), the one place that lists them: one line
# `<platform>: <runner>...` per platform, in data only, so a binding never patches the logic. A plain
# name is required; a trailing `?` marks a runner that is optional on a host (no browser, emulator
# or simulator there). For each platform that reports PASS, the parity step at the end FAILs unless
# target/conformance/ holds <runner>.json or <runner>-<suffix>.json (a CI matrix run) for every
# runner on its line, except an optional runner that the platform's script waived with
# `SKIPPED-RUNNER (<runner>: host:<token>)` (see the header). For the reference, rust-core, only
# rust-core.json counts (a rust-core-<features>.json is a Rust build with features, which
# scripts/conformance-parity.sh ignores). A SKIPPED or FAILed platform is never required to have a
# file. Every platform has a line naming at least one runner; a missing or empty line FAILs parity.
# wasm-pkg-workerd is required (feature 0013 F10): workerd comes from the pinned miniflare
# dev-dependency, so it runs wherever npm does (0006 lead); only the browser runners are optional.
results_runners='
rust: rust-core rust-surface
node: node
wasm: wasm-node wasm-chrome? wasm-pkg-node wasm-pkg-chrome? wasm-pkg-workerd
android: jvm android-emulator?
apple: swift-macos swift-ios-sim?
'
# runners_of <platform>: prints the runners on the platform's line; returns 1 if it has no line.
runners_of() {
  local line
  while IFS= read -r line; do
    case $line in "$1:"*) echo "${line#*:}"; return 0 ;; esac
  done <<<"$results_runners"
  return 1
}

# dispatch <platform>: runs the platform's script from the repository root, with no stdin, and
# returns 0; returns 1 if there is none, so the caller runs the inline commands below (and their
# SKIPPED reasons, 0001 T14). The script's exit status decides PASS or FAIL. A script that cannot
# run its suite (no simulator, no emulator) exits 0 with `SKIPPED (<reason>)` as its last non-blank
# line, which is reported as SKIPPED and never as passing (pipeline rule 9); a last line that starts
# with SKIPPED in any other form FAILs, and so does a script that exists but is not an executable
# file (falling back to the inline commands would hide that the platform's own suite never ran).
# A SKIPPED-RUNNER line (header) is not a platform SKIPPED line; the parity step reads it from the
# saved output ($scratch/<platform>.out).
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
    SKIPPED-RUNNER*) record "$name" PASS ;;
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

# The binding API name check (feature 0013 T13, ADR 0030 §2, §8): one step per mode file in
# scripts/check-binding-api.d/ ("api-names: <mode>"), each comparing a binding's exported names with
# bindings/api-inventory.txt. The exit status decides PASS or FAIL; `SKIPPED (<mode>: <reason>)` as
# the last line with exit 0 (a mode whose inputs are missing, e.g. js without node) is reported as
# SKIPPED, never as passing (pipeline rule 9); a last line starting with SKIPPED in any other form
# FAILs, and so does finding no mode at all.
run_api_names() {
  local f mode out rc last found=0
  for f in scripts/check-binding-api.d/*.sh; do
    [ -e "$f" ] || continue # bash 3.2 has no nullglob by default: an unmatched glob stays literal
    found=1; mode=${f##*/}; mode=${mode%.sh}
    echo "==> api-names: $mode"
    out="$scratch/api-names-$mode.out"
    scripts/check-binding-api.sh "$mode" </dev/null 2>&1 | tee "$out"; rc=${PIPESTATUS[0]}
    last=$(awk 'NF { line = $0 } END { sub(/\r$/, "", line); sub(/[ \t]+$/, "", line); print line }' "$out")
    if [ "$rc" -ne 0 ]; then record "api-names: $mode" FAIL; continue; fi
    case $last in
      "SKIPPED ($mode: "?*")") record "api-names: $mode" "$last" ;;
      SKIPPED*) echo "check-binding-api.sh $mode: last line \"$last\" is not SKIPPED ($mode: <reason>)"; record "api-names: $mode" FAIL ;;
      *) record "api-names: $mode" PASS ;;
    esac
  done
  if [ "$found" -eq 0 ]; then echo "no binding API modes found (scripts/check-binding-api.d/*.sh)"; record api-names FAIL; fi
}

# The UniFFI-generated Kotlin and Swift names (feature 0013 F05, review S4; T12; ADR 0030 §2, §3,
# §8; ADR 0032 §3): bindings/ffi/tests/generated-names.sh builds polyjose-ffi and the bindgen,
# generates both languages, requires every bindings/api-inventory.txt entry in each (required
# fields such as allowedAlgs with no default) and type-checks the Swift under Swift 6. It stands in
# for the kotlin and swift modes of check-binding-api.sh, so features 0008 and 0009 remove this
# step when they add them. One step, "api-names: ffi-generated", run under this script's bash. The
# exit status decides PASS or FAIL (exit 2, a setup error such as a failed bindgen build, FAILs
# too); `SKIPPED (<reason>)` on a line of its output with exit 0 (no xcrun, so no Swift typecheck)
# is reported as SKIPPED, never as passing (pipeline rule 9); any other line starting with SKIPPED
# FAILs, and so does a missing script. Needs cargo (the caller skips it without).
run_ffi_generated_names() {
  local name="api-names: ffi-generated" script=bindings/ffi/tests/generated-names.sh out rc skipped
  echo "==> $name"
  if [ ! -f "$script" ]; then echo "$script not found"; record "$name" FAIL; return 0; fi
  out="$scratch/ffi-generated.out"
  "${BASH:-bash}" "$script" </dev/null 2>&1 | tee "$out"; rc=${PIPESTATUS[0]}
  if [ "$rc" -ne 0 ]; then echo "$script exited $rc"; record "$name" FAIL; return 0; fi
  if awk '{ sub(/\r$/, ""); sub(/[ \t]+$/, "") } /^SKIPPED/ && !/^SKIPPED \(.+\)$/ { bad = 1 } END { exit !bad }' "$out"; then
    echo "$script: a line starting with SKIPPED is not SKIPPED (<reason>)"; record "$name" FAIL; return 0
  fi
  skipped=$(awk '{ sub(/\r$/, ""); sub(/[ \t]+$/, "") } /^SKIPPED \(.+\)$/ { print; exit }' "$out")
  if [ -n "$skipped" ]; then record "$name" "$skipped"; else record "$name" PASS; fi
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
      # Every binding's exported names against the API inventory (needs no cargo), before the
      # cargo steps, so a renamed or missing name fails before any conformance run.
      run_api_names
      # The same for the UniFFI-generated Kotlin and Swift (needs cargo to build them), still before
      # the cargo steps below.
      if have cargo; then run_ffi_generated_names
      else record "api-names: ffi-generated" "SKIPPED (cargo missing)"; fi
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

# Conformance parity (ADR 0034 §5), after every platform suite. First, each platform that passed
# must have written the results files of its runners (results_runners above), and when the rust
# platform ran (PASS or FAIL) the reference rust-core.json must exist; each one missing is a
# `FAIL (...)` line under parity in the summary and FAILs parity (review S3), with or without the
# parity script; each optional runner waived by its platform's SKIPPED-RUNNER line is a
# `SKIPPED (<runner>: host:<token>)` line there instead. Then scripts/conformance-parity.sh (feature 0013 T02) compares each runner's results
# file in target/conformance/ with the reference rust-core.json and prints
# `SKIPPED (no results: <runner>)` for each runner that wrote none; those lines go into the summary
# under parity too, except for a runner already reported missing or waived above. Without the script or the
# reference, and with nothing missing, parity is SKIPPED (pipeline rule 9: never counted as passing).
# has_results <runner>: target/conformance/ holds the runner's results file.
has_results() {
  local f
  [ -f "$results_dir/$1.json" ] && return 0
  [ "$1" = rust-core ] && return 1 # rust-core-<features>.json is never the reference
  for f in "$results_dir/$1"-*.json; do [ -f "$f" ] && return 0; done
  return 1
}
missing_results=""; missing_runners=" "
# missing <reason> [<runner>]: a FAIL line under parity, and the runner it names.
missing() {
  missing_results="$missing_results
    FAIL ($1)"
  [ -z "${2:-}" ] || missing_runners="$missing_runners$2 "
}
# declarations <output file>: its SKIPPED-RUNNER lines (trailing blanks and CR removed), each as
# `ok<TAB><runner><TAB>host:<token>` or, in any other form, `bad<TAB><line>`.
declarations() {
  awk '{ sub(/\r$/, ""); sub(/[ \t]+$/, "") }
    /^[ \t]*SKIPPED-RUNNER/ {
      if ($0 ~ /^SKIPPED-RUNNER \([a-z0-9][a-z0-9-]*: host:[a-z0-9-]+\)$/) {
        r = $0; sub(/^SKIPPED-RUNNER \(/, "", r); sub(/\)$/, "", r)
        reason = r; sub(/:.*/, "", r); sub(/^[^:]*: /, "", reason)
        print "ok\t" r "\t" reason
      } else { gsub(/\t/, " "); print "bad\t" $0 }
    }' "$1"
}
waived_results=""; tab=$(printf '\t')
# not_missing: copies the `SKIPPED (no results: <runner>)` lines on stdin, except a missing runner's.
# (A function: bash 3.2 cannot parse a case pattern inside $(...).)
not_missing() {
  local line r
  while IFS= read -r line; do
    r=${line#*no results: }; r=${r%)}
    case $missing_runners in *" $r "*) ;; *) printf '%s\n' "$line" ;; esac
  done
}
echo "==> parity"
checked="|"
for p in "${platforms[@]}"; do
  case $checked in *"|$p|"*) continue ;; esac
  checked="$checked$p|"
  if ! line_runners=$(runners_of "$p"); then
    echo "parity: no line for $p in the runner table (results_runners in scripts/test-all.sh)"
    missing "no line for $p in the runner table"; continue
  fi
  read -r -a runners <<<"$line_runners"
  if [ ${#runners[@]} -eq 0 ]; then
    echo "parity: the runner table's line for $p names no runner"
    missing "no runners for $p in the runner table"; continue
  fi
  case $passed in *"|$p|"*) ;; *) continue ;; esac
  # The platform script's SKIPPED-RUNNER lines: only an optional runner on its line can be waived.
  waived=" "
  if [ -f "$scratch/$p.out" ]; then
    declarations "$scratch/$p.out" >"$scratch/$p.declared"
    while IFS="$tab" read -r kind r reason; do
      if [ "$kind" = bad ]; then
        echo "parity: $p: bad SKIPPED-RUNNER line: $r${reason:+ $reason}"
        missing "bad SKIPPED-RUNNER line from $p: $r${reason:+ $reason}; the form is SKIPPED-RUNNER (<runner>: host:<token>)"
        continue
      fi
      kind=other
      for spec in "${runners[@]}"; do
        [ "$spec" = "$r?" ] && kind=optional
        [ "$spec" = "$r" ] && kind=required
      done
      case $kind in
        required)
          echo "parity: $p declared SKIPPED-RUNNER for $r, a required runner"
          missing "SKIPPED-RUNNER for $r, a required runner of $p" ;;
        other)
          echo "parity: $p declared SKIPPED-RUNNER for $r, which is not on its line of the runner table"
          missing "SKIPPED-RUNNER for $r, not a runner of $p" ;;
        *)
          case $waived in *" $r "*) continue ;; esac
          has_results "$r" && continue # it ran after all: its file is compared as usual
          waived="$waived$r "; missing_runners="$missing_runners$r "
          echo "parity: $p skipped runner $r ($reason)"
          waived_results="$waived_results
    SKIPPED ($r: $reason)" ;;
      esac
    done <"$scratch/$p.declared"
  fi
  for spec in "${runners[@]}"; do
    r=${spec%\?}
    has_results "$r" && continue
    case $waived in *" $r "*) continue ;; esac
    if [ "$r" = rust-core ]; then where="$results_dir/rust-core.json, the reference"
    else where="$results_dir/$r.json or $r-<suffix>.json"; fi
    echo "parity: the $p platform passed but wrote no results file for runner $r ($where)"
    missing "no results: $r; the $p platform passed" "$r"
  done
done
case $ran in *"|rust|"*)
  if [ ! -f "$results_dir/rust-core.json" ]; then
    case $missing_runners in *" rust-core "*) ;; *)
      echo "parity: the rust platform ran but wrote no $results_dir/rust-core.json, the reference"
      missing "no results: rust-core; the rust platform ran" rust-core ;;
    esac
  fi ;;
esac
parity=scripts/conformance-parity.sh; skipped_runners=""
if [ ! -e "$parity" ] && [ ! -L "$parity" ]; then parity_status="SKIPPED ($parity missing)"
elif [ ! -f "$parity" ] || [ ! -x "$parity" ]; then
  echo "$parity exists but is not an executable file (chmod +x $parity)"; parity_status=FAIL
elif [ ! -f "$results_dir/rust-core.json" ]; then
  parity_status="SKIPPED (no reference results: $results_dir/rust-core.json; the rust platform writes it)"
else
  "$parity" "$results_dir" </dev/null 2>&1 | tee "$scratch/parity.out"
  if [ "${PIPESTATUS[0]}" -eq 0 ]; then parity_status=PASS; else parity_status=FAIL; fi
  skipped_runners=$(sed -n 's/^[[:space:]]*\(SKIPPED (no results: .*)\)[[:space:]]*$/    \1/p' "$scratch/parity.out" |
    not_missing)
fi
[ -z "$missing_results" ] || parity_status=FAIL
record parity "$parity_status"
summary="$summary$missing_results$waived_results"
[ -z "$skipped_runners" ] || summary="$summary
$skipped_runners"

printf "\nSummary:%b\n" "$summary"
completed=1; exit "$status"
