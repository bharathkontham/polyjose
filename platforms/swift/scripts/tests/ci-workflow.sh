#!/usr/bin/env bash
# Local verification of .github/workflows/binding-apple.yml, the Swift (iOS) workflow (feature 0009
# T05). The workflow is never dispatched without the owner and PR CI is off (ADR 0044, pipeline
# rule 8), so this script is what checks it. Run by platforms/swift/test.sh, or directly.
#
# Usage:
#   platforms/swift/scripts/tests/ci-workflow.sh               check the workflow, then the
#                                                              self-test below
#   platforms/swift/scripts/tests/ci-workflow.sh --check <f>   check another file as if it were the
#                                                              workflow (scripts resolve against
#                                                              this checkout); no self-test
#
# The checks (each prints `ok   - <check>` or `FAIL - <check>: <why>`):
#   name         the top-level `name:` says "Swift (iOS)" (ADR 0046 §1).
#   triggers     `on:` has exactly workflow_dispatch and workflow_call: no pull_request, push,
#                schedule or other trigger (ADR 0044; owner, 2026-11-07).
#   mode input   both triggers declare the same single input, `mode` (type string, not required,
#                default ci), the shape ADR 0037 §1 gives feature 0012; the first step rejects any
#                value other than ci or release.
#   permissions  one `permissions:` block, top-level, exactly `contents: read`.
#   forbidden    none of: secrets, GITHUB_TOKEN, github.token, an OIDC token, `gh` release/api
#                commands, a release upload action, a registry publish, git push, a download of
#                another run's artifacts (ADR 0060: the parity reference is made in this job),
#                event context. Comment lines are not searched.
#   pins         every `uses:` is `<owner>/<repo>@<40 hex> # vX.Y.Z`; an action uses one pin, and
#                the same pin as ci.yml when ci.yml uses that action (ADR 0037 §1).
#   checkout     every actions/checkout step sets `persist-credentials: false`.
#   artifacts    the uploads are exactly apple-xcframework (dist/apple/*), conformance-swift-macos
#                and conformance-swift-ios-sim (target/conformance/swift-*.json), each once, with
#                `if-no-files-found: error` (ADR 0037 §1).
#   scripts      every script path the file names exists (and is executable when it starts with
#                `#!`; a sourced library need not be), and the steps call
#                test.sh, build-xcframework.sh, package.sh, check-no-cargo-config.sh and
#                conformance-parity.sh.
#   one job      a single job on a macOS runner with a timeout, so the rust-core reference, the
#                Swift results and the parity check share one checkout (ADR 0060).
#   order        test.sh, then the rust-core reference (`cargo test --locked -p polyjose --test
#                conformance`), then parity, none of them conditional. The test.sh step first
#                empties target/conformance/, so that parity sees only this job's results, and
#                requires test.sh's PASS line.
#   modes        release mode installs the pinned nightly (platforms/swift/nightly-toolchain) with
#                rust-src, builds with build-xcframework.sh --release and runs package.sh without
#                --allow-dev; ci mode runs package.sh too (it may pass --allow-dev); --allow-dev
#                appears only in steps conditional on ci mode; rust-cache
#                runs in ci mode only (ADR 0032 §1, feature 0009 T05).
#   expressions  no `${{ ... }}` inside a `run:` script: inputs reach scripts through `env:` only
#                (feature 0007 review-security.md I6).
#   xcode        the job sets DEVELOPER_DIR to /Applications/Xcode_<v>.app and XCODE_VERSION to
#                the same <v>, and a step compares `xcodebuild -version` with it.
#   ios-sim      the iOS Simulator is required in release mode (owner, 2026-11-07): a step after
#                test.sh, conditional on release mode, fails on either skip line of
#                test-simulators.sh (`SKIPPED-RUNNER (swift-ios-sim: ...` and `SKIPPED (no iOS
#                simulator runtime)`) and on a missing swift-ios-sim.json; the step that accepts
#                the waiver does so only when "$MODE" is ci.
#   continue     `continue-on-error` only on the step with `id: ios-runtime` (the best-effort
#                download of the iOS simulator runtime).
#   actionlint   `actionlint` accepts the file (it runs shellcheck on the scripts when shellcheck
#                is installed). A missing actionlint fails the check.
#
# Self-test: once the workflow passes, each of a list of mutations of it (one line replaced or
# lines inserted, in a scratch copy) must fail the check named for it, so that every check is
# shown to reject what it is there to reject: a pull_request trigger, a write permission, a secret,
# an unpinned action, --allow-dev in release mode, an expression in a run script, and so on.
#
# Exit status: 0 every check passed; 1 a check failed; 2 a usage error.
# Bash 3.2 compatible (macOS /bin/bash). Needs awk, grep, sed and actionlint.
set -uo pipefail
export LC_ALL=C

me=ci-workflow.sh
tests_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$tests_dir/../../../.." && pwd)"
workflow="$root/.github/workflows/binding-apple.yml"
ci_yml="$root/.github/workflows/ci.yml"

usage() { sed -n '6,11s/^# \{0,1\}//p' "$0"; }

self_test=1
case "${1:-}" in
  "") ;;
  --check) [ $# -eq 2 ] || { usage >&2; exit 2; }; workflow=$2; self_test=0 ;;
  -h | --help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-ci-workflow.XXXXXX") || { echo "$me: mktemp failed" >&2; exit 2; }
trap 'rm -rf "$work"' EXIT

failed=0
ok() { echo "ok   - $1"; }
bad() { failed=1; echo "FAIL - $1: $2"; }

if [ ! -f "$workflow" ]; then
  bad "workflow" "no such file: $workflow"
  echo "$me: FAIL"
  exit 1
fi

# --- Parsing helpers ------------------------------------------------------------------------
# The workflow is read line by line, relying on its layout: two-space indentation, the steps of
# the one job under `    steps:` as `      - ` items. A file laid out otherwise fails the checks
# that look for these structures, never passes them silently.

# Lines that are not comments (a line whose first non-blank character is `#`).
code="$work/code"
grep -v '^[[:space:]]*#' "$workflow" >"$code" || true

# block <exact header line> <indent>: the non-blank, non-comment lines after the header line up
# to the next line indented by <indent> spaces or less.
block() {
  awk -v hdr="$1" -v ind="$2" '
    found {
      if ($0 ~ /^[ ]*$/ || $0 ~ /^[ ]*#/) next
      match($0, /^ */)
      if (RLENGTH <= ind) exit
      print
      next
    }
    $0 == hdr { found = 1 }
  ' "$workflow"
}

# keys <indent>: the mapping keys at exactly <indent> spaces among the lines on stdin.
keys() {
  awk -v ind="$1" '{ match($0, /^ */); if (RLENGTH == ind) { k = substr($0, ind + 1); sub(/:.*/, "", k); print k } }'
}

# The steps, one file each ($work/steps/NN), with the item's `- ` turned into indentation so that
# every key of a step sits at 8 spaces.
mkdir -p "$work/steps"
awk -v out="$work/steps" '
  $0 == "    steps:" { in_steps = 1; next }
  in_steps {
    if ($0 ~ /^[ ]*$/) { if (f != "") print > f; next }
    if ($0 ~ /^[ ]*#/) next
    match($0, /^ */)
    if (RLENGTH == 6 && substr($0, 7, 2) == "- ") {
      if (f != "") close(f)
      n++
      f = sprintf("%s/%02d", out, n)
      line = $0
      sub(/^      - /, "        ", line)
      print line > f
    } else if (RLENGTH >= 8 && f != "") {
      print > f
    } else {
      in_steps = 0
    }
  }
' "$workflow"
steps=$(find "$work/steps" -type f | sort)

# step_key <step file> <key>: the value of the step's top-level key (empty when absent).
step_key() {
  local line prefix="        $2: "
  while IFS= read -r line; do
    case $line in "$prefix"*) printf '%s\n' "${line#"$prefix"}"; return ;; esac
  done <"$1"
}
# step_with <step file> <key>: the value of a key under the step's `with:`.
step_with() {
  awk -v k="$2" '
    $0 == "        with:" { w = 1; next }
    w && /^           / { next }
    w && /^          [A-Za-z]/ { if (index($0, "          " k ": ") == 1) { print substr($0, length(k) + 13); exit } next }
    w { exit }
  ' "$1"
}
# The step's `run:` script (inline or block), extracted once into <step file>.run.
for s in $steps; do
  awk '
    $0 == "        run: |" { m = 1; next }
    !m && index($0, "        run: ") == 1 { print substr($0, 14); exit }
    m { if ($0 ~ /^          / || $0 ~ /^[ ]*$/) print; else exit }
  ' "$s" >"$s.run"
done
# run_has <step file> <text>: the step's run script contains the text.
run_has() { grep -qF -- "$2" "$1.run"; }
# step_index <grep -F pattern in the run script>: the number of the first step whose run script
# contains the pattern (0 when none).
step_index() {
  local s i=0
  for s in $steps; do
    i=$((i + 1))
    if run_has "$s" "$1"; then echo "$i"; return; fi
  done
  echo 0
}
# step_file <index>
step_file() { printf '%s/%02d' "$work/steps" "$1"; }

# --- name -----------------------------------------------------------------------------------
name_line=$(sed -n 's/^name: //p' "$code" | head -n 1)
case $name_line in
  *"Swift (iOS)"*) ok "name: $name_line" ;;
  *) bad "name" "the top-level name must say \"Swift (iOS)\" (ADR 0046 §1), got '${name_line}'" ;;
esac

# --- triggers -------------------------------------------------------------------------------
if ! grep -qx 'on:' "$code"; then
  bad "triggers" "no block-style top-level 'on:'"
else
  triggers=$(block "on:" 0 | keys 2 | sort | tr '\n' ' ')
  if [ "$triggers" = "workflow_call workflow_dispatch " ]; then
    ok "triggers: workflow_dispatch and workflow_call only"
  else
    bad "triggers" "expected exactly workflow_dispatch and workflow_call, got: ${triggers}"
  fi
fi

# --- mode input -----------------------------------------------------------------------------
block "  workflow_dispatch:" 2 >"$work/dispatch"
block "  workflow_call:" 2 >"$work/call"
expected_mode="    inputs:
      mode:
        type: string
        required: false
        default: ci"
mode_ok=1
for t in dispatch call; do
  shape=$(grep -v '^        description: ' "$work/$t")
  if [ "$shape" != "$expected_mode" ]; then
    mode_ok=0
    bad "mode input" "workflow_$t must declare only 'mode' (type: string, required: false, default: ci, and a description)"
  fi
  if [ "$(grep -c '^        description: ' "$work/$t")" != 1 ]; then
    mode_ok=0
    bad "mode input" "workflow_$t's mode input needs one description line"
  fi
done
if [ "$mode_ok" = 1 ] && ! cmp -s "$work/dispatch" "$work/call"; then
  mode_ok=0
  bad "mode input" "workflow_dispatch and workflow_call must declare the mode input identically"
fi
first_step=$(step_file 1)
if [ -f "$first_step" ] && [ "$(step_key "$first_step" name)" = "mode is ci or release" ] &&
  run_has "$first_step" 'ci | release)'; then
  [ "$mode_ok" = 1 ] && ok "mode input: one string input, default ci, declared identically; the first step validates it"
else
  bad "mode input" "the first step must be 'mode is ci or release', accepting only ci and release"
fi

# --- permissions ----------------------------------------------------------------------------
perm_count=$(grep -c 'permissions:' "$code" || true)
perm_block=$(block "permissions:" 0)
if [ "$perm_count" = 1 ] && [ "$perm_block" = "  contents: read" ]; then
  ok "permissions: top-level contents: read only"
else
  bad "permissions" "expected one top-level 'permissions:' block that is exactly 'contents: read' (found $perm_count permissions keys)"
fi

# --- forbidden strings ----------------------------------------------------------------------
forbidden_found=0
for s in 'secrets.' 'secrets:' 'GITHUB_TOKEN' 'github.token' 'id-token' 'ACTIONS_ID_TOKEN' \
  'ACTIONS_RUNTIME_TOKEN' 'gh release' 'gh api' 'gh workflow' 'gh pr ' 'upload-release-asset' \
  'action-gh-release' 'create-release' 'cargo publish' 'npm publish' 'pod trunk' 'git push' \
  'download-artifact' 'pull_request_target' 'write-all' ': write' 'github.event' '--upload-file'; do
  if grep -qF -- "$s" "$code"; then
    forbidden_found=1
    bad "forbidden" "'$s' on line $(grep -nF -- "$s" "$code" | head -n 1 | cut -d: -f1) of the non-comment lines"
  fi
done
[ "$forbidden_found" = 0 ] && ok "forbidden: no secrets, tokens, OIDC, gh, release upload, registry, push or artifact download"

# --- pins -----------------------------------------------------------------------------------
pin_re='^ *(- )?uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$'
uses_lines=$(grep -E '^ *(- )?uses: ' "$code" || true)
pins_ok=1
if [ -z "$uses_lines" ]; then
  pins_ok=0
  bad "pins" "no uses: lines"
fi
bad_pins=$(printf '%s\n' "$uses_lines" | grep -Ev "$pin_re" || true)
if [ -n "$uses_lines" ] && [ -n "$bad_pins" ]; then
  pins_ok=0
  bad "pins" "not pinned as <action>@<40 hex> # vX.Y.Z: $(printf '%s' "$bad_pins" | head -n 1 | sed 's/^ *//')"
fi
printf '%s\n' "$uses_lines" | grep -E "$pin_re" | sed -E 's/^ *(- )?uses: //' | sort -u >"$work/pins"
sed 's/@.*//' "$work/pins" | sort -u >"$work/actions"
while IFS= read -r action; do
  n=$(grep -c "^$action@" "$work/pins")
  if [ "$n" != 1 ]; then
    pins_ok=0
    bad "pins" "$action is pinned $n different ways"
    continue
  fi
  ours=$(grep "^$action@" "$work/pins")
  theirs=$(grep -E "^ *(- )?uses: $action@" "$ci_yml" 2>/dev/null | head -n 1 | sed -E 's/^ *(- )?uses: //' || true)
  if [ -n "$theirs" ] && [ "$ours" != "$theirs" ]; then
    pins_ok=0
    bad "pins" "$action differs from ci.yml: '$ours' vs '$theirs' (bump both together)"
  fi
done <"$work/actions"
[ "$pins_ok" = 1 ] && ok "pins: $(wc -l <"$work/pins" | tr -d ' ') actions, each on a full SHA with its tag, as in ci.yml"

# --- checkout -------------------------------------------------------------------------------
checkouts=0
checkout_ok=1
for s in $steps; do
  case $(step_key "$s" uses) in
    actions/checkout@*)
      checkouts=$((checkouts + 1))
      [ "$(step_with "$s" persist-credentials)" = false ] || checkout_ok=0
      ;;
  esac
done
if [ "$checkouts" -ge 1 ] && [ "$checkout_ok" = 1 ]; then
  ok "checkout: persist-credentials: false"
else
  bad "checkout" "every actions/checkout step must set persist-credentials: false ($checkouts checkouts)"
fi

# --- artifacts ------------------------------------------------------------------------------
: >"$work/artifacts"
art_ok=1
for s in $steps; do
  case $(step_key "$s" uses) in
    actions/upload-artifact@*)
      a=$(step_with "$s" name)
      p=$(step_with "$s" path)
      echo "$a" >>"$work/artifacts"
      [ "$(step_with "$s" if-no-files-found)" = error ] ||
        { art_ok=0; bad "artifacts" "$a: if-no-files-found must be error"; }
      case "$a=$p" in
        "apple-xcframework=dist/apple/*" | \
          "conformance-swift-macos=target/conformance/swift-macos.json" | \
          "conformance-swift-ios-sim=target/conformance/swift-ios-sim.json") ;;
        *) art_ok=0; bad "artifacts" "unexpected upload '$a' of '$p'" ;;
      esac
      ;;
  esac
done
art_set=$(sort "$work/artifacts" | tr '\n' ' ')
if [ "$art_set" != "apple-xcframework conformance-swift-ios-sim conformance-swift-macos " ]; then
  art_ok=0
  bad "artifacts" "expected apple-xcframework, conformance-swift-macos and conformance-swift-ios-sim once each, got: $art_set"
fi
[ "$art_ok" = 1 ] && ok "artifacts: apple-xcframework, conformance-swift-macos, conformance-swift-ios-sim"

# --- scripts --------------------------------------------------------------------------------
scripts_ok=1
for p in $(grep -oE '(platforms|scripts)/[A-Za-z0-9_./-]+\.sh' "$code" | sort -u) platforms/swift/nightly-toolchain; do
  if [ ! -f "$root/$p" ]; then
    scripts_ok=0
    bad "scripts" "$p does not exist"
  elif [ "$(head -c 2 "$root/$p")" = '#!' ] && [ ! -x "$root/$p" ]; then
    scripts_ok=0
    bad "scripts" "$p has a #! line but is not executable"
  fi
done
for p in scripts/check-no-cargo-config.sh platforms/swift/test.sh \
  platforms/swift/scripts/build-xcframework.sh platforms/swift/scripts/package.sh \
  scripts/conformance-parity.sh; do
  if [ "$(step_index "$p")" = 0 ]; then
    scripts_ok=0
    bad "scripts" "no step runs $p"
  fi
done
[ "$scripts_ok" = 1 ] && ok "scripts: every file named exists (executable when it has a #! line); the steps run the five required ones"

# --- one job --------------------------------------------------------------------------------
jobs=$(block "jobs:" 0 | keys 2 | tr '\n' ' ' | sed 's/ $//')
job_block=$(block "jobs:" 0)
if [ "$(echo "$jobs" | wc -w | tr -d ' ')" != 1 ]; then
  bad "one job" "expected exactly one job, got: $jobs"
elif ! printf '%s\n' "$job_block" | grep -qE '^    runs-on: macos-'; then
  bad "one job" "the job must run on a macOS runner"
elif ! printf '%s\n' "$job_block" | grep -qE '^    timeout-minutes: [0-9]+$'; then
  bad "one job" "the job needs a timeout-minutes"
else
  ok "one job: $jobs on macOS, with a timeout"
fi

# --- order ----------------------------------------------------------------------------------
i_test=$(step_index "platforms/swift/test.sh")
i_core=$(step_index "cargo test --locked -p polyjose --test conformance")
i_parity=$(step_index "scripts/conformance-parity.sh")
order_ok=1
if [ "$i_test" = 0 ] || [ "$i_core" = 0 ] || [ "$i_parity" = 0 ]; then
  order_ok=0
  bad "order" "missing step: test.sh ($i_test), rust-core reference ($i_core) or parity ($i_parity)"
elif [ "$i_test" -ge "$i_core" ] || [ "$i_core" -ge "$i_parity" ]; then
  order_ok=0
  bad "order" "expected test.sh, then the rust-core reference, then parity (steps $i_test, $i_core, $i_parity)"
else
  for i in "$i_test" "$i_core" "$i_parity"; do
    if [ -n "$(step_key "$(step_file "$i")" if)" ]; then
      order_ok=0
      bad "order" "step $i ($(step_key "$(step_file "$i")" name)) must not be conditional"
    fi
  done
  if ! run_has "$(step_file "$i_test")" 'rm -rf target/conformance'; then
    order_ok=0
    bad "order" "the test.sh step must empty target/conformance/ first (a restored cache could hold old results)"
  fi
  if ! run_has "$(step_file "$i_test")" 'platforms/swift/test.sh: PASS'; then
    order_ok=0
    bad "order" "the test.sh step must require test.sh's PASS line (it prints SKIPPED and exits 0 without its tools)"
  fi
fi
[ "$order_ok" = 1 ] && ok "order: test.sh (on an empty target/conformance/, PASS line required), rust-core reference, parity, unconditional"

# --- modes ----------------------------------------------------------------------------------
modes_ok=1
release_nightly=0
release_build=0
release_package=0
ci_package=0
for s in $steps; do
  cond=$(step_key "$s" if)
  if run_has "$s" '--allow-dev' && [ "$cond" != "inputs.mode == 'ci'" ]; then
    modes_ok=0
    bad "modes" "--allow-dev in step '$(step_key "$s" name)', which is not limited to ci mode"
  fi
  case $(step_key "$s" uses) in
    Swatinem/rust-cache@*)
      [ "$cond" = "inputs.mode == 'ci'" ] ||
        { modes_ok=0; bad "modes" "rust-cache must run in ci mode only (release builds restore no cache)"; } ;;
  esac
  if [ "$cond" = "inputs.mode == 'ci'" ] && run_has "$s" 'platforms/swift/scripts/package.sh'; then
    ci_package=1
  fi
  [ "$cond" = "inputs.mode == 'release'" ] || continue
  if run_has "$s" 'rustup toolchain install' &&
    run_has "$s" 'platforms/swift/nightly-toolchain' &&
    run_has "$s" '--component rust-src'; then
    release_nightly=1
  fi
  run_has "$s" 'platforms/swift/scripts/build-xcframework.sh --release' && release_build=1
  if run_has "$s" 'platforms/swift/scripts/package.sh' &&
    ! run_has "$s" '--allow-dev'; then
    release_package=1
  fi
done
[ "$release_nightly" = 1 ] ||
  { modes_ok=0; bad "modes" "release mode must install the toolchain of platforms/swift/nightly-toolchain with --component rust-src"; }
[ "$release_build" = 1 ] ||
  { modes_ok=0; bad "modes" "release mode must run platforms/swift/scripts/build-xcframework.sh --release"; }
[ "$release_package" = 1 ] ||
  { modes_ok=0; bad "modes" "release mode must run platforms/swift/scripts/package.sh without --allow-dev"; }
[ "$ci_package" = 1 ] ||
  { modes_ok=0; bad "modes" "ci mode must run platforms/swift/scripts/package.sh too (the apple-xcframework artifact)"; }
[ "$modes_ok" = 1 ] && ok "modes: release installs the nightly with rust-src, builds with --release, packages without --allow-dev; ci mode packages too; --allow-dev and rust-cache in ci mode only"

# --- expressions ----------------------------------------------------------------------------
expr_ok=1
for s in $steps; do
  # shellcheck disable=SC2016 # the literal text of a GitHub expression, not a shell expansion
  if run_has "$s" '${{'; then
    expr_ok=0
    bad "expressions" "\${{ ... }} inside the run script of step '$(step_key "$s" name)'; pass it through env:"
  fi
done
[ "$expr_ok" = 1 ] && ok "expressions: no \${{ ... }} inside run scripts"

# --- xcode ----------------------------------------------------------------------------------
dev_dir_version=$(sed -n 's|^      DEVELOPER_DIR: /Applications/Xcode_\([0-9][0-9.]*\)\.app/Contents/Developer$|\1|p' "$code" | head -n 1)
xcode_version=$(sed -n 's/^      XCODE_VERSION: "\([0-9][0-9.]*\)"$/\1/p' "$code" | head -n 1)
if [ -z "$dev_dir_version" ] || [ "$dev_dir_version" != "$xcode_version" ]; then
  bad "xcode" "the job env needs DEVELOPER_DIR: /Applications/Xcode_<v>.app/Contents/Developer and XCODE_VERSION: \"<v>\" with the same <v>"
elif [ "$(step_index 'xcodebuild -version')" = 0 ]; then
  bad "xcode" "no step checks xcodebuild -version against XCODE_VERSION"
else
  ok "xcode: Xcode $xcode_version, selected with DEVELOPER_DIR and checked"
fi

# --- ios-sim --------------------------------------------------------------------------------
ios_ok=1
i_release_sim=0
i=0
for s in $steps; do
  i=$((i + 1))
  [ "$(step_key "$s" if)" = "inputs.mode == 'release'" ] || continue
  if run_has "$s" "grep -qF 'SKIPPED-RUNNER (swift-ios-sim:'" &&
    run_has "$s" "grep -qxF 'SKIPPED (no iOS simulator runtime)'" &&
    run_has "$s" '[ ! -f target/conformance/swift-ios-sim.json ]' && run_has "$s" 'exit 1'; then
    i_release_sim=$i
  fi
done
if [ "$i_release_sim" = 0 ]; then
  ios_ok=0
  bad "ios-sim" "release mode needs a step that fails on either skip line of test-simulators.sh and on a missing swift-ios-sim.json"
elif [ "$i_test" != 0 ] && [ "$i_release_sim" -le "$i_test" ]; then
  ios_ok=0
  bad "ios-sim" "the release-mode iOS Simulator check must come after the test.sh step"
fi
for s in $steps; do
  # shellcheck disable=SC2016 # literal workflow text
  if run_has "$s" 'ios_sim=skipped' && ! run_has "$s" '[ "$MODE" = ci ] && grep -qxF'; then
    ios_ok=0
    bad "ios-sim" "step '$(step_key "$s" name)' accepts the swift-ios-sim waiver without requiring ci mode"
  fi
done
[ "$ios_ok" = 1 ] && ok "ios-sim: required in release mode (either skip line or a missing file fails); the waiver only in ci mode"

# --- continue-on-error ----------------------------------------------------------------------
coe_ok=1
for s in $steps; do
  if [ -n "$(step_key "$s" continue-on-error)" ] && [ "$(step_key "$s" id)" != ios-runtime ]; then
    coe_ok=0
    bad "continue" "continue-on-error in step '$(step_key "$s" name)'; only the ios-runtime step may have it"
  fi
done
if grep -qE '^    continue-on-error:' "$code"; then
  coe_ok=0
  bad "continue" "the job must not set continue-on-error"
fi
[ "$coe_ok" = 1 ] && ok "continue: continue-on-error only on the iOS simulator runtime download"

# --- actionlint -----------------------------------------------------------------------------
if ! command -v actionlint >/dev/null 2>&1; then
  bad "actionlint" "actionlint is not on PATH (brew install actionlint; the workflow fetches it)"
elif actionlint -no-color "$workflow" >"$work/actionlint.log" 2>&1; then
  ok "actionlint: $(actionlint -version 2>/dev/null | head -n 1)"
else
  bad "actionlint" "it reports:"
  sed 's/^/    | /' "$work/actionlint.log"
fi

if [ "$failed" != 0 ]; then
  echo "$me: FAIL (${workflow#"$root"/})"
  exit 1
fi
if [ "$self_test" = 0 ]; then
  echo "$me: PASS (${workflow#"$root"/})"
  exit 0
fi

# --- Self-test ------------------------------------------------------------------------------
# mutate <check> <anchor> <old> <new> <what>: copies the workflow and replaces the first line
# equal to <old> (after the line equal to <anchor>, when one is given; otherwise <old> must occur
# exactly once) with <new> (`\n` separates inserted lines). Each copy is then checked with --check
# (below), which must fail with `FAIL - <check>:`.
mutations=0
mutations_failed=0
mutate() {
  local check=$1 anchor=$2 old=$3 new=$4 what=$5 copy
  mutations=$((mutations + 1))
  copy=$(printf '%s/mutation-%02d.yml' "$work" "$mutations")
  if [ -n "$anchor" ]; then
    [ "$(grep -cxF -- "$anchor" "$workflow")" = 1 ] ||
      { mutations_failed=1; echo "FAIL - self-test: $what: the anchor line is not unique: $anchor"; return; }
  else
    [ "$(grep -cxF -- "$old" "$workflow")" = 1 ] ||
      { mutations_failed=1; echo "FAIL - self-test: $what: the line to replace is not unique: $old"; return; }
  fi
  if ! awk -v anchor="$anchor" -v old="$old" -v new="$new" '
      BEGIN { armed = (anchor == "") }
      !done && armed && $0 == old { print new; done = 1; next }
      !armed && $0 == anchor { armed = 1 }
      { print }
      END { exit done ? 0 : 3 }
    ' "$workflow" >"$copy" || cmp -s "$workflow" "$copy"; then
    mutations_failed=1
    echo "FAIL - self-test: $what: the mutation did not apply"
    rm -f "$copy"
    return
  fi
  printf '%s\n%s\n' "$check" "$what" >"$copy.meta"
}

checkout_pin='      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'
cache_pin='      - uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3'
upload_pin='      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2'
test_step='      - name: platforms/swift/test.sh (macOS host and the iOS Simulator)'
# shellcheck disable=SC2016 # literal workflow text
mode_env='      MODE: ${{ inputs.mode }}'
runs_on='    runs-on: macos-latest'
parity_run='        run: scripts/conformance-parity.sh'
core_run='        run: cargo test --locked -p polyjose --test conformance'
release_package='        run: platforms/swift/scripts/package.sh'

mutate name "" "name: Swift (iOS)" "name: binding-apple" "a name without Swift (iOS)"
mutate triggers "" "  workflow_dispatch:" "  pull_request:\n  workflow_dispatch:" "a pull_request trigger"
mutate triggers "" "  workflow_dispatch:" "  push:\n    branches: [main]\n  workflow_dispatch:" "a push trigger"
mutate triggers "" "  workflow_dispatch:" "  schedule:\n    - cron: \"0 3 * * 1\"\n  workflow_dispatch:" "a schedule trigger"
mutate triggers "" "  workflow_call:" "  repository_dispatch:" "workflow_call replaced"
mutate "mode input" "  workflow_call:" "        default: ci" "        default: release" "mode defaulting to release under workflow_call"
mutate "mode input" "  workflow_dispatch:" "        type: string" "        type: choice\n        options: [ci, release]" "mode as a choice under workflow_dispatch"
mutate "mode input" "  workflow_call:" "        default: ci" "        default: ci\n      extra:\n        type: string" "a second input"
mutate "mode input" "" "      - name: mode is ci or release" "      - name: mode" "no mode validation step"
mutate permissions "" "  contents: read" "  contents: write" "contents: write"
mutate permissions "" "  contents: read" "  contents: read\n  id-token: write" "an OIDC token permission"
mutate permissions "" "$runs_on" "$runs_on\n    permissions:\n      contents: read" "a job-level permissions block"
mutate forbidden "" "$mode_env" "$mode_env\n      TOKEN: \${{ secrets.RELEASE_TOKEN }}" "a secret"
mutate forbidden "" "$mode_env" "$mode_env\n      GH_TOKEN: \${{ github.token }}" "github.token"
mutate forbidden "" "$mode_env" "$mode_env\n      GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}" "GITHUB_TOKEN"
mutate forbidden "" "$mode_env" "      MODE: \${{ github.event.inputs.mode }}" "event context"
mutate forbidden "" "$release_package" "$release_package && gh release upload v0.1.0 dist/apple/PolyjoseFFI.xcframework.zip" "a gh release upload"
mutate forbidden "" "        run: git diff --exit-code --stat HEAD" "        run: git diff --exit-code --stat HEAD && git push origin HEAD" "a git push"
mutate forbidden "" "      - name: rust-core reference" "      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: rust-core\n          path: target/conformance\n\n      - name: rust-core reference" "a reference downloaded from another run"
mutate checkout "" "          persist-credentials: false" "          persist-credentials: true" "persist-credentials: true"
mutate pins "" "$checkout_pin" "      - uses: actions/checkout@v7" "an action pinned to a tag"
mutate pins "" "$checkout_pin" "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" "a pin without its tag comment"
mutate pins "" "$cache_pin" "      - uses: Swatinem/rust-cache@0123456789abcdef0123456789abcdef01234567 # v2.9.3" "a pin that differs from ci.yml"
mutate pins "      - name: every results file is present" "$upload_pin" "      - uses: actions/upload-artifact@0123456789abcdef0123456789abcdef01234567 # v7.0.2" "one action pinned two ways"
mutate artifacts "" "          name: apple-xcframework" "          name: xcframework" "a renamed artifact"
mutate artifacts "          name: conformance-swift-macos" "          if-no-files-found: error" "          if-no-files-found: warn" "if-no-files-found: warn"
mutate artifacts "          name: apple-xcframework" "          if-no-files-found: error" "          if-no-files-found: error\n\n$upload_pin\n        with:\n          name: conformance-rust-core\n          path: target/conformance/rust-core.json\n          if-no-files-found: error" "an extra artifact"
mutate scripts "" "$parity_run" "        run: scripts/conformance-parity-all.sh" "a script that does not exist"
mutate modes "" "        run: platforms/swift/scripts/package.sh --allow-dev" "        run: echo packaged" "no ci-mode package.sh step"
mutate "one job" "          name: apple-xcframework" "          if-no-files-found: error" "          if-no-files-found: error\n\n  other:\n    runs-on: macos-latest\n    timeout-minutes: 5\n    steps:\n      - run: echo other" "a second job"
mutate "one job" "" "$runs_on" "    runs-on: ubuntu-latest" "a Linux runner"
mutate order "" "$core_run" "        run: cargo test --locked -p polyjose" "no rust-core reference"
mutate order "" "$core_run" "        if: inputs.mode == 'release'\n$core_run" "a conditional rust-core reference"
mutate order "" "      - name: conformance parity" "      - name: conformance parity\n        if: inputs.mode == 'release'" "a conditional parity check"
# shellcheck disable=SC2016 # literal workflow text
mutate order "" '          if [ "$(tail -n 1 "$RUNNER_TEMP/swift-test.log")" != "platforms/swift/test.sh: PASS" ]; then' "          if false; then" "test.sh's PASS line not required"
mutate order "" "          rm -rf target/conformance" "          mkdir -p target/conformance" "results files left from a restored cache"
mutate modes "" "$release_package" "$release_package --allow-dev" "--allow-dev in release mode"
mutate modes "      - name: package.sh (ci mode, a development build allowed)" "        if: inputs.mode == 'ci'" "        if: always()" "the --allow-dev step in every mode"
# shellcheck disable=SC2016 # literal workflow text
mutate modes "" '          rustup toolchain install "$nightly" --profile minimal --component rust-src' '          rustup toolchain install "$nightly" --profile minimal' "the nightly without rust-src"
mutate modes "" "        run: platforms/swift/scripts/build-xcframework.sh --release" "        run: platforms/swift/scripts/build-xcframework.sh" "the release build without --release"
mutate modes "$cache_pin" "        if: inputs.mode == 'ci'" "        if: always()" "rust-cache in release mode"
mutate expressions "" "$parity_run" "        run: echo \"\${{ inputs.mode }}\" && scripts/conformance-parity.sh" "an expression in a run script"
mutate xcode "" "      DEVELOPER_DIR: /Applications/Xcode_27.2.app/Contents/Developer" "      DEVELOPER_DIR: /Applications/Xcode.app/Contents/Developer" "an unversioned Xcode"
mutate xcode "" '      XCODE_VERSION: "27.2"' '      XCODE_VERSION: "27.1"' "an XCODE_VERSION that differs from DEVELOPER_DIR"
ios_step='      - name: the iOS Simulator ran (release mode)'
mutate ios-sim "$ios_step" "        if: inputs.mode == 'release'" "        if: false" "the release-mode iOS Simulator check dropped (never runs)"
mutate ios-sim "$ios_step" "        if: inputs.mode == 'release'" "        if: inputs.mode == 'ci'" "the iOS Simulator check applied to ci mode instead"
# shellcheck disable=SC2016 # literal workflow text
mutate ios-sim "" '            grep -qxF '"'"'SKIPPED (no iOS simulator runtime)'"'"' "$log"; then' "            false; then" "the release check matching only the SKIPPED-RUNNER line"
# shellcheck disable=SC2016 # literal workflow text
mutate ios-sim "" '          if grep -qF '"'"'SKIPPED-RUNNER (swift-ios-sim:'"'"' "$log" ||' "          if false ||" "the release check matching only the SKIPPED line"
mutate ios-sim "" "          if [ ! -f target/conformance/swift-ios-sim.json ]; then" "          if false; then" "the release check not requiring swift-ios-sim.json"
# shellcheck disable=SC2016 # literal workflow text
mutate ios-sim "" '          elif [ "$MODE" = ci ] && grep -qxF '"'"'SKIPPED-RUNNER (swift-ios-sim: host:no-ios-runtime)'"'"' "$RUNNER_TEMP/swift-test.log"; then' '          elif grep -qxF '"'"'SKIPPED-RUNNER (swift-ios-sim: host:no-ios-runtime)'"'"' "$RUNNER_TEMP/swift-test.log"; then' "the waiver accepted in every mode"
mutate continue "" "$test_step" "$test_step\n        continue-on-error: true" "continue-on-error on the test.sh step"
mutate continue "" "$runs_on" "$runs_on\n    continue-on-error: true" "a job-level continue-on-error"
mutate actionlint "" "$runs_on" "    runs_on: macos-latest" "a misspelled runs-on key"
mutate actionlint "" "    timeout-minutes: 180" "    timeout-minutes: three hours" "a timeout that is not a number"

# Check the copies, six at a time (each check is about a second of short-lived processes).
batch=0
for copy in "$work"/mutation-*.yml; do
  [ -f "$copy" ] || continue
  ( rc=0; "$0" --check "$copy" >"$copy.log" 2>&1 || rc=$?; echo "$rc" >"$copy.rc" ) &
  batch=$((batch + 1))
  if [ "$batch" = 6 ]; then wait; batch=0; fi
done
wait
for copy in "$work"/mutation-*.yml; do
  [ -f "$copy" ] || continue
  check=$(sed -n 1p "$copy.meta")
  what=$(sed -n 2p "$copy.meta")
  rc=$(cat "$copy.rc")
  if [ "$rc" = 1 ] && grep -qF -- "FAIL - $check:" "$copy.log"; then
    echo "ok   - self-test: $what is rejected ($check)"
  else
    mutations_failed=1
    echo "FAIL - self-test: $what was not rejected by the $check check (exit $rc)"
    sed 's/^/    | /' "$copy.log"
  fi
done

if [ "$mutations_failed" = 0 ]; then
  echo "$me: PASS (${workflow#"$root"/}; self-test: $mutations mutations rejected)"
  exit 0
fi
echo "$me: FAIL (self-test)"
exit 1
