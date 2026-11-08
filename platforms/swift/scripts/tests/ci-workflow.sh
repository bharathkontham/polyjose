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
#   forbidden    on normalised non-comment text (continuations joined, whitespace collapsed,
#                lower-cased, secrets['x'] and github['x'] rewritten as secrets.x and github.x;
#                B02): no reference to secrets (also toJSON(secrets), secrets: inherit), nothing
#                with "token" (github.token, GITHUB_TOKEN, id-token), no event context, no gh
#                command at all, no "publish" (npm, cargo, gradle, swift package-registry), no pod
#                trunk, twine or gem upload, no release action, git push or download of another
#                run's artifacts (ADR 0060), no write permission, no `|| true`, `|| :`, `set +e`,
#                `continue-on-error` or `exit 0`, and no curl or wget upload flag (-T, -F, -X in
#                any flag cluster, --upload-file, --form, --data*, --json, -d @, ...).
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
#   expressions  `${{` only in the value of a `name:` or `if:` key or inside an `env:` or `with:`
#                mapping; never on any line of a `run:` value, whatever its YAML form (B03), so
#                inputs reach scripts through `env:` only (feature 0007 review-security.md I6). The
#                expressions are only `inputs.mode` and `github.ref == 'refs/heads/main'`, with no
#                backslash on their line; `if:` conditions are only the mode tests and the
#                ios-sim results test.
#   xcode        the job sets DEVELOPER_DIR to /Applications/Xcode_<v>.app and XCODE_VERSION to
#                the same <v>, and a step compares `xcodebuild -version` with it.
#   ios-sim      the iOS Simulator is required in release mode (owner, 2026-11-07): a step after
#                test.sh, conditional on release mode, fails on either skip line of
#                test-simulators.sh (`SKIPPED-RUNNER (swift-ios-sim: ...` and `SKIPPED (no iOS
#                simulator runtime)`) and on a missing swift-ios-sim.json; the step that accepts
#                the waiver does so only when "$MODE" is ci.
#   quoting      outside run values, no backslash in a double-quoted scalar and no quoted scalar
#                continued onto the next line (B05): YAML escapes and escaped line breaks could
#                spell an expression or a context name no other check sees. A quote opens a
#                scalar after any white space, a TAB too, and after `[`, `{`, `,` or `:` (B06).
#   one-line     outside run values every value sits on its key's line (B07): each line is a
#                `key:` entry or a `- ` item, none continues the value above it (a plain scalar
#                folds a more-indented line in), no value is a block scalar, and no line is
#                indented with a TAB. The checks that read a value from its line see all of it.
#   continue     no `continue-on-error` anywhere.
#   steps        every run step equals, exactly, one of the canonical steps held in this script,
#                each once and in order (compared without its name line, trailing whitespace,
#                trailing blank lines and YAML comment lines; B04; a # line inside a
#                block-scalar run body is script text and is compared). Changing a run step of the
#                workflow means changing its canonical text here, on purpose.
#   actions      only actions/checkout, Swatinem/rust-cache, actions/setup-node and
#                actions/upload-artifact, each with exactly its keys, inputs (an upload may add
#                retention-days or compression-level) and condition (rust-cache: ci mode, saving
#                only on main; the ios-sim upload: only when its results file is present), and in
#                its place relative to the canonical steps.
#   shell        the top-level default shell is `bash --noprofile --norc -euo pipefail {0}`, and no
#                job or step sets another.
#   env          the workflow env is exactly CARGO_TERM_COLOR and CARGO_INCREMENTAL, the job env
#                exactly MODE, XCODE_VERSION and DEVELOPER_DIR (no BASH_ENV or other variable).
#   structure    top-level keys name, on, permissions, env, defaults, jobs; job keys name, runs-on,
#                timeout-minutes, env, steps (no concurrency, container, services, strategy...).
#   actionlint   `actionlint` accepts the file (it runs shellcheck on the scripts when shellcheck
#                is installed). A missing actionlint fails the check.
#
# Self-test: once the workflow passes, each of a list of mutations of it (one line replaced or
# lines inserted, in a scratch copy) must fail the check named for it, so that every check is
# shown to reject what it is there to reject: a pull_request trigger, a write permission, a secret
# in any spelling, an unpinned action, --allow-dev in release mode, an expression in a run script
# of any form, a required step turned into a no-op, a value continued onto the next line, and so
# on (including every case of bugs B02 to B07). A list of benign edits (retention-days, a renamed
# step, comments, a blank line, a longer timeout) must still pass, so that the checks are not
# simply brittle. About a minute.
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
# Fail closed (0013 F10): /bin/bash 3.2 runs an EXIT trap with $? = 0 after a syntax error, so an
# exit 0 before the last line, which sets the sentinel, becomes status 2 (see scripts/test-all.sh).
# A PASS, of --check or of the self-test, therefore ends on that last line.
completed=""
# shellcheck disable=SC2154 # rc is assigned by the trap itself (rc=$?)
trap 'rc=$?; rm -rf "$work"; [ -n "${completed:-}" ] || [ "$rc" -ne 0 ] || { echo "ci-workflow.sh: stopped before its last statement (a syntax error?); failing closed" >&2; rc=2; }; exit "$rc"' EXIT

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
  awk -v ind="$1" '/^[ ]*$/ { next } { match($0, /^ */); if (RLENGTH == ind) { k = substr($0, ind + 1); sub(/:.*/, "", k); print k } }'
}

# The steps, one file each ($work/steps/NN), with the item's `- ` turned into indentation so that
# every key of a step sits at 8 spaces.
mkdir -p "$work/steps"
awk -v out="$work/steps" '
  $0 == "    steps:" { in_steps = 1; next }
  in_steps {
    if ($0 ~ /^[ ]*$/) { if (f != "") print > f; next }
    match($0, /^ */)
    # A # line inside a block-scalar run body is script text (it can end a backslash-continued
    # command), so it is kept and compared; any other comment line is dropped.
    if ($0 ~ /^[ ]*#/) { if (blk && RLENGTH >= 10 && f != "") print > f; next }
    if (RLENGTH == 6 && substr($0, 7, 2) == "- ") {
      if (f != "") close(f)
      n++
      f = sprintf("%s/%02d", out, n)
      line = $0
      sub(/^      - /, "        ", line)
      print line > f
      blk = (line ~ /^        run: [|>]/)
    } else if (RLENGTH >= 8 && f != "") {
      print > f
      if (RLENGTH == 8) blk = ($0 ~ /^        run: [|>]/)
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
# Matched on normalised text, so that no spelling slips through (B02): the non-comment lines with
# line continuations joined, tabs and runs of spaces collapsed to one space, then lower-cased (GitHub
# context names are case-insensitive), with the bracket forms secrets['x'], secrets["x"] and
# github['x'] rewritten as secrets.x and github.x. The curl and wget upload flags are matched on the
# same text before lower-casing, since -F (form upload) and -f (fail), -T (upload) and -t differ only
# in case.
awk '{ if (sub(/\\$/, "")) { buf = buf $0 " "; next } print buf $0; buf = "" } END { if (buf != "") print buf }' "$code" |
  tr '\t' ' ' | sed -E 's/  +/ /g' >"$work/norm_case"
bracket_re="(secrets|github) ?\\[ ?['\"]([^'\"]*)['\"] ?\\]"
tr '[:upper:]' '[:lower:]' <"$work/norm_case" | sed -E "s/$bracket_re/\\1.\\2/g" >"$work/norm"
forbidden_found=0
# forbid <label> <extended regular expression> [<file>]
forbid() {
  local n
  n=$(grep -nE -- "$2" "${3:-$work/norm}" | head -n 1 | cut -d: -f1)
  if [ -n "$n" ]; then
    forbidden_found=1
    bad "forbidden" "$1 (normalised non-comment line $n: $(sed -n "${n}p" "${3:-$work/norm}" | sed 's/^ *//' | cut -c1-100))"
  fi
}
forbid "a reference to secrets" '(^|[^a-z0-9_])secrets([^a-z0-9_]|$)'
forbid "a token (github.token, GITHUB_TOKEN, id-token, any *token*)" 'token'
forbid "event context" 'github\.event'
forbid "a gh command (the workflow needs none)" '(^|[^a-z0-9_./-])gh( |$)'
forbid "a publish command or task" 'publish'
forbid "a registry upload" 'pod (trunk|repo push)|package-registry|twine upload|gem push'
forbid "a release action" 'upload-release-asset|action-gh-release|create-release'
forbid "git push" 'git push'
forbid "a download of another run's artifacts (ADR 0060)" 'download-artifact'
forbid "pull_request_target" 'pull_request_target'
forbid "a write permission" 'write-all|: write'
forbid "an error swallowed with || true or || :" '\|\| ?(true|:)( |;|\)|$)'
forbid "set +e or set +o" 'set \+([a-z]*e|o)'
forbid "continue-on-error" 'continue-on-error'
forbid "exit 0" 'exit 0( |;|\)|$)'
grep -iE '(^|[^a-z0-9_])(curl|wget)( |$)' "$work/norm_case" >"$work/fetch_lines" || true
forbid "a curl or wget upload flag" '(^| )-[A-Za-z]*[TFX]|--(upload-file|form|form-string|data|data-binary|data-raw|data-urlencode|json|request|post-file|post-data|body-file|body-data|method)( |=|$)|(^| )-d ?@' "$work/fetch_lines"
[ "$forbidden_found" = 0 ] && ok "forbidden: no secrets, token, event context, gh, publish, upload, push, artifact download, write permission or swallowed error (normalised text)"

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
# B03: `${{` is allowed only in the value of a `name:` or `if:` key or inside an `env:` or `with:`
# mapping. A `run:` value, whatever its form (`|`, `|-`, `|+`, `>`, `>-`, plain or quoted, inline
# or on later lines), is everything indented deeper than its `run:` key; no line of it may hold
# `${{`, comment lines included (GitHub substitutes expressions anywhere in the script). Then every
# expression must be one of the allowed ones, with no backslash on its line (a YAML escape such
# as s could spell a context name), and every `if:` condition one of the allowed ones.
awk '
  function indent(l) { match(l, /^ */); return RLENGTH }
  {
    line = $0
    if (line ~ /^[ ]*$/) next
    i = indent(line); rest = substr(line, i + 1); k = i
    if (substr(rest, 1, 2) == "- ") { k = i + 2; rest = substr(rest, 3) }
    if (region != "" && i <= rind) region = ""
    if (region == "run") { if (index(line, "${{")) print "RUN\t" FNR; next }
    if (rest ~ /^#/) next
    if (rest ~ /^["\047]?run["\047]?:/) {
      region = "run"; rind = k
      if (index(line, "${{")) print "RUN\t" FNR
      next
    }
    if (region == "map") { if (index(line, "${{")) print "EXPR\t" FNR "\t" line; next }
    if (rest ~ /^(env|with):[ ]*(#.*)?$/) { region = "map"; rind = k; next }
    key = rest; sub(/:.*/, "", key)
    if (key == "if") { v = rest; sub(/^if:[ ]*/, "", v); print "IF\t" FNR "\t" v }
    if (index(line, "${{")) {
      if (key == "name" || key == "if") print "EXPR\t" FNR "\t" line
      else print "KEY\t" FNR "\t" key
    }
  }
' "$workflow" >"$work/expr"
expr_ok=1
# shellcheck disable=SC2016 # the literal opening of a GitHub expression
open_expr='${{'
close_expr='}}'
while IFS="$(printf '\t')" read -r kind n rest; do
  case $kind in
    RUN) expr_ok=0; bad "expressions" "\${{ ... }} in a run script (line $n); pass it through env:" ;;
    KEY) expr_ok=0; bad "expressions" "\${{ ... }} in the value of '$rest' (line $n); only name:, if:, env: and with: values may hold one" ;;
    IF)
      case $rest in
        "inputs.mode == 'ci'" | "inputs.mode == 'release'" | "steps.results.outputs.ios_sim == 'present'") ;;
        *) expr_ok=0; bad "expressions" "if: condition not in the allow-list (line $n): $rest" ;;
      esac ;;
    EXPR)
      case $rest in
        *\\*) expr_ok=0; bad "expressions" "a backslash on a line with an expression (line $n)" ;;
      esac
      left=$rest
      while :; do
        case $left in *"$open_expr"*) ;; *) break ;; esac
        left=${left#*"$open_expr"}
        case $left in
          *"$close_expr"*) e=${left%%"$close_expr"*}; left=${left#*"$close_expr"} ;;
          *) expr_ok=0; bad "expressions" "an expression not closed on its line (line $n)"; break ;;
        esac
        e=$(printf '%s' "$e" | sed -E 's/^ +//; s/ +$//')
        case $e in
          "inputs.mode" | "github.ref == 'refs/heads/main'") ;;
          *) expr_ok=0; bad "expressions" "expression not in the allow-list (line $n): $e" ;;
        esac
      done ;;
  esac
done <"$work/expr"
[ "$expr_ok" = 1 ] && ok "expressions: only in name:, if:, env: and with: values, and only inputs.mode and the main-ref test; if: conditions from the allow-list"

# --- quoting (B05) --------------------------------------------------------------------------
# A YAML double-quoted scalar decodes escapes (\x24\x7b\x7b is `${{`, s is `s`) and an escaped
# line break joins two lines with nothing, so its text can spell an expression or a context name
# that no check here sees. Escapes are not decoded here (fragile); outside the run values (which
# "steps" compares exactly) a double-quoted scalar may not hold a backslash, and no quoted scalar
# may continue onto the next line. Free strings are plain or single-quoted on one line (a
# single-quoted scalar has no escapes, so a backslash in it is literal and allowed).
# B06: YAML separates a value from `key:`, `-` or `?` with any white space (YAML 1.2 §6.2
# s-separate-in-line: spaces or TABs), so a quote after a space or a TAB opens a scalar, as does
# one right after a flow indicator `[`, `{`, `,` or a `:` (a JSON-like flow `{"a":"..."}`, §7.4);
# a `#` after either kind of white space starts a comment (§6.6).
awk '
  function indent(l) { match(l, /^ */); return RLENGTH }
  {
    line = $0
    if (line ~ /^[ \t]*$/) next
    i = indent(line); rest = substr(line, i + 1); k = i
    if (substr(rest, 1, 2) == "- ") { k = i + 2; rest = substr(rest, 3) }
    if (inrun && i <= rind) inrun = 0
    if (inrun) next
    if (rest ~ /^[ \t]*#/) next
    if (rest ~ /^["\047]?run["\047]?:/) { inrun = 1; rind = k; next }
    q = ""; prev = " "
    for (c = i + 1; c <= length(line); c++) {
      ch = substr(line, c, 1)
      if (q == "\"") {
        if (ch == "\\") { print FNR "\ta backslash in a double-quoted scalar"; q = "x"; break }
        if (ch == "\"") q = ""
      } else if (q == "\047") {
        if (ch == "\047") { if (substr(line, c + 1, 1) == "\047") c++; else q = "" }
      } else if (prev ~ /[ \t\[{,:]/ && (ch == "\"" || ch == "\047")) {
        q = ch
      } else if (ch == "#" && prev ~ /[ \t]/) {
        break
      }
      prev = ch
    }
    if (q == "\"" || q == "\047") print FNR "\ta quoted scalar that continues onto the next line"
  }
' "$workflow" >"$work/quoting"
if [ -s "$work/quoting" ]; then
  while IFS="$(printf '\t')" read -r n why; do
    bad "quoting" "$why (line $n); write free strings plain or single-quoted, on one line"
  done <"$work/quoting"
else
  ok "quoting: no backslash in a double-quoted scalar and no quoted scalar over several lines (outside run values)"
fi

# --- one-line (B07) -------------------------------------------------------------------------
# The checks read a value from its key's line, but YAML lets a value go on over later lines: a
# plain scalar continues on every more-indented line that is not a comment, folded in with a space
# (YAML 1.2 §7.3.3 and §6.5: `name: apple-xcframework` and `  -dev` below it are the name
# `apple-xcframework -dev`; `if: inputs.mode == 'ci'` and `  && false` never run the step); a
# block scalar (`|` or `>`, §8.1) holds the lines below its key, even lines that look like
# comments; a flow collection may span lines (§7.4); and a value may start on the line after its
# key. So outside the run values ("steps" compares those exactly) every free value sits on its
# key's line: each non-blank line that is not a comment is a `key:` entry or a `- ` item, indented
# no deeper than the key (or the `-`) of the value above it; no value is a block scalar; and no line
# is indented with a TAB (§6.1 forbids it; spaces then a TAB would continue a value unseen).
awk '
  function indent(l) { match(l, /^ */); return RLENGTH }
  BEGIN { pend = -1 }
  {
    line = $0
    if (line ~ /^[ \t]*$/) next
    i = indent(line); rest = substr(line, i + 1)
    if (inrun) { if (i > rind) next; inrun = 0 }
    if (rest ~ /^[ \t]*#/) next
    if (pend >= 0 && i > pend) { print FNR "\ta continuation of the value on line " pline; next }
    pend = -1
    if (rest ~ /^\t/) { print FNR "\ta TAB in the indentation"; next }
    item = 0
    while (rest ~ /^-([ \t]|$)/) {
      item = 1; d = length(line) - length(rest)
      rest = substr(rest, 2); sub(/^[ \t]+/, "", rest)
    }
    k = length(line) - length(rest)
    if (rest == "") next
    if (match(rest, /^([A-Za-z0-9_][A-Za-z0-9_.\/-]*|"[^"]*"|\047[^\047]*\047):([ \t]|$)/)) {
      key = substr(rest, 1, RLENGTH); sub(/:[ \t]*$/, "", key); gsub(/["\047]/, "", key)
      v = substr(rest, RLENGTH + 1); sub(/^[ \t]+/, "", v)
      if (v ~ /^#/) v = ""
      if (key == "run") { inrun = 1; rind = k; next }
      if (v == "") next
      if (v ~ /^([!&][^ \t]*[ \t]+)*[|>]/) { print FNR "\ta block scalar (| or >)"; next }
      pend = k; pline = FNR
    } else if (item) {
      pend = d; pline = FNR
    } else {
      print FNR "\tneither a key: entry nor a - item (a value on a line of its own)"
    }
  }
' "$workflow" >"$work/oneline"
if [ -s "$work/oneline" ]; then
  while IFS="$(printf '\t')" read -r n why; do
    bad "one-line" "$why (line $n); outside run values every value sits on its key's line"
  done <"$work/oneline"
else
  ok "one-line: every value outside the run values sits on its key's line (no continuation, block scalar or TAB indentation)"
fi

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
if grep -q 'continue-on-error' "$code"; then
  bad "continue" "continue-on-error is not allowed anywhere (the job must fail when a step fails)"
else
  ok "continue: no continue-on-error"
fi

# --- steps (B04) ----------------------------------------------------------------------------
# Text greps cannot show that a command runs and that its failure fails the job, so every run
# step must be, exactly, one of the canonical steps below, each once and in this order. A step
# is compared without its name line (renaming is harmless), with trailing whitespace and trailing
# blank lines stripped, and without YAML comment lines (the step files drop them; a # line inside
# a block-scalar run body is script text and stays). Any edit to a run
# step of the workflow therefore needs the same edit here, on purpose, where a reviewer sees it.
# Action (uses:) steps are checked by "actions".
mkdir -p "$work/canon"
canon_n=0
# canon <label>: the next canonical step, read from stdin.
canon() {
  canon_n=$((canon_n + 1))
  cat >"$(printf '%s/canon/%02d' "$work" "$canon_n")"
  printf '%s\n' "$1" >"$(printf '%s/canon/%02d.label' "$work" "$canon_n")"
}
# The canonical steps, in order (copied from the reviewed workflow; keep the two in step).
canon 'mode is ci or release' <<'CANON'
        run: |
          case "$MODE" in
            ci | release) echo "mode: $MODE" ;;
            *) echo "::error::the mode input must be ci or release"; exit 1 ;;
          esac
CANON
canon 'Xcode 27.2' <<'CANON'
        run: |
          if [ ! -d "$DEVELOPER_DIR" ]; then
            echo "::error::Xcode $XCODE_VERSION is not at $DEVELOPER_DIR on this runner image; it has:"
            ls -d /Applications/Xcode*.app
            exit 1
          fi
          xcodebuild -version
          actual=$(xcodebuild -version | sed -n 's/^Xcode //p')
          if [ "$actual" != "$XCODE_VERSION" ]; then
            echo "::error::expected Xcode $XCODE_VERSION, xcodebuild reports $actual"
            exit 1
          fi
          swift --version
          sw_vers
          uname -m
CANON
canon 'no cargo config' <<'CANON'
        run: scripts/check-no-cargo-config.sh
CANON
canon 'Install toolchain (rust-toolchain.toml)' <<'CANON'
        run: |
          rustup toolchain install
          rustup show
          cargo --version
CANON
canon 'Install the pinned nightly (release mode)' <<'CANON'
        if: inputs.mode == 'release'
        run: |
          nightly=$(tr -d '[:space:]' < platforms/swift/nightly-toolchain)
          rustup toolchain install "$nightly" --profile minimal --component rust-src
          rustc "+$nightly" --version
CANON
canon 'actionlint 1.7.12' <<'CANON'
        env:
          ACTIONLINT_VERSION: 1.7.12
          ACTIONLINT_SHA256: aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f
        run: |
          [ "$(uname -m)" = arm64 ] || { echo "::error::the actionlint pin is for darwin arm64"; exit 1; }
          dir="$RUNNER_TEMP/actionlint"
          tarball="actionlint_${ACTIONLINT_VERSION}_darwin_arm64.tar.gz"
          mkdir -p "$dir"
          curl --proto '=https' --tlsv1.2 -fsSL -o "$dir/$tarball" \
            "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/$tarball"
          echo "$ACTIONLINT_SHA256  $dir/$tarball" | shasum -a 256 -c -
          tar -xzf "$dir/$tarball" -C "$dir" actionlint
          "$dir/actionlint" -version
          echo "$dir" >>"$GITHUB_PATH"
CANON
canon 'XCFramework (release mode, platforms/swift/scripts/build-xcframework.sh --release)' <<'CANON'
        if: inputs.mode == 'release'
        run: platforms/swift/scripts/build-xcframework.sh --release
CANON
canon 'iOS Simulator runtime' <<'CANON'
        id: ios-runtime
        timeout-minutes: 30
        run: |
          runtime=$(sed -n 's/^runtime_id=//p' platforms/swift/scripts/test-simulators.sh)
          if [ -z "$runtime" ]; then
            echo "::error::no runtime_id in test-simulators.sh"
            exit 1
          fi
          . platforms/swift/scripts/simulator-lib.sh
          xcrun simctl list runtimes -j >"$RUNNER_TEMP/runtimes.json"
          if sim_runtime_available "$RUNNER_TEMP/runtimes.json" "$runtime"; then
            echo "$runtime is installed"
          else
            version=${runtime##*.iOS-}
            version=${version//-/.}
            echo "$runtime is missing; downloading the iOS $version simulator runtime"
            if xcodebuild -downloadPlatform iOS -buildVersion "$version"; then
              xcrun simctl list runtimes
            else
              echo "::warning::the iOS $version simulator runtime could not be downloaded"
            fi
          fi
CANON
canon 'platforms/swift/test.sh (macOS host and the iOS Simulator)' <<'CANON'
        run: |
          rm -rf target/conformance
          platforms/swift/test.sh 2>&1 | tee "$RUNNER_TEMP/swift-test.log"
          if [ "$(tail -n 1 "$RUNNER_TEMP/swift-test.log")" != "platforms/swift/test.sh: PASS" ]; then
            echo "::error::platforms/swift/test.sh did not end with its PASS line"
            exit 1
          fi
CANON
canon 'the iOS Simulator ran (release mode)' <<'CANON'
        if: inputs.mode == 'release'
        run: |
          log="$RUNNER_TEMP/swift-test.log"
          if grep -qF 'SKIPPED-RUNNER (swift-ios-sim:' "$log" ||
            grep -qxF 'SKIPPED (no iOS simulator runtime)' "$log"; then
            echo "::error::release mode requires the iOS Simulator run; test-simulators.sh skipped it (no iOS 27.2 runtime on the runner)"
            exit 1
          fi
          if [ ! -f target/conformance/swift-ios-sim.json ]; then
            echo "::error::release mode requires target/conformance/swift-ios-sim.json"
            exit 1
          fi
          echo "the iOS Simulator ran: target/conformance/swift-ios-sim.json"
CANON
canon 'every results file is present' <<'CANON'
        id: results
        run: |
          if [ ! -f target/conformance/swift-macos.json ]; then
            echo "::error::missing target/conformance/swift-macos.json"
            exit 1
          fi
          echo "present: target/conformance/swift-macos.json"
          if [ -f target/conformance/swift-ios-sim.json ]; then
            echo "present: target/conformance/swift-ios-sim.json"
            echo "ios_sim=present" >>"$GITHUB_OUTPUT"
          elif [ "$MODE" = ci ] && grep -qxF 'SKIPPED-RUNNER (swift-ios-sim: host:no-ios-runtime)' "$RUNNER_TEMP/swift-test.log"; then
            echo "::warning::swift-ios-sim SKIPPED: the runner has no iOS 27.2 simulator runtime, so the iOS Simulator suite did not run"
            echo "swift-ios-sim: SKIPPED (no iOS 27.2 simulator runtime on the runner)" >>"$GITHUB_STEP_SUMMARY"
            echo "ios_sim=skipped" >>"$GITHUB_OUTPUT"
          else
            echo "::error::missing target/conformance/swift-ios-sim.json (and no ci-mode waiver from test-simulators.sh)"
            exit 1
          fi
CANON
canon 'rust-core reference' <<'CANON'
        run: cargo test --locked -p polyjose --test conformance
CANON
canon 'conformance parity' <<'CANON'
        run: scripts/conformance-parity.sh
CANON
canon 'package.sh (release mode)' <<'CANON'
        if: inputs.mode == 'release'
        run: platforms/swift/scripts/package.sh
CANON
canon 'package.sh (ci mode, a development build allowed)' <<'CANON'
        if: inputs.mode == 'ci'
        run: platforms/swift/scripts/package.sh --allow-dev
CANON
canon 'the checkout is unchanged' <<'CANON'
        run: git diff --exit-code --stat HEAD
CANON
canon 'dist/apple holds the three packaged files' <<'CANON'
        run: |
          for f in PolyjoseFFI.xcframework.zip PolyjoseFFI.xcframework.zip.sha256 binaryTarget.swift.txt; do
            [ -f "dist/apple/$f" ] || { echo "::error::missing dist/apple/$f"; exit 1; }
          done
          ls -l dist/apple
          cat dist/apple/PolyjoseFFI.xcframework.zip.sha256
CANON

# normalise_step <step file>: the step without its name line, trailing whitespace and trailing
# blank lines.
normalise_step() {
  sed -e '/^        name: /d' -e 's/[[:space:]]*$//' "$1" |
    awk '{ a[NR] = $0 } END { n = NR; while (n > 0 && a[n] == "") n--; for (i = 1; i <= n; i++) print a[i] }'
}
steps_ok=1
last_canon=0
i=0
canon_at=()
for s in $steps; do
  i=$((i + 1))
  if grep -q '^        run:' "$s"; then
    normalise_step "$s" >"$s.norm"
    # The expected next canonical step first (the usual case), then all of them.
    found=0
    j=$((last_canon + 1))
    if [ "$j" -le "$canon_n" ] && cmp -s "$s.norm" "$(printf '%s/canon/%02d' "$work" "$j")"; then
      found=$j
    else
      j=0
      while [ "$j" -lt "$canon_n" ]; do
        j=$((j + 1))
        if cmp -s "$s.norm" "$(printf '%s/canon/%02d' "$work" "$j")"; then found=$j; break; fi
      done
    fi
    if [ "$found" = 0 ]; then
      steps_ok=0
      bad "steps" "run step $i ('$(step_key "$s" name)') is not one of the canonical steps (edit the canonical text in ci-workflow.sh on purpose)"
    elif [ -n "${canon_at[$found]:-}" ]; then
      steps_ok=0
      bad "steps" "the canonical step '$(cat "$work/canon/$(printf '%02d' "$found").label")' appears twice"
    elif [ "$found" -le "$last_canon" ]; then
      steps_ok=0
      bad "steps" "run step $i ('$(step_key "$s" name)') is out of the canonical order"
      canon_at[found]=$i
    else
      canon_at[found]=$i
      last_canon=$found
    fi
  elif ! grep -q '^        uses: ' "$s"; then
    steps_ok=0
    bad "steps" "step $i has neither run: nor uses:"
  fi
done
j=0
while [ "$j" -lt "$canon_n" ]; do
  j=$((j + 1))
  if [ -z "${canon_at[$j]:-}" ]; then
    steps_ok=0
    bad "steps" "missing (or changed) canonical step: $(cat "$work/canon/$(printf '%02d' "$j").label")"
  fi
done
[ "$steps_ok" = 1 ] && ok "steps: the $canon_n run steps are exactly the canonical ones, in order"

# canon_step <label>: the workflow step index of the canonical step with that label (0 if absent).
canon_step() {
  local j=0
  while [ "$j" -lt "$canon_n" ]; do
    j=$((j + 1))
    if [ "$(cat "$work/canon/$(printf '%02d' "$j").label")" = "$1" ]; then echo "${canon_at[$j]:-0}"; return; fi
  done
  echo 0
}

# --- actions (B04) --------------------------------------------------------------------------
# Only the four actions the job needs, each with exactly its keys and inputs; rust-cache in ci mode
# only and saving only on main; positions relative to the canonical steps.
actions_ok=1
i=0
for s in $steps; do
  i=$((i + 1))
  u=$(step_key "$s" uses)
  [ -n "$u" ] || continue
  a=${u%%@*}
  cond=$(step_key "$s" if)
  stepkeys=$(keys 8 <"$s" | sort | tr '\n' ' ')
  withkeys=$(awk '$0 == "        with:" { w = 1; next } w && /^          [^ ]/ { k = substr($0, 11); sub(/:.*/, "", k); print k; next } w && /^        [^ ]/ { w = 0 }' "$s" | sort | tr '\n' ' ')
  want_cond=""
  case $a in
    actions/checkout)
      want_keys="uses with "; want_with="persist-credentials "
      [ "$i" -lt "$(canon_step "no cargo config")" ] ||
        { actions_ok=0; bad "actions" "actions/checkout must come before the cargo-config check"; } ;;
    Swatinem/rust-cache)
      want_keys="if uses with "; want_with="save-if "; want_cond="inputs.mode == 'ci'"
      # shellcheck disable=SC2016 # literal workflow text
      [ "$(step_with "$s" save-if)" = '${{ github.ref == '"'refs/heads/main'"' }}' ] ||
        { actions_ok=0; bad "actions" "rust-cache must save only on main (save-if: \${{ github.ref == 'refs/heads/main' }})"; }
      if [ "$i" -lt "$(canon_step "Install toolchain (rust-toolchain.toml)")" ] || [ "$i" -gt "$(canon_step "platforms/swift/test.sh (macOS host and the iOS Simulator)")" ]; then
        actions_ok=0; bad "actions" "rust-cache must come after the toolchain install and before test.sh"
      fi ;;
    actions/setup-node)
      want_keys="uses with "; want_with="node-version package-manager-cache "
      [ "$(step_with "$s" package-manager-cache)" = false ] ||
        { actions_ok=0; bad "actions" "setup-node must set package-manager-cache: false"; }
      [ "$i" -lt "$(canon_step "conformance parity")" ] ||
        { actions_ok=0; bad "actions" "setup-node must come before parity"; } ;;
    actions/upload-artifact)
      want_keys="uses with "; want_with="if-no-files-found name path "
      case $(step_with "$s" name) in
        conformance-swift-ios-sim)
          want_keys="if uses with "; want_cond="steps.results.outputs.ios_sim == 'present'"
          after="every results file is present" ;;
        conformance-swift-macos) after="every results file is present" ;;
        *) after="dist/apple holds the three packaged files" ;;
      esac
      [ "$i" -gt "$(canon_step "$after")" ] ||
        { actions_ok=0; bad "actions" "the $(step_with "$s" name) upload must come after the step '$after'"; } ;;
    *)
      actions_ok=0; bad "actions" "$a is not one of the allowed actions (checkout, rust-cache, setup-node, upload-artifact)"
      continue ;;
  esac
  # A step's keys, apart from its name, and its with: inputs; benign extra upload inputs allowed.
  stepkeys=$(printf '%s' "$stepkeys" | sed 's/name //')
  if [ "$stepkeys" != "$want_keys" ]; then
    actions_ok=0; bad "actions" "step $i ($a) has the keys '$stepkeys', expected '$want_keys'"
  fi
  if [ "$a" = actions/upload-artifact ]; then
    withkeys=$(printf '%s' "$withkeys" | sed -E 's/(compression-level|retention-days) //g')
  fi
  if [ "$withkeys" != "$want_with" ]; then
    actions_ok=0; bad "actions" "step $i ($a) has the inputs '$withkeys', expected '$want_with'"
  fi
  if [ "$cond" != "$want_cond" ]; then
    actions_ok=0; bad "actions" "step $i ($a) has the condition '$cond', expected '$want_cond'"
  fi
done
[ "$actions_ok" = 1 ] && ok "actions: only checkout, rust-cache (ci mode, saving on main), setup-node and upload-artifact, each with its own keys and place"

# --- shell (B04) ----------------------------------------------------------------------------
shell_block=$(block "defaults:" 0)
expected_shell="  run:
    shell: bash --noprofile --norc -euo pipefail {0}"
if [ "$shell_block" != "$expected_shell" ]; then
  bad "shell" "the top-level defaults must be exactly run.shell: bash --noprofile --norc -euo pipefail {0}"
elif [ "$(grep -c 'shell:' "$code")" != 1 ] || [ "$(grep -c 'defaults:' "$code")" != 1 ]; then
  bad "shell" "no job or step may set its own shell or defaults"
else
  ok "shell: every run script runs under bash -euo pipefail"
fi

# --- env (B04) ------------------------------------------------------------------------------
env_ok=1
workflow_env=$(block "env:" 0)
if [ "$workflow_env" != "  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: 0" ]; then
  env_ok=0; bad "env" "the workflow env must be exactly CARGO_TERM_COLOR: always and CARGO_INCREMENTAL: 0 (no BASH_ENV or other variable)"
fi
job_env=$(block "    env:" 4)
# shellcheck disable=SC2016 # literal workflow text
if [ "$job_env" != '      MODE: ${{ inputs.mode }}
      XCODE_VERSION: "27.2"
      DEVELOPER_DIR: /Applications/Xcode_27.2.app/Contents/Developer' ]; then
  env_ok=0; bad "env" "the job env must be exactly MODE, XCODE_VERSION and DEVELOPER_DIR"
fi
[ "$env_ok" = 1 ] && ok "env: the workflow and job env blocks are exactly the expected variables"

# --- structure (B04) ------------------------------------------------------------------------
top_keys=$(keys 0 <"$code" | sort | tr '\n' ' ')
job_keys=$(block "jobs:" 0 | keys 4 | sort | tr '\n' ' ')
if [ "$top_keys" != "defaults env jobs name on permissions " ]; then
  bad "structure" "top-level keys must be name, on, permissions, env, defaults and jobs, got: $top_keys"
elif [ "$job_keys" != "env name runs-on steps timeout-minutes " ]; then
  bad "structure" "the job's keys must be name, runs-on, timeout-minutes, env and steps, got: $job_keys"
else
  ok "structure: the expected top-level and job keys only"
fi

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
status=0
if [ "$self_test" = 0 ]; then
  echo "$me: PASS (${workflow#"$root"/})"
else
  # --- Self-test ------------------------------------------------------------------------------
  # mutate <check> <anchor> <old> <new> <what>: copies the workflow and replaces the first line
  # equal to <old> (after the line equal to <anchor>, when one is given; otherwise <old> must occur
  # exactly once) with <new> (`\n` separates inserted lines). Each copy is then checked with --check
  # (below), which must fail with `FAIL - <check>:`. benign <anchor> <old> <new> <what> makes a
  # copy the same way that must still PASS, so that the checks are not simply brittle.
  mutations=0
  mutations_failed=0
  mutate() {
    local check=$1 anchor=$2 old=$3 new=$4 what=$5 copy anchor_lit old_lit
    mutations=$((mutations + 1))
    copy=$(printf '%s/mutation-%03d.yml' "$work" "$mutations")
    # The lines as awk will match them (awk -v turns \\ into \).
    anchor_lit=$(awk -v s="$anchor" 'BEGIN { print s }')
    old_lit=$(awk -v s="$old" 'BEGIN { print s }')
    if [ -n "$anchor" ]; then
      [ "$(grep -cxF -- "$anchor_lit" "$workflow")" = 1 ] ||
        { mutations_failed=1; echo "FAIL - self-test: $what: the anchor line is not unique: $anchor"; return; }
    else
      [ "$(grep -cxF -- "$old_lit" "$workflow")" = 1 ] ||
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
  benigns=0
  benign() { benigns=$((benigns + 1)); mutate PASS "$@"; }

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

  # --- B02: secrets, the token and publishing in any spelling --------------------------------------
  mutate forbidden "" "$mode_env" "$mode_env\n      T: \${{ SECRETS.X }}" "secrets in upper case"
  mutate forbidden "" "$mode_env" "$mode_env\n      T: \${{ secrets['X'] }}" "secrets in bracket form"
  mutate forbidden "" "$mode_env" "$mode_env\n      T: \${{ secrets[\"X\"] }}" "secrets in double-quoted bracket form"
  mutate forbidden "" "$mode_env" "$mode_env\n      T: \${{ toJSON(secrets) }}" "toJSON(secrets)"
  mutate forbidden "" "$mode_env" "$mode_env\n      T: \${{ github.Token }}" "github.Token in mixed case"
  mutate forbidden "" "$mode_env" "$mode_env\n      T: \${{ github['token'] }}" "github['token']"
  mutate forbidden "" "$mode_env" "$mode_env\n      T: \${{ github['event'].pull_request.title }}" "github['event']"
  mutate forbidden "" "$runs_on" "$runs_on\n    secrets: inherit" "secrets: inherit"
  mutate forbidden "" "$mode_env" "$mode_env\n      GH_TOKEN: abc" "a literal token variable"
  mutate forbidden "" "$parity_run" "        run: gh run download 1 && scripts/conformance-parity.sh" "gh run download"
  mutate forbidden "" "$release_package" "$release_package && gh  release upload v0.1.0 dist/apple/PolyjoseFFI.xcframework.zip" "gh release with two spaces"
  mutate forbidden "" "$release_package" "$release_package && curl -T dist/apple/PolyjoseFFI.xcframework.zip https://example.com/up" "curl -T"
  mutate forbidden "" "$release_package" "$release_package && curl --upload-file dist/apple/PolyjoseFFI.xcframework.zip https://example.com/up" "curl --upload-file"
  mutate forbidden "" "$release_package" "$release_package && curl -fsF file=@dist/apple/PolyjoseFFI.xcframework.zip https://example.com/up" "curl -F in a flag cluster"
  mutate forbidden "" "$release_package" "$release_package && curl --data-binary @dist/apple/PolyjoseFFI.xcframework.zip https://example.com/up" "curl --data-binary @"
  mutate forbidden "" "$release_package" "$release_package && npm  publish" "npm publish with two spaces"
  mutate forbidden "" "$release_package" "$release_package && cargo   publish -p polyjose" "cargo publish with three spaces"
  mutate forbidden "" "$release_package" "$release_package && ./gradlew publishToMavenCentral" "a gradle publish task"
  mutate forbidden "" "$release_package" "$release_package && pod trunk push Polyjose.podspec" "pod trunk push"
  mutate forbidden "" "$release_package" "$release_package && swift package-registry publish polyjose.Polyjose 0.1.0" "swift package-registry publish"
  mutate forbidden "" "$parity_run" "        run: scripts/conformance-parity.sh || :" "|| :"
  mutate forbidden "" "          rm -rf target/conformance" "          set +e\n          rm -rf target/conformance" "set +e"
  mutate forbidden "" "$parity_run" "        run: scripts/conformance-parity.sh; exit 0" "exit 0"

  # --- B03: no expression in any run script, whatever its form; expressions only where listed ----
  mutate expressions "" "      - name: rust-core reference" "      - name: extra\n        run: >-\n          echo \${{ inputs.mode }}\n\n      - name: rust-core reference" "an expression in a run: >- script"
  mutate expressions "" "      - name: rust-core reference" "      - name: extra\n        run: >\n          echo \${{ inputs.mode }}\n\n      - name: rust-core reference" "an expression in a run: > script"
  mutate expressions "" "      - name: rust-core reference" "      - name: extra\n        run: |-\n          echo \${{ inputs.mode }}\n\n      - name: rust-core reference" "an expression in a run: |- script"
  mutate expressions "" "      - name: rust-core reference" "      - name: extra\n        run: |+\n          echo \${{ inputs.mode }}\n\n      - name: rust-core reference" "an expression in a run: |+ script"
  mutate expressions "" "      - name: rust-core reference" "      - name: extra\n        run: echo\n          \${{ inputs.mode }}\n\n      - name: rust-core reference" "an expression in a plain multi-line run script"
  mutate expressions "" "      - name: rust-core reference" "      - run: echo \${{ inputs.mode }}\n\n      - name: rust-core reference" "an expression in a - run: item"
  mutate expressions "" "    timeout-minutes: 180" "    timeout-minutes: \${{ inputs.mode == 'ci' && 180 || 200 }}" "an expression outside the listed keys"
  mutate expressions "" "$mode_env" "$mode_env\n      T: \${{ github.actor }}" "a context outside the allow-list"
  mutate expressions "" "$mode_env" "$mode_env\n      T: \"\${{ \\\\u0073ecrets.X }}\"" "a YAML escape inside an expression"
  mutate expressions "      - name: conformance parity" "$parity_run" "        if: \${{ always() }}\n$parity_run" "an if: condition outside the allow-list"

  # --- B04: the required steps are exactly what they must be ----------------------------------------
  mutate steps "" "$parity_run" "$parity_run || true" "parity || true"
  mutate steps "" "$parity_run" "        run: echo scripts/conformance-parity.sh" "parity only echoed"
  mutate steps "" "$parity_run" "        run: scripts/conformance-parity.sh /nonexistent" "parity over another directory"
  mutate steps "" "$core_run" "$core_run || true" "rust-core || true"
  mutate steps "" "$core_run" "        run: echo cargo test --locked -p polyjose --test conformance" "rust-core only echoed"
  mutate steps "" "$release_package" "$release_package || true" "release package.sh || true"
  mutate steps "" "$release_package" "        run: echo platforms/swift/scripts/package.sh" "release package.sh only echoed"
  mutate steps "" "        run: platforms/swift/scripts/build-xcframework.sh --release" "        run: echo platforms/swift/scripts/build-xcframework.sh --release" "the release build only echoed"
  mutate steps "" "$release_package" "        run: |\n          platforms/swift/scripts/package.sh --allow-d\\\\\n          ev" "--allow-dev split over a line continuation"
  # shellcheck disable=SC2016 # literal workflow text
  mutate steps "" '          platforms/swift/test.sh 2>&1 | tee "$RUNNER_TEMP/swift-test.log"' '          platforms/swift/scripts/test-simulators.sh 2>&1 | tee "$RUNNER_TEMP/swift-test.log"' "test.sh replaced while its PASS text stays"
  # shellcheck disable=SC2016 # literal workflow text
  mutate steps "" '          if [ "$(tail -n 1 "$RUNNER_TEMP/swift-test.log")" != "platforms/swift/test.sh: PASS" ]; then' '          if [ "$(tail -n 1 "$RUNNER_TEMP/swift-test.log")" != "platforms/swift/test.sh: PASS" ] && false; then' "the PASS check ending in && false"
  mutate steps "" "          rm -rf target/conformance" "          echo rm -rf target/conformance" "the results reset only echoed"
  # shellcheck disable=SC2016 # literal workflow text
  mutate steps "" '          platforms/swift/test.sh 2>&1 | tee "$RUNNER_TEMP/swift-test.log"' '          platforms/swift/test.sh 2>&1 | tee "$RUNNER_TEMP/swift-test.log"\n          rm -rf target/conformance' "the results reset after test.sh"
  mutate steps '            echo "::error::release mode requires the iOS Simulator run; test-simulators.sh skipped it (no iOS 27.2 runtime on the runner)"' "            exit 1" "            exit 0" "the release iOS check exiting 0 on a skip line"
  mutate steps '            echo "::error::release mode requires target/conformance/swift-ios-sim.json"' "            exit 1" "            exit 0" "the release iOS check exiting 0 on a missing file"
  # shellcheck disable=SC2016 # literal workflow text
  mutate steps "" '          log="$RUNNER_TEMP/swift-test.log"' '          log="$RUNNER_TEMP/other.log"' "the release iOS check reading another log"
  mutate steps '            echo "::error::missing target/conformance/swift-macos.json"' "            exit 1" "            exit 0" "the results step passing without swift-macos.json"
  mutate steps '            echo "::error::missing target/conformance/swift-ios-sim.json (and no ci-mode waiver from test-simulators.sh)"' "            exit 1" "            exit 0" "the results step passing without swift-ios-sim.json"
  mutate steps "" '            *) echo "::error::the mode input must be ci or release"; exit 1 ;;' '            *) echo "::error::the mode input must be ci or release"; exit 0 ;;' "mode validation exiting 0"
  mutate steps "" "      - name: every results file is present" "      - name: extra\n        run: rm -f target/conformance/swift-ios-sim.json\n\n      - name: every results file is present" "an extra run step"
  mutate actions "" "          save-if: \${{ github.ref == 'refs/heads/main' }}" "          save-if: true" "rust-cache saving from every ref"
  mutate actions "" "      - name: rust-core reference" "      - uses: softprops/action-gh-release@0123456789abcdef0123456789abcdef01234567 # v2.0.0\n        with:\n          draft: true\n\n      - name: rust-core reference" "an action outside the allow-list"
  mutate shell "" "    shell: bash --noprofile --norc -euo pipefail {0}" "    working-directory: ." "the default shell removed"
  mutate shell "" "    shell: bash --noprofile --norc -euo pipefail {0}" "    shell: bash" "GitHub's bash default, without -u"
  mutate shell "" "$parity_run" "        shell: sh\n$parity_run" "a step overriding the shell"
  mutate env "" "  CARGO_INCREMENTAL: 0" "  CARGO_INCREMENTAL: 0\n  BASH_ENV: /tmp/x" "BASH_ENV in the workflow env"
  mutate env "" "$mode_env" "$mode_env\n      POLYJOSE_LOCAL_XCFRAMEWORK: 0" "an extra job env variable"
  mutate structure "" "permissions:" "concurrency:\n  group: apple\npermissions:" "a top-level concurrency block"
  mutate structure "" "$runs_on" "$runs_on\n    container: ghcr.io/example/image:1" "a job container"

  # --- B05: escapes and folding in double-quoted free strings ---------------------------------------
  # (single-quoted here so that awk turns \\x into \x, writing the YAML escape itself)
  mutate quoting "" "      - name: conformance parity" '      - name: "\\x24\\x7b\\x7b \\x73ecrets.X \\x7d\\x7d"' "an escaped secrets expression in a step name"
  mutate quoting "" "      - name: conformance parity" '      - name: "\\x24\\x7b\\x7b github.\\x74oken \\x7d\\x7d"' "an escaped github.token expression in a step name"
  mutate quoting "" "          node-version: 24" '          node-version: "\\x24\\x7b\\x7b \\x73ecrets.X \\x7d\\x7d"' "an escaped expression in node-version"
  # shellcheck disable=SC2016 # literal workflow text
  mutate quoting "" "          node-version: 24" '          node-version: "${\\\n            { sec\\\n            rets.X }}"' "an expression folded over escaped line breaks in node-version"
  mutate quoting "          name: apple-xcframework" "          if-no-files-found: error" '          if-no-files-found: error\n          retention-days: "\\x24\\x7b\\x7b \\x73ecrets.X \\x7d\\x7d"' "an escaped expression in retention-days"
  # shellcheck disable=SC2016 # literal workflow text
  mutate quoting "" "$checkout_pin" '      - name: "$\\\n          {{ secrets.X }}"\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1' "an action step name folded into an expression"
  mutate quoting "" "      - name: conformance parity" '      - name: "conformance\n          parity"' "a double-quoted step name folded over two lines"
  # shellcheck disable=SC2016 # literal workflow text
  mutate quoting "" "      - name: conformance parity" '      - name: "\\u0024{{ github.ref }}"' "a \$ written as an escape"
  # A single-quoted scalar holds a backslash literally (YAML has no escapes there): harmless.
  benign "" "      - name: conformance parity" "      - name: 'conformance parity (results in target\\\\conformance)'" "a single-quoted step name with a literal backslash"
  # B05 backlog: in a run block, a # line between backslash-continued lines is part of the script.
  mutate steps "" "          curl --proto '=https' --tlsv1.2 -fsSL -o \"\$dir/\$tarball\" \\\\" "          curl --proto '=https' --tlsv1.2 -fsSL -o \"\$dir/\$tarball\" \\\\\n          # a comment line that ends the command here" "a # line inside a backslash-continued command"

  # --- B06: any whitespace (a TAB too) separates a value, so a quoted scalar after it is scanned ----
  # (awk turns \t into a TAB, \n into a line break and \\x into \x)
  mutate quoting "" "          node-version: 24" '          node-version:\t"\\x24\\x7b\\x7b \\x73ecrets.X \\x7d\\x7d"' "an escaped expression in node-version after a tab"
  mutate quoting "" "          node-version: 24" '          node-version: \t"\\x73ecrets"' "an escape in node-version after a space and a tab"
  # shellcheck disable=SC2016 # literal workflow text
  mutate quoting "" "          node-version: 24" '          node-version:\t"${\\\n            { sec\\\n            rets.X }}"' "an expression folded over escaped line breaks after a tab"
  mutate quoting "" "          node-version: 24" "          node-version:\t'a\n            b'" "a single-quoted node-version over two lines after a tab"
  mutate quoting "          name: apple-xcframework" "          if-no-files-found: error" '          if-no-files-found: error\n          retention-days:\t"\\x73ecrets"' "an escape in retention-days after a tab"
  mutate quoting "          name: conformance-swift-macos" "          if-no-files-found: error" '          if-no-files-found: error\n          compression-level:\t"\\x73ecrets"' "an escape in compression-level after a tab"
  mutate quoting "" "$checkout_pin" "$checkout_pin"'\n        name:\t"\\x73ecrets"' "an escape in an action step's name after a tab"
  mutate quoting "" "$checkout_pin" '      - name:\t"\\x73ecrets"\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1' "an escape in an action step's item name after a tab"
  mutate quoting "" "    name: Swift (iOS) (\${{ inputs.mode }})" '    name:\t"\\x73ecrets"' "an escape in the job name after a tab"
  mutate quoting "" "          node-version: 24" '          node-version: {"a":"\\x73ecrets"}' "an escape in a JSON-like flow mapping (a quote right after a colon)"
  benign "" "          node-version: 24" '          node-version: 24\t# the "parity runner' "a tab before a comment that holds a quote"

  # --- B07: every value outside the run bodies sits on its key's line --------------------------------
  mutate one-line "" "          name: apple-xcframework" "          name: apple-xcframework\n            -dev" "the apple-xcframework artifact name continued (apple-xcframework -dev)"
  mutate one-line "" "          name: apple-xcframework" "          name: apple-xcframework\n            - dev" "the apple-xcframework artifact name continued by a list-like line"
  mutate one-line "" "          name: conformance-swift-macos" "          name: conformance-swift-macos\n            more" "the conformance-swift-macos artifact name continued"
  mutate one-line "" "          persist-credentials: false" "          persist-credentials: false\n            x" "persist-credentials continued (false x)"
  mutate one-line "" "          node-version: 24" "          node-version: 24\n            0" "node-version continued"
  mutate one-line "" "          package-manager-cache: false" "          package-manager-cache: false\n            x" "package-manager-cache continued"
  mutate one-line "" "          path: dist/apple/*" "          path: dist/apple/*\n            x" "an upload path continued"
  mutate one-line "          name: conformance-swift-macos" "          if-no-files-found: error" "          if-no-files-found: error\n            x" "if-no-files-found continued"
  mutate one-line "" "          save-if: \${{ github.ref == 'refs/heads/main' }}" "          save-if: \${{ github.ref == 'refs/heads/main' }}\n            x" "save-if continued"
  mutate one-line "" "    timeout-minutes: 180" "    timeout-minutes: 180\n      0" "the job timeout continued"
  mutate one-line "      - name: package.sh (ci mode, a development build allowed)" "        if: inputs.mode == 'ci'" "        if: inputs.mode == 'ci'\n          && false" "a ci-mode step's if: continued with && false"
  mutate one-line "$cache_pin" "        if: inputs.mode == 'ci'" "        if: inputs.mode == 'ci'\n          && false" "rust-cache's if: continued with && false"
  mutate one-line "" "          node-version: 24" "          node-version:\n            24" "node-version on a line of its own"
  # shellcheck disable=SC2016 # literal workflow text
  mutate one-line "" "          node-version: 24" '          node-version: |\n            # ${{ secrets.X }}' "a block-scalar node-version whose line looks like a comment"
  mutate one-line "" "$checkout_pin" "$checkout_pin\n        name: >-\n          # \${{ secrets.X }}" "a block-scalar action step name"
  mutate one-line "" "          node-version: 24" "          node-version: 24\n\t    0" "a continuation line indented with a tab"
  benign "" "      - name: conformance parity" "      - name: conformance parity # ADR 0060" "a comment after a step name"

  # --- The ADR 0037 §1 artifact names are whole values ------------------------------------------------
  mutate artifacts "" "          name: apple-xcframework" "          name: apple-xcframework-dev" "the artifact name apple-xcframework-dev"
  mutate artifacts "" "          name: apple-xcframework" "          name: apple-xcframework x" "the artifact name apple-xcframework x"
  mutate artifacts "" "          name: apple-xcframework" "          name: 'apple-xcframework x'" "a single-quoted artifact name with extra text"
  mutate artifacts "" "          name: apple-xcframework" '          name: "apple-xcframework-dev"' "a double-quoted artifact name with extra text"
  mutate artifacts "" "          name: conformance-swift-macos" "          name: conformance-swift-macos-2" "conformance-swift-macos with a suffix"
  mutate artifacts "" "          name: conformance-swift-ios-sim" "          name: conformance-swift-ios-sim x" "conformance-swift-ios-sim with extra text"

  # --- Benign: must still PASS ------------------------------------------------------------------
  benign "          name: apple-xcframework" "          if-no-files-found: error" "          if-no-files-found: error\n          retention-days: 30" "retention-days on an upload"
  benign "          name: conformance-swift-macos" "          if-no-files-found: error" "          if-no-files-found: error\n          compression-level: 9" "compression-level on an upload"
  benign "" "      - name: conformance parity" "      - name: parity of every results file (ADR 0034, ADR 0060)" "a step renamed"
  benign "" "      - name: rust-core reference" "      # a note for readers\n      - name: rust-core reference" "a comment line between steps"
  benign "" "$parity_run" "$parity_run\n          # not a step key: a comment inside the step" "a comment line inside a step"
  benign "" "      - name: rust-core reference" "\n      - name: rust-core reference" "a blank line between steps"
  benign "" "    timeout-minutes: 180" "    timeout-minutes: 200" "a longer job timeout"
  benign "" "          node-version: 24" "          node-version: 22" "another Node major for parity"

  # Check the copies, eight at a time (each check is a few seconds of short-lived processes).
  batch=0
  for copy in "$work"/mutation-*.yml; do
    [ -f "$copy" ] || continue
    ( rc=0; "$0" --check "$copy" >"$copy.log" 2>&1 || rc=$?; echo "$rc" >"$copy.rc" ) &
    batch=$((batch + 1))
    if [ "$batch" = 8 ]; then wait; batch=0; fi
  done
  wait
  for copy in "$work"/mutation-*.yml; do
    [ -f "$copy" ] || continue
    check=$(sed -n 1p "$copy.meta")
    what=$(sed -n 2p "$copy.meta")
    rc=$(cat "$copy.rc")
    if [ "$check" = PASS ]; then
      if [ "$rc" = 0 ]; then
        echo "ok   - self-test: $what still passes"
      else
        mutations_failed=1
        echo "FAIL - self-test: $what (benign) was rejected (exit $rc)"
        sed 's/^/    | /' "$copy.log"
      fi
    elif [ "$rc" = 1 ] && grep -qF -- "FAIL - $check:" "$copy.log"; then
      echo "ok   - self-test: $what is rejected ($check)"
    else
      mutations_failed=1
      echo "FAIL - self-test: $what was not rejected by the $check check (exit $rc)"
      sed 's/^/    | /' "$copy.log"
    fi
  done

  if [ "$mutations_failed" = 0 ]; then
    echo "$me: PASS (${workflow#"$root"/}; self-test: $((mutations - benigns)) mutations rejected, $benigns benign ones accepted)"
  else
    echo "$me: FAIL (self-test)"
    status=1
  fi
fi
completed=1; exit "$status"
