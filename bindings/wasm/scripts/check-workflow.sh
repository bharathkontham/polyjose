#!/usr/bin/env bash
# Local verification of the WASM package's GitHub Actions workflow (feature 0006 T05; ADR 0044,
# ADR 0037 §1 and §2, pipeline rule 8). The workflow is never run on a PR and never dispatched by
# an agent, so this script is what checks it.
#
#   bindings/wasm/scripts/check-workflow.sh [file]     check the workflow (default:
#                                                      .github/workflows/binding-wasm.yml)
#   bindings/wasm/scripts/check-workflow.sh --self-test
#
# Checks, each reported as `check-workflow: FAIL [<rule>] <file>:<line>: <reason>`:
#   [top-level]   only the keys name, run-name, on, permissions, env, defaults, concurrency and jobs
#                 at the top, each once (so a quoted "on" or a `true:` key cannot add triggers);
#   [trigger]     `on:` is a block mapping of exactly `workflow_dispatch` and `workflow_call`, each
#                 with no configuration at all: no `inputs`, `secrets` or `outputs` (owner rule
#                 2026-11-07: no pull_request, push or schedule trigger; ADR 0044);
#   [permissions] the top-level `permissions:` is exactly `contents: read`, and no line anywhere
#                 grants `write`, `write-all` or `read-all`;
#   [secrets]     no `secrets` and no `token` anywhere (any case): no secrets context, no
#                 `secrets: inherit`, no GITHUB_TOKEN / github.token, no `token:` input, no
#                 registry token, no id-token;
#   [publish]     no publish or release command: npm/pnpm/yarn/bun/wasm-pack/cargo publish, napi
#                 pre-publish, npm login/adduser, gh release, Maven Central publish tasks, and no
#                 setup-node `registry-url` (it writes an .npmrc for publishing). Publishing is
#                 Gate 3 (ADR 0011, ADR 0037 §2);
#   [pin]         every `uses:` of a third-party action is pinned to a full 40-character commit SHA
#                 followed by its `# v<tag>` comment (ADR 0037 §1 "Pins"); local `./` workflows are
#                 exempt;
#   [actionlint]  actionlint (which also runs shellcheck on `run:` scripts when it is installed)
#                 reports nothing.
# The text rules never depend on actionlint (pipeline rule 9): without it they still run, and only
# the actionlint step is skipped. The output then ends with
#   check-workflow: text rules PASS; actionlint not run (actionlint missing)
#   SKIPPED (host:actionlint)
# the reason on the line before, and as the last line exactly the host-tool skip form that
# scripts/test-all.sh's negative-test step accepts (host:<tool>, feature 0013 F10). A text-rule
# failure is still a FAIL (exit 1) without actionlint.
# Full-line comments are ignored by every text rule; text after a `#` on a content line is not, so
# a pin comment cannot hide a publish command.
#
# --self-test runs the text rules on the real workflow (it must pass) and on scratch copies, each
# changed by one exact-text edit (the old text must occur exactly once): a pull_request, push,
# schedule or pull_request_target trigger, workflow_call inputs or secrets, an inline `on:`, a
# quoted "on" key, an `npm publish`, `cargo publish` or `wasm-pack publish` step, a setup-node
# registry-url, a `secrets.` reference, `secrets: inherit`, a GITHUB_TOKEN, write permissions at
# the top or on a job, `write-all`, and an unpinned action. Each copy must fail, with every FAIL
# line of the expected rule, so no other rule is what caught the change. With actionlint
# installed, a copy with a broken expression must fail actionlint too; without it every text case
# still runs, and only that one case is skipped, ending with the same two lines. The repository
# is never modified.
#
# Exit status: 0 passed, or the text rules passed and the last line is SKIPPED (host:actionlint);
# 1 a check failed; 2 a usage error or a missing file. Needs awk and grep. Runs on macOS /bin/bash 3.2 and
# Linux bash.
set -uo pipefail
export LC_ALL=C
# bash 5.2 would put the matched text in place of a `&` in a ${var/old/new} replacement.
shopt -u patsub_replacement 2>/dev/null || true

me=check-workflow
repo=$(cd "$(dirname "$0")/../../.." && pwd -P) || exit 2
default_file=$repo/.github/workflows/binding-wasm.yml

usage() { echo "usage: $0 [--self-test | <workflow file>]" >&2; exit 2; }

# text_rules <file>: prints one FAIL line per violation of a text rule; exits 1 if there was one.
text_rules() {
  awk -v file="$1" -v me="$me" '
    function fail(rule, msg) { printf "%s: FAIL [%s] %s:%d: %s\n", me, rule, file, NR, msg; bad = 1 }
    function fail_end(rule, msg) { printf "%s: FAIL [%s] %s: %s\n", me, rule, file, msg; bad = 1 }
    function indent(s) { match(s, /^ */); return RLENGTH }
    # The line without a trailing ` # comment` and trailing blanks, for the structure rules only.
    function structure(s) { sub(/[[:space:]]+#.*$/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    function key_of(s) { sub(/^[[:space:]]*/, "", s); sub(/:.*$/, "", s); return s }
    function value_of(s) { if (s !~ /:/) return ""; sub(/^[^:]*:[[:space:]]*/, "", s); return s }
    BEGIN {
      split("name run-name on permissions env defaults concurrency jobs", k, " ")
      for (i in k) top_allowed[k[i]] = 1
      sha = ""; for (i = 0; i < 40; i++) sha = sha "[0-9a-f]"
      pinned = "^[^@[:space:]]+@" sha " # v[0-9]"
    }
    /^[[:space:]]*(#|$)/ { next }
    {
      raw = $0
      line = structure(raw)
      ind = indent(line)
      lower = tolower(raw)

      # --- structure: top-level keys, `on:` and the top-level `permissions:` -----------------------
      if (ind == 0) {
        section = ""
        if (line ~ /^(---|\.\.\.)/) { fail("top-level", "more than one YAML document"); next }
        key = key_of(line); value = value_of(line)
        if (line !~ /:/ || !(key in top_allowed)) fail("top-level", "top-level key " key " is not allowed")
        else if (++seen[key] > 1) fail("top-level", "duplicate top-level key " key)
        if (key == "on") {
          if (value != "") fail("trigger", "on: must be a block mapping of workflow_dispatch and workflow_call, not \"" value "\"")
          section = "on"; trigger_indent = -1
        } else if (key == "permissions") {
          if (value != "") fail("permissions", "the top-level permissions must be the block \"contents: read\", not \"" value "\"")
          section = "permissions"
        }
      } else if (section == "on") {
        if (trigger_indent < 0) trigger_indent = ind
        if (ind > trigger_indent) fail("trigger", "configuration under a trigger (inputs, secrets, outputs, branches...) is not allowed")
        else if (ind < trigger_indent) fail("trigger", "unexpected indentation in on:")
        else {
          key = key_of(line); value = value_of(line)
          if (key != "workflow_dispatch" && key != "workflow_call") fail("trigger", "trigger " key " is not allowed (only workflow_dispatch and workflow_call)")
          else triggers[key]++
          if (value != "" && value != "{}" && value != "null" && value != "~") fail("trigger", key " must have no configuration, not \"" value "\"")
        }
      } else if (section == "permissions") {
        permissions_lines++
        if (line !~ /^[[:space:]]+contents:[[:space:]]+read$/) fail("permissions", "the top-level permissions must be exactly \"contents: read\": " line)
      }

      # --- content rules, on every non-comment line -------------------------------------------------
      # `<scope>: write`, quoted or not, as a block entry or inside a flow mapping.
      if (line ~ /(^|[^[:alnum:]_-])(write-all|read-all)([^[:alnum:]_-]|$)/ || line ~ /:[[:space:]]*["'"'"']?write["'"'"']?[[:space:]]*([,}]|$)/)
        fail("permissions", "write or blanket permission: " line)
      if (lower ~ /secrets|token/)
        fail("secrets", "secrets and tokens are not allowed: " raw)
      if (lower ~ /(npm|pnpm|yarn|bun|wasm-pack|cargo)[[:space:]]+publish|napi[[:space:]]+pre-?publish|npm[[:space:]]+(login|adduser)|gh[[:space:]]+release|publish(and)?(release)?tomavencentral|registry-url/)
        fail("publish", "publishing is Gate 3 and never in this workflow: " raw)
      if (raw ~ /^[[:space:]]*(-[[:space:]]+)?uses:/) {
        target = raw; sub(/^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*/, "", target)
        gsub(/["'"'"']/, "", target)
        if (target !~ /^\.\// && target !~ pinned) fail("pin", "not pinned to a full commit SHA with its # v<tag> comment: " target)
      }
    }
    END {
      if (!seen["on"]) fail_end("trigger", "no on: key")
      if (seen["on"] && triggers["workflow_dispatch"] != 1) fail_end("trigger", "workflow_dispatch must be listed exactly once")
      if (seen["on"] && triggers["workflow_call"] != 1) fail_end("trigger", "workflow_call must be listed exactly once")
      if (!seen["permissions"]) fail_end("permissions", "no top-level permissions: (it must be contents: read)")
      else if (permissions_lines != 1) fail_end("permissions", "the top-level permissions must be exactly \"contents: read\"")
      if (!seen["jobs"]) fail_end("top-level", "no jobs:")
      exit bad
    }' "$1"
}

# lint <file>: 0 actionlint is clean, 1 it reported something, 3 actionlint is not installed.
lint() {
  command -v actionlint >/dev/null 2>&1 || return 3
  if actionlint -no-color "$1"; then return 0; fi
  echo "$me: FAIL [actionlint] $1"
  return 1
}

# check <file>: every rule; prints the result line.
check() {
  local file=$1 status=0 rc=0
  [ -f "$file" ] || { echo "$me: $file not found" >&2; exit 2; }
  echo "==> $me: text rules (${file#"$repo"/})"
  text_rules "$file" || status=1
  echo "==> $me: actionlint"
  lint "$file" || rc=$?
  [ "$rc" -eq 1 ] && status=1
  if [ "$status" -ne 0 ]; then
    echo "$me: FAILED (${file#"$repo"/})"
    return 1
  fi
  if [ "$rc" -eq 3 ]; then
    echo "$me: text rules PASS (${file#"$repo"/}); actionlint not run (actionlint missing)"
    echo "SKIPPED (host:actionlint)"
    return 0
  fi
  echo "$me: PASS (${file#"$repo"/}: text rules, actionlint $(actionlint -version 2>/dev/null | head -n 1))"
}

# --- --self-test ---------------------------------------------------------------------------------

self_test() {
  local scratch base cases_run=0 cases_failed=0 lint_note=""
  [ -f "$default_file" ] || { echo "$me: $default_file not found" >&2; exit 2; }
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/check-workflow-test.XXXXXX") || { echo "$me: mktemp failed" >&2; exit 2; }
  # shellcheck disable=SC2064 # expand now: the path is fixed
  trap "rm -rf '$scratch'" EXIT
  base=$(cat "$default_file") || exit 2

  # mutate <name> <old> <new>: writes $scratch/<name>.yml, the workflow with the one occurrence of
  # <old> replaced by <new>, and prints its path. A missing or repeated <old> is a test error.
  mutate() {
    local name=$1 old=$2 new=$3 rest count out
    rest=${base//"$old"/}
    count=$(( (${#base} - ${#rest}) / ${#old} ))
    if [ "$count" -ne 1 ]; then
      echo "$me: self-test error: case $name: expected exactly one occurrence of the edited text, found $count" >&2
      exit 2
    fi
    out=$scratch/$name.yml
    printf '%s\n' "${base/"$old"/$new}" >"$out"
    if cmp -s "$out" "$default_file"; then
      echo "$me: self-test error: case $name: the edit left the file unchanged" >&2
      exit 2
    fi
    echo "$out"
  }

  # expect_fail <name> <rules> <old> <new>: the edited copy must fail the text rules with a FAIL
  # line of each rule in <rules> (comma-separated), and with no FAIL line of any other rule.
  expect_fail() {
    local name=$1 rules=$2 copy out rc=0 rule missing="" others pattern
    copy=$(mutate "$name" "$3" "$4") || exit 2
    cases_run=$((cases_run + 1))
    out=$(text_rules "$copy") || rc=$?
    pattern="FAIL \[(${rules//,/|})\]"
    others=$(printf '%s\n' "$out" | grep "FAIL \[" | grep -vE "$pattern" || true)
    for rule in ${rules//,/ }; do
      printf '%s\n' "$out" | grep -q "FAIL \[$rule\]" || missing="$missing [$rule]"
    done
    if [ "$rc" -ne 1 ]; then
      echo "  FAIL $name: the text rules exited $rc (expected 1, with [$rules])"
      cases_failed=$((cases_failed + 1))
    elif [ -n "$missing" ]; then
      echo "  FAIL $name: no failure of$missing; got:"; printf '%s\n' "$out" | sed 's/^/    /'
      cases_failed=$((cases_failed + 1))
    elif [ -n "$others" ]; then
      echo "  FAIL $name: failures of another rule too (the case must isolate [$rules]):"
      printf '%s\n' "$others" | sed 's/^/    /'
      cases_failed=$((cases_failed + 1))
    else
      echo "  ok   $name: [$rules]"
    fi
  }

  echo "==> $me: self-test (text rules, scratch copies of ${default_file#"$repo"/})"

  cases_run=$((cases_run + 1))
  if out=$(text_rules "$default_file"); then
    echo "  ok   the workflow itself passes"
  else
    echo "  FAIL the workflow itself fails the text rules:"; printf '%s\n' "$out" | sed 's/^/    /'
    cases_failed=$((cases_failed + 1))
  fi

  local on_block call_line pin_line
  on_block=$'on:\n  workflow_dispatch:\n  workflow_call:\n'
  call_line=$'  workflow_call:\n'
  # The first action pin of the file, whatever it is.
  pin_line=$(grep -m 1 -E '^[[:space:]]*(-[[:space:]]+)?uses: [^.]' "$default_file" | sed -E 's/^[[:space:]]*(-[[:space:]]+)?uses: //')
  [ -n "$pin_line" ] || { echo "$me: self-test error: no uses: line in the workflow" >&2; exit 2; }
  local run_marker=$'    steps:\n'

  expect_fail pull-request trigger "$on_block" $'on:\n  pull_request:\n  workflow_dispatch:\n  workflow_call:\n'
  expect_fail pull-request-target trigger "$on_block" $'on:\n  pull_request_target:\n  workflow_dispatch:\n  workflow_call:\n'
  expect_fail push trigger "$on_block" $'on:\n  push:\n    branches: [main]\n  workflow_dispatch:\n  workflow_call:\n'
  expect_fail schedule trigger "$on_block" $'on:\n  schedule:\n    - cron: \'0 3 * * *\'\n  workflow_dispatch:\n  workflow_call:\n'
  expect_fail inline-on trigger "$on_block" $'on: [pull_request, workflow_dispatch, workflow_call]\n'
  expect_fail call-inputs trigger "$call_line" $'  workflow_call:\n    inputs:\n      mode:\n        type: string\n'
  expect_fail call-outputs trigger "$call_line" $'  workflow_call:\n    outputs:\n      x:\n        value: y\n'
  expect_fail call-secrets trigger,secrets "$call_line" $'  workflow_call:\n    secrets:\n      NPM_KEY:\n        required: true\n'
  expect_fail quoted-on top-level "$on_block" $'on:\n  workflow_dispatch:\n  workflow_call:\n"on":\n  workflow_dispatch:\n'
  expect_fail npm-publish publish "$run_marker" $'    steps:\n      - name: publish\n        run: npm publish dist/npm/polyjose-wasm-0.1.0.tgz\n'
  expect_fail cargo-publish publish "$run_marker" $'    steps:\n      - name: publish\n        run: cargo publish -p polyjose\n'
  expect_fail wasm-pack-publish publish "$run_marker" $'    steps:\n      - name: publish\n        run: wasm-pack  publish bindings/wasm/pkg\n'
  expect_fail registry-url publish "$run_marker" $'    steps:\n      - name: npmrc\n        run: echo registry-url=https://registry.npmjs.org\n'
  expect_fail secrets-ref secrets "$run_marker" $'    steps:\n      - name: env\n        env:\n          X: ${{ secrets.X }}\n        run: echo "$X"\n'
  expect_fail secrets-inherit secrets "$run_marker" $'    secrets: inherit\n    steps:\n'
  expect_fail github-token secrets "$run_marker" $'    steps:\n      - name: env\n        run: echo "$GITHUB_TOKEN"\n'
  expect_fail top-write permissions $'permissions:\n  contents: read\n' $'permissions:\n  contents: write\n'
  expect_fail top-extra permissions $'permissions:\n  contents: read\n' $'permissions:\n  contents: read\n  packages: read\n'
  expect_fail job-write permissions "$run_marker" $'    permissions:\n      contents: write\n    steps:\n'
  expect_fail write-all permissions "$run_marker" $'    permissions: write-all\n    steps:\n'
  expect_fail job-write-quoted permissions "$run_marker" $'    permissions:\n      packages: "write"\n    steps:\n'
  expect_fail job-write-flow permissions "$run_marker" $'    permissions: { contents: read, pull-requests: write }\n    steps:\n'
  expect_fail unpinned pin "uses: $pin_line" "uses: ${pin_line%%@*}@v7"
  expect_fail sha-without-tag pin "uses: $pin_line" "uses: ${pin_line%% #*}"

  # actionlint must reject what the text rules cannot see: a broken expression.
  if command -v actionlint >/dev/null 2>&1; then
    local copy
    copy=$(mutate broken-expression "$run_marker" $'    steps:\n      - name: broken\n        if: ${{ steps.nope.outcome == }}\n        run: "true"\n') || exit 2
    cases_run=$((cases_run + 1))
    if lint "$copy" >/dev/null 2>&1; then
      echo "  FAIL broken-expression: actionlint passed"
      cases_failed=$((cases_failed + 1))
    else
      echo "  ok   broken-expression: [actionlint]"
    fi
  else
    lint_note="actionlint missing"
  fi

  echo
  if [ "$cases_failed" -gt 0 ]; then
    echo "$me: self-test FAILED ($cases_failed of $cases_run cases)"
    return 1
  fi
  if [ -n "$lint_note" ]; then
    echo "$me: self-test: $cases_run text cases PASS; the actionlint case was not run ($lint_note)"
    echo "SKIPPED (host:actionlint)"
    return 0
  fi
  echo "$me: self-test PASS ($cases_run cases)"
}

case $# in
  0) check "$default_file" ;;
  1)
    case $1 in
      --self-test) self_test ;;
      -*) usage ;;
      *) check "$1" ;;
    esac ;;
  *) usage ;;
esac
