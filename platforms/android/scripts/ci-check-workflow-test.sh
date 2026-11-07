#!/usr/bin/env bash
# Negative tests of ci-check-workflow.sh (feature 0008 T05): the real
# .github/workflows/binding-android.yml must pass, and each mutated copy of it (in a temporary
# directory, never in the checkout) must fail with the rule it breaks.
#
#   platforms/android/scripts/ci-check-workflow-test.sh
#
# Some forbidden names are assembled from pieces, so that this file itself does not trip
# scripts/check-artifacts.sh's grep for Central and signing configuration in platforms/android.
# Exit status: 0 every case behaved; 1 a case did not (each printed with FAIL); 2 setup error.
# The cases hold literal ${{ }} and $VAR text for the workflow, never for this shell.
# shellcheck disable=SC2016
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd -P) || exit 2
repo=$(cd "$here/../../.." && pwd -P) || exit 2
check=$here/ci-check-workflow.sh
base=$repo/.github/workflows/binding-android.yml
[ -x "$check" ] || { echo "no executable $check"; exit 2; }
[ -f "$base" ] || { echo "no $base"; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/ci-check-workflow-test.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT
case_file=$tmp/binding-android.yml
passed=0 failed=0
ok() { echo "ok    $*"; passed=$((passed + 1)); }
bad() { echo "FAIL  $*"; failed=$((failed + 1)); }

# Mutations of the base file into $case_file (exit 3 when the anchor is not found).
insert_after() { # <exact line> <text, \n separated>
  awk -v anchor="$1" -v text="$2" '{ print } !done && $0 == anchor { print text; done = 1 } END { if (!done) exit 3 }' "$base" >"$case_file"
}
replace_line() { # <exact line> <text, \n separated>
  awk -v anchor="$1" -v text="$2" '!done && $0 == anchor { print text; done = 1; next } { print } END { if (!done) exit 3 }' "$base" >"$case_file"
}
replace_str() { # <literal> <literal>: the first occurrence in the file
  awk -v from="$1" -v to="$2" '!done && (i = index($0, from)) { $0 = substr($0, 1, i - 1) to substr($0, i + length(from)); done = 1 } { print } END { if (!done) exit 3 }' "$base" >"$case_file"
}
append() { { cat "$base"; printf '%b\n' "$1"; } >"$case_file"; }

# expect_fail <name> <substring of a FAIL line> <mutation...>
expect_fail() {
  local name=$1 want=$2 out rc; shift 2
  if ! "$@"; then bad "$name: the mutation did not apply (anchor not found)"; return; fi
  if cmp -s "$base" "$case_file"; then bad "$name: the mutation changed nothing"; return; fi
  out=$("$check" "$case_file" 2>&1); rc=$?
  if [ "$rc" -ne 1 ]; then bad "$name: exit $rc, not 1"; printf '%s\n' "$out" | sed 's/^/        /'; return; fi
  if printf '%s\n' "$out" | grep '^FAIL: ' | grep -qF "$want"; then ok "$name"
  else bad "$name: no FAIL line with \"$want\""; printf '%s\n' "$out" | sed 's/^/        /'; fi
}
# expect_pass <name> <mutation...>: a change that must not fail the check.
expect_pass() {
  local name=$1 out rc; shift
  if ! "$@"; then bad "$name: the mutation did not apply (anchor not found)"; return; fi
  out=$("$check" "$case_file" 2>&1); rc=$?
  if [ "$rc" -eq 0 ]; then ok "$name"; else bad "$name: exit $rc"; printf '%s\n' "$out" | sed 's/^/        /'; fi
}

sha40=0123456789abcdef0123456789abcdef01234567
checkout='actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'
setup_java='actions/setup-java@b843ebf9b913146b38da2eaa7aeddf76074ae1ad # v6.1.0'
env_anchor='          MODE: ${{ inputs.mode }}'
run_anchor='          case $MODE in'
steps_anchor='    steps:'
central_user="SONA""TYPE_USERNAME"
central_task="publishTo""MavenCentral"
central_prop="mavenCentral""Username"
signing_prop="ORG_GRADLE_PROJECT_signing""InMemoryKey"

# The real workflow.
out=$("$check" "$base" 2>&1); rc=$?
if [ "$rc" -eq 0 ]; then ok "the real workflow passes"; else bad "the real workflow fails (exit $rc)"; printf '%s\n' "$out" | sed 's/^/        /'; fi

# Triggers.
expect_fail "trigger: pull_request" "trigger:" insert_after "on:" "  pull_request:"
expect_fail "trigger: pull_request_target" "trigger:" insert_after "on:" "  pull_request_target:"
expect_fail "trigger: push" "trigger:" insert_after "on:" "  push:\n    branches: [main]"
expect_fail "trigger: schedule" "trigger:" insert_after "on:" "  schedule:\n    - cron: '0 3 * * *'"
expect_fail "trigger: workflow_call uncommented" "trigger:" replace_str "  # workflow_call:" "  workflow_call:"
expect_fail "trigger: workflow_run" "trigger:" insert_after "on:" "  workflow_run:\n    workflows: [CI]"
expect_fail "trigger: scalar on:" "trigger: on: must be a block" replace_line "on:" "on: workflow_dispatch"
expect_fail "trigger: flow list on:" "trigger: on: must be a block" replace_line "on:" "on: [workflow_dispatch, push]"
expect_fail "trigger: a second on: key (true)" "top-level on: keys" append "true:\n  push:"
expect_fail "trigger: a second on: key (quoted)" "top-level on: keys" append "\"on\":\n  push:"
expect_fail "trigger: list under on:" "trigger:" insert_after "on:" "  - push"

# Permissions.
expect_fail "permissions: no top-level block" "no top-level permissions" replace_line "permissions:" "x-permissions:"
expect_fail "permissions: contents: write" "permissions:" replace_str "  contents: read" "  contents: write"
expect_fail "permissions: write-all" "permissions:" replace_line "permissions:" "permissions: write-all"
expect_fail "permissions: read-all" "permissions:" replace_line "permissions:" "permissions: read-all"
expect_fail "permissions: a second top-level grant" "only contents: read" insert_after "  contents: read" "  actions: read"
expect_fail "permissions: job id-token: write" "permissions:" replace_str "permissions: {}" "permissions: { id-token: write }"
expect_fail "permissions: job actions: read" "only contents: read" replace_str "    permissions: {}" "    permissions:\n      actions: read"
expect_fail "permissions: job packages: write" "permissions:" insert_after "    timeout-minutes: 60" "    permissions:\n      packages: write"

# Actions.
expect_fail "actions: a tag instead of a SHA" "actions:" replace_str "$checkout" "actions/checkout@v7"
expect_fail "actions: a short SHA" "actions:" replace_str "$checkout" "actions/checkout@3d3c42e # v7.0.1"
expect_fail "actions: no version comment" "actions:" replace_str "$checkout" "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
expect_fail "actions: an allowed action at another SHA" "not one of the allowed pins" replace_str "$setup_java" "actions/setup-java@$sha40 # v6.1.0"
expect_fail "actions: the right SHA with another version" "not one of the allowed pins" replace_str "$setup_java" "actions/setup-java@b843ebf9b913146b38da2eaa7aeddf76074ae1ad # v6.2.0"
expect_fail "actions: a third-party action pinned by SHA" "not one of the allowed pins" insert_after "$steps_anchor" "      - uses: reactivecircus/android-emulator-runner@$sha40 # v2.35.0"
expect_fail "actions: a local action" "actions:" insert_after "$steps_anchor" "      - uses: ./.github/actions/setup"
expect_fail "actions: a docker action" "actions:" insert_after "$steps_anchor" "      - uses: docker://alpine:3.22"
expect_fail "structure: flow-style uses" "structure: flow-style uses:" insert_after "$steps_anchor" "      - { uses: $checkout }"

# Quoted keys (F03): the uses: scan must see them, and a quoted key is outside the subset.
expect_fail "actions: a double-quoted uses key, unpinned" "actions:" insert_after "$steps_anchor" '      - "uses": evil/x@v1'
expect_fail "actions: a single-quoted uses key, unpinned" "actions:" insert_after "$steps_anchor" "      - 'uses': evil/x@v1"
expect_fail "actions: a quoted uses key, pinned but not allowed" "actions:" insert_after "$steps_anchor" "      - \"uses\": reactivecircus/android-emulator-runner@$sha40 # v2.35.0"
expect_fail "actions: a quoted uses key after a space" "actions:" insert_after "$steps_anchor" "      - 'uses' : evil/x@v1"
expect_fail "actions: a quoted uses key on its own line" "actions:" insert_after "$steps_anchor" '      - name: x\n        "uses": evil/x@v1'
expect_fail "structure: a quoted uses key with an allowed pin" "structure: a quoted key" insert_after "$steps_anchor" "      - \"uses\": $checkout"
expect_fail "structure: an escaped double-quoted uses key" "structure: a quoted key" insert_after "$steps_anchor" '      - "u\\x73es": evil/x@v1'
expect_fail "structure: flow-style double-quoted uses" "structure: flow-style uses:" insert_after "$steps_anchor" '      - { "uses": evil/x@v1 }'
expect_fail "structure: flow-style single-quoted uses" "structure: flow-style uses:" insert_after "$steps_anchor" "      - { 'uses': evil/x@v1 }"
expect_fail "structure: flow-style quoted uses without spaces" "structure: a quoted key" insert_after "$steps_anchor" '      - {"name":"x","uses":"evil/x@v1"}'
expect_fail "structure: flow-style quoted key after a comma" "structure: a quoted key" insert_after "$steps_anchor" "      - { name: x, 'uses': evil/x@v1 }"
expect_fail "structure: an explicit ? key" "structure: an explicit ? key" insert_after "$steps_anchor" "      - ? uses\n        : evil/x@v1"
expect_fail "structure: a tagged uses key" "structure: a YAML tag" insert_after "$steps_anchor" "      - !!str uses: evil/x@v1"
expect_fail "trigger: a quoted pull_request key" "trigger:" insert_after "on:" '  "pull_request":'
expect_fail "trigger: a quoted pull_request key is outside the subset" "structure: a quoted key" insert_after "on:" "  'pull_request':"
expect_fail "permissions: a quoted job permissions key" "structure: a quoted key" replace_str "    permissions: {}" "    \"permissions\": {}"
expect_fail "credentials: a quoted secrets key" "credentials: secrets" insert_after "    timeout-minutes: 5" "    'secrets': inherit"
expect_pass "structure: quoted values with a colon or an apostrophe are not keys" insert_after "$env_anchor" "          X: \"a: b\"\n          Y: 'it''s: fine'\n          Z: { a: \"x\", b: 'y: z' }"

# Credentials.
expect_fail "credentials: secrets context" "credentials: secrets" insert_after "$env_anchor" '          X: ${{ secrets.X }}'
expect_fail "credentials: secrets[...] context" "credentials: secrets" insert_after "$env_anchor" "          X: \${{ secrets['X'] }}"
expect_fail "credentials: secrets: inherit" "credentials: secrets" insert_after "    timeout-minutes: 5" "    secrets: inherit"
expect_fail "credentials: github.token" "credentials: a token" insert_after "$env_anchor" '          X: ${{ github.token }}'
expect_fail "credentials: GITHUB_TOKEN in a script" "credentials: a token" insert_after "$run_anchor" '          curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com'
expect_fail "credentials: github['token']" "credentials: a token" insert_after "$env_anchor" "          X: \${{ github['token'] }}"
expect_fail "credentials: github[\"token\"]" "credentials: a token" insert_after "$env_anchor" '          X: ${{ github["token"] }}'
expect_fail "credentials: a github-token input" "credentials: a token" insert_after "          pattern: conformance-*" "          github-token: x"
expect_fail "credentials: persist-credentials: true" "credentials: password, username or credential" replace_str "persist-credentials: false" "persist-credentials: true"
expect_fail "credentials: Sonatype user" "credentials:" insert_after "$env_anchor" "          $central_user: x"
expect_fail "credentials: Central property" "credentials: Maven Central" insert_after "$env_anchor" "          X: $central_prop"
expect_fail "credentials: Gradle project property" "credentials: an ORG_GRADLE_PROJECT_ property" insert_after "$env_anchor" "          ORG_GRADLE_PROJECT_x: y"
expect_fail "credentials: a deployment environment" "credentials: a deployment environment" insert_after "    timeout-minutes: 5" "    environment: release-signing"
expect_fail "credentials: setup-java server password" "credentials: password" insert_after '          java-version: "21"' "          server-password: X"

# Publishing and signing.
expect_fail "publishing: the Central task" "publishing: publish" insert_after "$run_anchor" "          ./gradlew $central_task"
expect_fail "publishing: npm publish" "publishing: publish" insert_after "$run_anchor" "          npm publish"
expect_fail "publishing: a signing key property" "publishing: signing" insert_after "$env_anchor" "          $signing_prop: x"
expect_fail "publishing: gpg" "publishing: signing" insert_after "$run_anchor" "          gpg --batch --import key.asc"
expect_fail "publishing: sign" "publishing: signing" insert_after "$run_anchor" "          cosign sign x"

# Expressions.
expect_fail "expressions: vars context" "expressions:" insert_after "$env_anchor" '          X: ${{ vars.X }}'
expect_fail "expressions: env context" "expressions:" insert_after "$env_anchor" '          X: ${{ env.X }}'
expect_fail "expressions: toJSON(github)" "whole github context" insert_after "$env_anchor" '          X: ${{ toJSON(github) }}'
expect_fail "expressions: toJSON(secrets)" "credentials: secrets" insert_after "$env_anchor" '          X: ${{ toJSON(secrets) }}'
expect_fail "expressions: toJSON(env)" "expressions:" insert_after "$env_anchor" '          X: ${{ toJSON(env) }}'
expect_fail "expressions: the bare github context" "whole github context" insert_after "$env_anchor" '          X: ${{ github }}'
expect_fail "expressions: github['token'] indexes the github context" "whole github context" insert_after "$env_anchor" "          X: \${{ github['token'] }}"
expect_fail "expressions: github[\"token\"] indexes the github context" "whole github context" insert_after "$env_anchor" '          X: ${{ github["token"] }}'
expect_fail "expressions: a computed github index" "whole github context" insert_after "$env_anchor" "          X: \${{ github[format('{0}{1}', 'tok', 'en')] }}"
expect_fail "expressions: the github.* object filter" "whole github context" insert_after "$env_anchor" '          X: ${{ toJSON(github.*) }}'
expect_fail "expressions: fromJSON(toJSON(github))" "whole github context" insert_after "$env_anchor" '          X: ${{ fromJSON(toJSON(github)).sha }}'
expect_pass "expressions: a github property stays allowed" insert_after "$env_anchor" '          X: ${{ github.sha }}\n          Y: ${{ toJSON(github.event.inputs) }}'
expect_fail "expressions: an input inside run:" "inside a run: script" replace_line "$run_anchor" '          case ${{ inputs.mode }} in'
expect_fail "expressions: inline run: with \${{ }}" "inside a run: script" replace_line "        run: platforms/android/scripts/ci-parity.sh target/ci-results" '        run: platforms/android/scripts/ci-parity.sh ${{ github.workspace }}/target/ci-results'

# Structure.
expect_fail "structure: an anchor" "structure: YAML anchor" insert_after "$env_anchor" "          X: &x 1"
expect_fail "structure: a merge key" "structure: YAML anchor" insert_after "$env_anchor" "          <<: {X: 1}"
expect_fail "structure: a second document" "structure: a second YAML document" append "---\nname: other"
expect_fail "structure: tab indentation" "structure: tab indentation" append "\tx: 1"

# Scripts.
expect_fail "scripts: a step that is gone" "scripts: no step calls platforms/android/scripts/ci-parity.sh" \
  replace_line "        run: platforms/android/scripts/ci-parity.sh target/ci-results" "        run: scripts/conformance-parity.sh"
expect_fail "scripts: a script that does not exist" "is not an executable regular file" \
  replace_line "        run: platforms/android/scripts/ci-parity.sh target/ci-results" "        run: platforms/android/scripts/ci-parity.sh target/ci-results && platforms/android/scripts/ci-missing.sh"

# Comments do not count.
expect_pass "comments: a commented trigger and secrets mention" insert_after "on:" "  # pull_request:   (\${{ secrets.X }}, publish, signing: not code)"
expect_pass "comments: a commented uses line" insert_after "$steps_anchor" "      # - uses: actions/checkout@v4"

# Usage.
"$check" "$tmp/does-not-exist.yml" >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 2 ]; then ok "a missing workflow file is a usage error (2)"; else bad "a missing workflow file: exit $rc, not 2"; fi

echo
echo "ci-check-workflow-test: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
