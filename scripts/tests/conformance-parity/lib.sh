# shellcheck shell=bash
# Shared helpers for the negative tests of scripts/conformance-parity.sh. Sourced, not run.
#
# Each case writes results files (conformance/schema/results.schema.json) into a fresh temporary
# directory, runs the parity check on it, and checks the exit status and the output: a failing
# case must print the expected FAIL line, and every FAIL line must be of the expected kind, so no
# other check is what caught the change. Fixtures are built from REFERENCE below by exact text
# replacement (each old text must occur exactly once). The repository is never modified.
#
# Runs on macOS /bin/bash 3.2 and Linux bash.

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
parity=$repo/scripts/conformance-parity.sh
tests_failed=0
tests_run=0

lib_die() { echo "ERROR: $*" >&2; exit 2; }

command -v node >/dev/null 2>&1 || lib_die "node not found on PATH"
[ -x "$parity" ] || lib_die "$parity is not executable"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/conformance-parity-test.XXXXXX") || lib_die "mktemp failed"
trap 'rm -rf "$scratch"' EXIT

# The reference fixture (rust-core.json): an executed success, an executed failure vector, and two
# skips, one per feature.
REFERENCE='{"runner":"rust-core","polyjose":"0.1.0","features":[],
"error_codes":["InvalidBase64","InvalidKey","DecryptionFailed"],
"results":[
{"id":"b64url/encode.json#0","source":"RFC 4648 §10","op":"b64url.encode","status":"pass","actual":{"ok":true}},
{"id":"b64url/decode-reject.json#0","op":"b64url.decode","status":"pass","actual":{"ok":false,"error":"InvalidBase64"}},
{"id":"jwe/zip/decrypt.json#0","op":"jwe.decrypt","status":"skipped","reason":"feature:deflate"},
{"id":"jwe/compact/exact.json#0","op":"jwe.encrypt","status":"skipped","reason":"feature:fixed-rng"}
]}'

# The runner names of ADR 0034 §2, from the schema's runner enum, one per line.
runner_names() {
  node -e 'for (const r of JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).properties.runner.enum) console.log(r)' \
    "$repo/conformance/schema/results.schema.json" || lib_die "could not read the runner enum"
}

# new_case <name>: an empty results directory in $case_dir.
new_case() {
  case_dir="$scratch/case-$1"
  rm -rf "$case_dir"
  mkdir -p "$case_dir" || lib_die "could not create $case_dir"
}

# edit <text> <old> <new>: prints <text> with the one occurrence of <old> replaced by <new>.
edit() {
  # shellcheck disable=SC2016 # a JavaScript template literal, not a shell expansion
  node -e '
const [text, old, replacement] = process.argv.slice(1);
const count = text.split(old).length - 1;
if (count !== 1) { console.error(`expected exactly one ${JSON.stringify(old)}, found ${count}`); process.exit(1); }
process.stdout.write(text.replace(old, () => replacement));
' "$1" "$2" "$3" || lib_die "edit failed"
}

# as_runner <runner> [text]: the text (default REFERENCE) with its runner set to <runner>.
as_runner() {
  edit "${2:-$REFERENCE}" '"runner":"rust-core"' "\"runner\":\"$1\""
}

# put <file> <text>: writes a results file into the case directory.
put() {
  printf '%s\n' "$2" >"$case_dir/$1" || lib_die "could not write $1"
}

# run_parity: runs the check on the case directory into $scratch/out; sets $rc.
run_parity() {
  rc=0
  "$parity" "$case_dir" >"$scratch/out" 2>&1 || rc=$?
}

# expect_pass <description> [ERE...]: the check exits 0, prints no FAIL line, and its output
# matches every given ERE.
expect_pass() {
  local description=$1 pattern missing=""
  shift
  tests_run=$((tests_run + 1))
  run_parity
  for pattern in "$@"; do
    grep -Eq -- "$pattern" "$scratch/out" || missing="$missing /$pattern/"
  done
  if [ "$rc" -eq 0 ] && ! grep -q '^FAIL: ' "$scratch/out" && [ -z "$missing" ]; then
    echo "ok   - $description: passes"
  else
    echo "FAIL - $description: exit $rc (expected 0), FAIL lines or missing output:$missing"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

# expect_fail <description> <required ERE> <ERE every FAIL line must match>: the check exits 1,
# its output matches the required pattern, and every FAIL line matches the second one.
expect_fail() {
  local bad
  tests_run=$((tests_run + 1))
  run_parity
  bad=$(grep '^FAIL: ' "$scratch/out" | grep -Ev -- "$3" || true)
  if [ "$rc" -eq 1 ] && grep -Eq -- "$2" "$scratch/out" && [ -z "$bad" ]; then
    echo "ok   - $1: fails as expected"
    grep -E -- "$2" "$scratch/out" | head -3 | sed 's/^/       /'
  else
    echo "FAIL - $1: exit $rc (expected 1), wanted output matching /$2/ and only FAIL lines matching /$3/"
    sed 's/^/       /' "$scratch/out"
    tests_failed=$((tests_failed + 1))
  fi
}

# finish: prints the summary and exits non-zero if any case failed.
finish() {
  echo "$((tests_run - tests_failed))/$tests_run cases passed"
  [ "$tests_failed" -eq 0 ]
}
