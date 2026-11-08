#!/usr/bin/env bash
# The Maven Central step of publish.yml (feature 0012 H3; ADR 0038 §1 step 3, option 3a).
#
#   scripts/release/maven-central.sh check [--allow-unsigned] <zip> <version> <public-key> <fingerprint>
#       The bundle's layout and signatures, offline (also the whole Maven step of a dry run):
#       exactly dev/polyjose/polyjose/<v>/ and dev/polyjose/polyjose-jvm/<v>/ with the AAR, the
#       jar and both POMs; every file other than a checksum or a signature has a matching .md5 and
#       .sha1 and an .asc that verifies as made by the primary key <fingerprint> of <public-key>.
#       --allow-unsigned (dry runs of a dryrun- draft only) accepts a bundle without any .asc.
#   scripts/release/maven-central.sh upload <zip> <version>
#       Uploads the bundle to the Central Portal with publishingType=USER_MANAGED, then polls the
#       deployment until VALIDATED and prints its id. It never publishes: the owner presses
#       Publish in the Portal (Gate 3). Needs MAVEN_CENTRAL_USERNAME and MAVEN_CENTRAL_PASSWORD
#       (the Portal user token pair) in the environment.
#
# Portal API (https://central.sonatype.org/publish/publish-portal-api/):
#   POST /api/v1/publisher/upload?name=<n>&publishingType=USER_MANAGED, multipart field `bundle`,
#     header `Authorization: Bearer base64(<username>:<password>)`; the response body is the
#     deployment id.
#   POST /api/v1/publisher/status?id=<id> returns JSON whose deploymentState is PENDING,
#     VALIDATING, VALIDATED, PUBLISHING, PUBLISHED or FAILED.
# The Authorization header reaches curl through a config on stdin (-K -), never through its
# argument list, and is never printed.
set -euo pipefail
export LC_ALL=C
me=maven-central
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/scripts/release/lib.sh"

portal=https://central.sonatype.com/api/v1/publisher
usage() {
  echo "usage: scripts/release/maven-central.sh check [--allow-unsigned] <zip> <version> <public-key> <fingerprint>" >&2
  echo "       scripts/release/maven-central.sh upload <zip> <version>" >&2
  exit 2
}

check() {
  local allow_unsigned=0 zip v key fpr work files artifacts a alg got signed=0
  if [ "${1:-}" = --allow-unsigned ]; then allow_unsigned=1; shift; fi
  [ $# -eq 4 ] || usage
  zip=$1 v=$2 key=$3 fpr=$4
  [ -f "$zip" ] || rel_die "no bundle $zip"
  [ -f "$key" ] || rel_die "$key is missing: the release public key has not been committed yet (ADR 0038 §2)"
  work=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-maven-check.XXXXXX")
  # A home of its own, as short as verify-draft.sh's: gpg's socket path has a length limit.
  GNUPGHOME=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-maven-gpg.XXXXXX")
  export GNUPGHOME
  chmod 700 "$GNUPGHOME"
  # shellcheck disable=SC2064 # expand now: the trap must remove this run's directories
  trap "rm -rf '$work' '$GNUPGHOME'" EXIT
  gpg --batch --no-tty --quiet --import "$key" 2>/dev/null || rel_die "gpg cannot import $key"

  files=$(zipinfo -1 "$zip" | grep -v '/$' | sort)
  unexpected=$(printf '%s\n' "$files" | grep -vE "^dev/polyjose/polyjose(-jvm)?/$v/[^/]+$" || true)
  [ -z "$unexpected" ] || rel_die "unexpected entries in the bundle:
$unexpected"
  mkdir "$work/x"
  unzip -q "$zip" -d "$work/x"
  for f in "dev/polyjose/polyjose/$v/polyjose-$v.aar" "dev/polyjose/polyjose/$v/polyjose-$v.pom" \
    "dev/polyjose/polyjose-jvm/$v/polyjose-jvm-$v.jar" "dev/polyjose/polyjose-jvm/$v/polyjose-jvm-$v.pom"; do
    [ -f "$work/x/$f" ] || rel_die "the bundle has no $f"
  done
  artifacts=$(printf '%s\n' "$files" | grep -vE '\.(md5|sha1|sha256|sha512|asc)$')
  for a in $artifacts; do
    for alg in md5 sha1; do
      [ -f "$work/x/$a.$alg" ] || rel_die "$a has no .$alg"
      got=$(python3 -I -c 'import hashlib, sys; print(hashlib.new(sys.argv[2], open(sys.argv[1], "rb").read()).hexdigest())' "$work/x/$a" "$alg")
      [ "$(tr -d '[:space:]' <"$work/x/$a.$alg")" = "$got" ] || rel_die "$a.$alg does not match"
    done
    if [ -f "$work/x/$a.asc" ]; then
      rel_verify_sig "$work/x/$a.asc" "$work/x/$a" "$fpr" || rel_die "$a.asc is not a good signature by the primary key $fpr"
      signed=$((signed + 1))
    fi
  done
  local count
  count=$(printf '%s\n' "$artifacts" | grep -c .)
  if [ "$signed" -eq "$count" ]; then
    echo "$me: check PASS ($count artifacts, each with .md5, .sha1 and a good .asc by $fpr)"
  elif [ "$signed" -eq 0 ] && [ "$allow_unsigned" -eq 1 ]; then
    echo "$me: check PASS, UNSIGNED ($count artifacts with .md5 and .sha1; no .asc, accepted for a dry-run draft only)"
  else
    rel_die "$signed of $count artifacts are signed; every one must be"
  fi
}

upload() {
  [ $# -eq 2 ] || usage
  local zip=$1 v=$2 auth id state i body
  [ -f "$zip" ] || rel_die "no bundle $zip"
  [ -n "${MAVEN_CENTRAL_USERNAME:-}" ] && [ -n "${MAVEN_CENTRAL_PASSWORD:-}" ] ||
    rel_die "MAVEN_CENTRAL_USERNAME and MAVEN_CENTRAL_PASSWORD must be set (the Central Portal user token)"
  auth=$(printf '%s:%s' "$MAVEN_CENTRAL_USERNAME" "$MAVEN_CENTRAL_PASSWORD" | base64 | tr -d '\n')
  curl_portal() { # curl_portal <curl args>...: one Portal request with the Authorization header from stdin
    printf 'header = "Authorization: Bearer %s"\n' "$auth" |
      curl --proto '=https' --tlsv1.2 -sS --fail-with-body --retry 3 --max-time 600 -K - "$@"
  }
  echo "==> $me: upload ${zip##*/} (publishingType=USER_MANAGED)"
  id=$(curl_portal -X POST -F "bundle=@$zip" "$portal/upload?name=polyjose-$v&publishingType=USER_MANAGED") ||
    rel_die "the upload failed: $id"
  [[ $id =~ ^[0-9a-fA-F-]{8,64}$ ]] || rel_die "unexpected upload response: $id"
  echo "  deployment id: $id"
  for i in $(seq 1 90); do
    body=$(curl_portal -X POST "$portal/status?id=$id") || rel_die "the status request failed: $body"
    state=$(printf '%s' "$body" | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["deploymentState"])')
    echo "  [$i] $state"
    case $state in
      VALIDATED)
        echo "$me: VALIDATED: deployment $id is ready; the owner publishes it in the Central Portal (Gate 3)"
        return 0 ;;
      PENDING | VALIDATING) sleep 20 ;;
      *) printf '%s\n' "$body"; rel_die "deployment $id is $state" ;;
    esac
  done
  rel_die "deployment $id is not VALIDATED after 30 minutes"
}

[ $# -ge 1 ] || usage
cmd=$1
shift
case $cmd in
  check) check "$@" ;;
  upload) upload "$@" ;;
  *) usage ;;
esac
