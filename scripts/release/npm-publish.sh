#!/usr/bin/env bash
# The npm step of publish.yml (feature 0012 H3; ADR 0038 §1 step 2): publishes the draft's 10 npm
# tarballs as they are, never a fresh pack, in this order: the 8 @polyjose/node-<platform> packages
# (bindings/node/npm/*/), then @polyjose/node (whose optional dependencies they are), then
# @polyjose/wasm. ADR 0038 says 11 packages; the repository has 10 (decisions.md, 2026-11-08, H3).
#
#   scripts/release/npm-publish.sh <dir> <version>
#
#   <dir>      the verified draft assets (scripts/release/verify-draft.sh has passed on them)
#   <version>  X.Y.Z
#
# Environment:
#   DRY_RUN=true|false   true: `npm publish --dry-run` for each tarball (uploads nothing)
#   BOOTSTRAP=true|false true: authenticate with NODE_AUTH_TOKEN (the NPM_BOOTSTRAP_TOKEN secret,
#                        the first release only; npm whoami proves it, also in a dry run). false:
#                        npm trusted publishing over GitHub OIDC (npm >= 11.5.1, `id-token: write`);
#                        NODE_AUTH_TOKEN must then be empty.
#   NODE_AUTH_TOKEN      read by npm from a temporary user config holding the literal
#                        `${NODE_AUTH_TOKEN}` (npm expands it), so the token is never written to a
#                        file or a command line, and never printed.
#
# For each tarball: its package/package.json must name the expected package at <version>. If
# <name>@<version> is already on the registry, its dist.integrity must be the tarball's sha512
# (then it is skipped, so a re-run after a partial failure is safe); other bytes fail. Every
# publish uses --access public, --provenance and --ignore-scripts (npm docs, "Generating provenance statements";
# trusted publishing adds provenance itself). After a real publish, npm view must report each
# version. Exit 1 on any failure, 2 on usage.
set -euo pipefail
export LC_ALL=C
me=npm-publish
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/scripts/release/lib.sh"

[ $# -eq 2 ] || { echo "usage: scripts/release/npm-publish.sh <dir> <version>" >&2; exit 2; }
dir=$(cd "$1" && pwd -P) || rel_die "no directory $1"
v=$2
[[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || rel_die "'$v' is not X.Y.Z"
case ${DRY_RUN:-} in true | false) ;; *) rel_die "DRY_RUN must be true or false" ;; esac
case ${BOOTSTRAP:-} in true | false) ;; *) rel_die "BOOTSTRAP must be true or false" ;; esac
registry=https://registry.npmjs.org/

work=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-npm-publish.XXXXXX")
trap 'rm -rf "$work"' EXIT
# A user config of our own (no ~/.npmrc), and a global one that is empty.
: >"$work/global.npmrc"
if [ "$BOOTSTRAP" = true ]; then
  [ -n "${NODE_AUTH_TOKEN:-}" ] || rel_die "bootstrap: NODE_AUTH_TOKEN (NPM_BOOTSTRAP_TOKEN) is empty"
  # Single quotes on purpose: npm expands ${NODE_AUTH_TOKEN} itself when it reads the file.
  # shellcheck disable=SC2016
  printf '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}\n' >"$work/user.npmrc"
else
  [ -z "${NODE_AUTH_TOKEN:-}" ] || rel_die "trusted publishing: NODE_AUTH_TOKEN must be empty"
  unset NODE_AUTH_TOKEN
  : >"$work/user.npmrc"
  if [ "$DRY_RUN" = false ]; then
    [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || rel_die "trusted publishing needs GitHub OIDC (id-token: write)"
  fi
fi
export npm_config_userconfig=$work/user.npmrc npm_config_globalconfig=$work/global.npmrc \
  npm_config_registry=$registry npm_config_cache=$work/cache npm_config_update_notifier=false \
  npm_config_fund=false npm_config_audit=false

npm_version=$(npm --version)
python3 -I -c 'import sys
have = tuple(int(x) for x in sys.argv[1].split("-")[0].split("."))
sys.exit(0 if have >= (11, 5, 1) else 1)' "$npm_version" || rel_die "npm $npm_version is older than 11.5.1 (trusted publishing)"
echo "==> $me: $v from $dir (npm $npm_version; dry run: $DRY_RUN; bootstrap: $BOOTSTRAP)"
if [ "$BOOTSTRAP" = true ]; then
  echo "  npm whoami: $(npm whoami)"
fi

platforms=$(cd "$repo/bindings/node/npm" && for d in */; do echo "${d%/}"; done | sort)
[ "$(printf '%s\n' "$platforms" | grep -c .)" -eq 8 ] || rel_die "bindings/node/npm/ does not hold 8 platform packages"
order=()
for p in $platforms; do order+=("polyjose-node-$p-$v.tgz:@polyjose/node-$p"); done
order+=("polyjose-node-$v.tgz:@polyjose/node" "polyjose-wasm-$v.tgz:@polyjose/wasm")
[ "${#order[@]}" -eq 10 ] || rel_die "expected 10 npm packages, have ${#order[@]}"

integrity() { # integrity <file>: the npm dist.integrity of a tarball (sha512, base64)
  python3 -I -c 'import base64, hashlib, sys
print("sha512-" + base64.b64encode(hashlib.sha512(open(sys.argv[1], "rb").read()).digest()).decode())' "$1"
}

published=()
for entry in "${order[@]}"; do
  file=$dir/${entry%%:*}
  name=${entry#*:}
  [ -f "$file" ] || rel_die "the draft has no ${file##*/}"
  mkdir -p "$work/pkg"
  rm -rf "$work/pkg/package"
  tar -xzf "$file" -C "$work/pkg" package/package.json
  read -r got_name got_version < <(python3 -I -c 'import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print(d["name"], d["version"])' "$work/pkg/package/package.json")
  [ "$got_name" = "$name" ] && [ "$got_version" = "$v" ] || rel_die "${file##*/} is $got_name@$got_version, not $name@$v"
  want=$(integrity "$file")
  if have=$(npm view "$name@$v" dist.integrity 2>"$work/view.err"); then
    if [ -n "$have" ]; then
      [ "$have" = "$want" ] || rel_die "$name@$v is already on npm with other bytes ($have, the draft is $want)"
      echo "  skip $name@$v: already on npm with these bytes"
      continue
    fi
  elif ! grep -q E404 "$work/view.err"; then
    cat "$work/view.err" >&2
    rel_die "npm view $name@$v failed"
  fi
  # --ignore-scripts: no package lifecycle script runs while the npm credentials are present.
  args=(publish "$file" --access public --provenance --ignore-scripts)
  [ "$DRY_RUN" = false ] || args+=(--dry-run)
  echo "  npm ${args[*]##*/}"
  npm "${args[@]}"
  published+=("$name")
done

if [ "$DRY_RUN" = false ]; then
  for name in ${published[@]+"${published[@]}"}; do
    ok=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if [ "$(npm view "$name@$v" version 2>/dev/null || true)" = "$v" ]; then ok=1; break; fi
      sleep 15
    done
    [ "$ok" -eq 1 ] || rel_die "npm view $name@$v does not report the version"
    echo "  ok   npm view $name@$v"
  done
fi
echo "$me: PASS ($([ "$DRY_RUN" = true ] && echo "dry run, ")${#order[@]} packages)"
