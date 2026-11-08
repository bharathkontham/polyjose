#!/usr/bin/env bash
# Verifies downloaded draft-release assets before anything is published (feature 0012 H3; ADR 0038
# §1 "Input check"): SHA256SUMS.asc is a valid signature over SHA256SUMS by the release key's
# primary key, and SHA256SUMS lists every asset in the directory exactly once, with its SHA-256.
#
#   scripts/release/verify-draft.sh [--allow-unsigned] <dir> <tag> <public-key> <fingerprint>
#
#   <dir>          the assets (`gh release download <tag> --dir <dir>`), no subdirectories
#   <tag>          vX.Y.Z, or dryrun-vX.Y.Z[-N] (a disposable draft for publish.yml dry runs,
#                  ADR 0038 §3 item 5)
#   <public-key>   the committed public key, .github/keys/polyjose-release.asc
#   <fingerprint>  the release key's primary fingerprint (40 hex digits; repository variable
#                  GPG_FINGERPRINT)
#   --allow-unsigned
#                  a missing SHA256SUMS.asc is accepted, for a dryrun- tag only (a candidate
#                  build's assets are unsigned); a present one is always verified. publish.yml
#                  passes it only together with dry_run: true.
#
# Fails (exit 1) when: the public key file is missing (the owner has not committed it yet), it
# holds anything but exactly one public key whose primary fingerprint is <fingerprint>, or a
# secret key; the signature is missing (unless allowed above), bad, or made by another key or a
# subkey; SHA256SUMS has a malformed line, a path, a duplicate, a name not in <dir>, or a wrong
# digest; or <dir> holds a file SHA256SUMS does not list. Exit 2: usage.
# gpg runs in a temporary home, so the runner's keyring is never read or changed.
set -euo pipefail
export LC_ALL=C
me=verify-draft
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/scripts/release/lib.sh"

usage() { echo "usage: scripts/release/verify-draft.sh [--allow-unsigned] <dir> <tag> <public-key> <fingerprint>" >&2; exit 2; }
allow_unsigned=0
if [ "${1:-}" = --allow-unsigned ]; then allow_unsigned=1; shift; fi
[ $# -eq 4 ] || usage
dir=$1 tag=$2 key=$3 fpr=$4

[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ || $tag =~ ^dryrun-v[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?$ ]] ||
  rel_die "tag '$tag' is neither vX.Y.Z nor dryrun-vX.Y.Z[-N]"
[[ $fpr =~ ^[0-9A-F]{40}$ ]] || rel_die "the fingerprint must be 40 upper-case hex digits (repository variable GPG_FINGERPRINT), got '$fpr'"
[ -d "$dir" ] || rel_die "no asset directory $dir"
[ -f "$key" ] || rel_die "$key is missing: the release public key has not been committed yet (ADR 0038 §2; the owner provides it). Nothing can be verified, so nothing is published."
[ -f "$dir/SHA256SUMS" ] || rel_die "the draft has no SHA256SUMS"

echo "==> $me: $tag ($dir)"
GNUPGHOME=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-verify-gpg.XXXXXX")
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
chmod 700 "$GNUPGHOME"

# The key file: exactly one public key, no secret key material, primary fingerprint = <fpr>.
gpg --batch --no-tty --quiet --import "$key" 2>/dev/null || rel_die "gpg cannot import $key"
[ -z "$(gpg --batch --no-tty --with-colons --list-secret-keys 2>/dev/null)" ] ||
  rel_die "$key contains secret key material; it must be the public key only"
primaries=$(gpg --batch --no-tty --with-colons --fingerprint 2>/dev/null |
  awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }')
[ "$primaries" = "$fpr" ] || rel_die "$key must hold exactly the key $fpr, it holds: $(printf '%s ' "$primaries")"
echo "  ok   $key: the public key $fpr"

# The signature.
if [ -f "$dir/SHA256SUMS.asc" ]; then
  rel_verify_sig "$dir/SHA256SUMS.asc" "$dir/SHA256SUMS" "$fpr" ||
    rel_die "SHA256SUMS.asc is not a valid signature of SHA256SUMS by the primary key $fpr"
  echo "  ok   SHA256SUMS.asc: a good signature by the primary key $fpr"
elif [ "$allow_unsigned" -eq 1 ] && [[ $tag == dryrun-* ]]; then
  echo "  WARN SHA256SUMS.asc is missing; accepted for the dry-run draft $tag only"
else
  rel_die "the draft has no SHA256SUMS.asc (only a dryrun- tag with --allow-unsigned may lack it)"
fi

# SHA256SUMS: `<64 hex>  <name>` lines, each name a plain file of <dir>, once; every file listed.
listed=$(awk -v me="$me" '
  # No {64} interval: not every awk (older mawk) supports it.
  substr($0, 1, 64) !~ /^[0-9a-f]+$/ || substr($0, 65, 2) != "  " || substr($0, 67) !~ /^[A-Za-z0-9][A-Za-z0-9._+-]*$/ { printf "%s: FAIL: SHA256SUMS line %d is malformed: %s\n", me, NR, $0 > "/dev/stderr"; bad = 1; next }
  { name = substr($0, 67); if (seen[name]++) { printf "%s: FAIL: SHA256SUMS lists %s twice\n", me, name > "/dev/stderr"; bad = 1 } print name }
  END { exit bad }' "$dir/SHA256SUMS") || exit 1
[ -n "$listed" ] || rel_die "SHA256SUMS is empty"
present=$(cd "$dir" && find . -mindepth 1 -maxdepth 1 | sed 's|^\./||' | grep -vxE 'SHA256SUMS(\.asc)?' | sort)
[ -z "$(cd "$dir" && find . -mindepth 1 ! -type f)" ] || rel_die "$dir holds something other than plain files"
[ "$(printf '%s\n' "$listed" | sort)" = "$present" ] || rel_die "SHA256SUMS does not list exactly the assets:
$(diff <(printf '%s\n' "$listed" | sort) <(printf '%s\n' "$present") || true)"
while IFS= read -r line; do
  want=${line%%  *}
  name=${line#*  }
  [ "$(rel_sha256 "$dir/$name")" = "$want" ] || rel_die "$name does not match its SHA256SUMS digest"
done <"$dir/SHA256SUMS"
echo "  ok   SHA256SUMS: $(printf '%s\n' "$listed" | grep -c .) assets, each digest matches, nothing unlisted"
echo "$me: PASS ($tag)"
