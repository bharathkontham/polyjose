# shellcheck shell=bash
# Shared helpers of the release scripts (feature 0012 H3; ADR 0037 §2-§3, ADR 0038 §1-§2). Sourced,
# not run. Bash 3.2 compatible (macOS /bin/bash) and Linux bash.
#
#   rel_die <msg>               print "<me>: FAIL: <msg>" on stderr and exit 1
#   rel_sha256 <file>           the file's SHA-256, lowercase hex (FIPS 180-4), from sha256sum or
#                               shasum -a 256, whichever the host has
#   rel_sign <file>             write <file>.asc, a detached ASCII-armored OpenPGP signature
#                               (RFC 9580 §5.2) by the primary key "$RELEASE_GPG_FPR!", then
#                               verify it (rel_verify_sig)
#   rel_verify_sig <sig> <file> <fpr>
#                               the signature verifies and was made by the primary key <fpr>
#                               itself (gpg's VALIDSIG status line: its first field is the key
#                               that signed, its last the primary key; both must be <fpr>)
#
# Signing reads the key from the gpg home in $GNUPGHOME (the workflow imports it there) and its
# passphrase from $GPG_SIGNING_KEY_PASSWORD, handed to gpg on a pipe (--passphrase-fd 0, with
# --batch --pinentry-mode loopback). printf is a shell builtin, so the passphrase is never in a
# process argument list, and nothing here prints it. The trailing `!` of --local-user makes gpg
# use the primary key even if a signing subkey exists: Maven Central verifies against the primary
# key (ADR 0038 context 3; owner, 2026-11-08).

rel_die() { printf '%s: FAIL: %s\n' "${me:-release}" "$*" >&2; exit 1; }

rel_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

rel_verify_sig() {
  local sig=$1 file=$2 fpr=$3 status
  status=$(gpg --batch --no-tty --status-fd 1 --verify "$sig" "$file" 2>/dev/null) || return 1
  printf '%s\n' "$status" | awk -v fpr="$fpr" '
    $1 == "[GNUPG:]" && $2 == "VALIDSIG" && $3 == fpr && $NF == fpr { ok = 1 }
    END { exit ok ? 0 : 1 }'
}

rel_sign() {
  local file=$1
  [ -n "${RELEASE_GPG_FPR:-}" ] || rel_die "RELEASE_GPG_FPR is not set (the signing key's fingerprint)"
  [ -n "${GPG_SIGNING_KEY_PASSWORD:-}" ] || rel_die "GPG_SIGNING_KEY_PASSWORD is not set"
  rm -f "$file.asc"
  printf '%s' "$GPG_SIGNING_KEY_PASSWORD" |
    gpg --batch --no-tty --quiet --pinentry-mode loopback --passphrase-fd 0 \
      --local-user "${RELEASE_GPG_FPR}!" --armor --detach-sign --output "$file.asc" "$file" ||
    rel_die "gpg could not sign ${file##*/}"
  rel_verify_sig "$file.asc" "$file" "$RELEASE_GPG_FPR" ||
    rel_die "the signature of ${file##*/} does not verify as made by the primary key $RELEASE_GPG_FPR"
}
