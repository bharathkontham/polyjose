#!/usr/bin/env bash
# Checks the glibc floor of a gnu @polyjose/node addon (feature 0007 F04; review-code.md SF-2):
# the highest GLIBC_x.y symbol version the addon requires must be at or below <floor>, or the
# addon would not load on a distribution whose glibc is the floor (the loader then reports
# "Cannot find native binding"). scripts/ci-build.sh runs it on the gnu targets after the build,
# with the floor the README states (2.28: the manylinux_2_28 build images, and Node 22's own
# Linux floor).
#
# Usage: scripts/glibc-floor.sh <floor> <addon.node>
#        scripts/glibc-floor.sh --output <floor> <file>
#   floor   <major>.<minor>, for example 2.28
#   addon   read with `readelf --version-info --wide` (GNU binutils), or `objdump -T` when there
#           is no readelf on PATH
#   --output  reads <file>, a recorded output of either tool, instead (test/ci.test.ts runs it on
#           test/fixtures/glibc/)
#
# It reads every GLIBC_<name> token of the output: the version-needs entries (`Name: GLIBC_2.28`)
# and the per-symbol versions (`(GLIBC_2.28)`). Versions of other libraries (libgcc_s's GCC_*,
# libstdc++'s GLIBCXX_*) are not glibc's and are ignored. A numbered version, x.y or x.y.z (the
# x86-64 base version is GLIBC_2.2.5), is compared with the floor as integers, field by field:
# no `sort -V`, which macOS bash 3.2 and BSD sort lack, and no text comparison ("2.9" > "2.28").
#
# Exit status:
#   0  every glibc version is at or below the floor; prints the highest
#   1  a version is above the floor, or a glibc version is not a numbered release: GLIBC_PRIVATE
#      (glibc's internal ABI, which may change between builds of one release), GLIBC_ABI_DT_RELR
#      (written by -z pack-relative-relocs, needs glibc 2.36) or any other name
#   2  fails closed: a usage error, no tool, a tool failure, or no GLIBC_ version at all (not
#      linked against glibc, or an output this script did not understand), never a pass
# Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail

usage() {
  echo "usage: scripts/glibc-floor.sh <floor> <addon.node>" >&2
  echo "       scripts/glibc-floor.sh --output <floor> <readelf or objdump output file>" >&2
  exit 2
}
closed() { echo "glibc-floor.sh: $*" >&2; exit 2; }
fail() { echo "glibc-floor.sh: $*" >&2; exit 1; }

from_output=false
if [ "${1:-}" = --output ]; then
  from_output=true
  shift
fi
[ $# -eq 2 ] || usage
floor=$1
file=$2

# key <x.y[.z]>: the version as one integer, x*1000000 + y*1000 + z. Each field is at most three
# digits and read as decimal (10#: a leading zero is not octal). Fails on anything else.
version_re='^([0-9]{1,3})\.([0-9]{1,3})(\.([0-9]{1,3}))?$'
key() {
  [[ $1 =~ $version_re ]] || return 1
  echo $((10#${BASH_REMATCH[1]} * 1000000 + 10#${BASH_REMATCH[2]} * 1000 + 10#${BASH_REMATCH[4]:-0}))
}

floor_re='^[0-9]{1,3}\.[0-9]{1,3}$'
[[ $floor =~ $floor_re ]] || closed "floor '$floor' is not <major>.<minor> (for example 2.28)"
floor_key=$(key "$floor")

[ -f "$file" ] || closed "$file: no such file"
hint=
if [ "$from_output" = true ]; then
  out=$(cat "$file")
elif command -v readelf >/dev/null 2>&1; then
  out=$(readelf --version-info --wide "$file") || closed "readelf --version-info --wide $file failed"
  hint=" (\`objdump -T $file\` names the symbols)"
elif command -v objdump >/dev/null 2>&1; then
  out=$(objdump -T "$file") || closed "objdump -T $file failed"
  hint=" (\`objdump -T $file\` names the symbols)"
else
  closed "neither readelf nor objdump is on PATH (GNU binutils)"
fi

# Every distinct GLIBC_<name> token; grep exits 1 when there is none, which is checked below.
names=$(printf '%s\n' "$out" | grep -oE 'GLIBC_[A-Za-z0-9_.]+' | LC_ALL=C sort -u) || names=

max=
max_key=-1
above=
unnumbered=
for name in $names; do
  version=${name#GLIBC_}
  if k=$(key "$version"); then
    if [ "$k" -gt "$max_key" ]; then
      max_key=$k
      max=$version
    fi
    if [ "$k" -gt "$floor_key" ]; then above="$above $name"; fi
  else
    unnumbered="$unnumbered $name"
  fi
done

[ -n "$max" ] || [ -n "$unnumbered" ] ||
  closed "$file: no GLIBC_ symbol version found (not linked against glibc, or an output this script does not read)"
[ -z "$unnumbered" ] ||
  fail "$file requires glibc versions that are not numbered releases:$unnumbered (GLIBC_PRIVATE is glibc's internal ABI; GLIBC_ABI_DT_RELR needs glibc 2.36)"
[ -z "$above" ] ||
  fail "$file requires GLIBC_$max, above the floor $floor:$above$hint"
echo "glibc-floor.sh: $file: highest GLIBC_$max (floor $floor): OK"
