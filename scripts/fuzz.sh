#!/usr/bin/env bash
# Runs polyjose's cargo-fuzz targets (fuzz/, feature 0012 H1, ADR 0036) for a fixed time each.
#
# Usage: scripts/fuzz.sh [--seconds N] [target ...]
#   With no targets it runs all eight. N defaults to 60 seconds per target.
#
# Setup, once:
#   cargo install cargo-fuzz --version '=0.13.2' --locked
#   rustup toolchain install "$(cat fuzz/nightly-toolchain)"
#
# Each target starts from fuzz/corpus/<target> (git-ignored), into which the committed seeds of
# fuzz/seeds/<target> are copied first, so the seeds themselves never grow. libFuzzer's output goes
# to fuzz/artifacts/<target>/run.log, not to the terminal: a crash input or stack trace is a
# vulnerability report until it is fixed (ADR 0036 §6). The script prints one line per target,
#   <target>: ok
#   <target>: CRASH <artifact path>
# and exits non-zero if any target crashed (1), or on a usage or setup error (2).
set -eu

all_targets="json jose_header jwk der_pem jwt jws jwe inflate"

usage() {
  sed -n '4,5p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

seconds=60
targets=""
while [ $# -gt 0 ]; do
  case $1 in
    --seconds)
      [ $# -ge 2 ] || usage
      seconds=$2
      shift 2
      ;;
    --seconds=*)
      seconds=${1#--seconds=}
      shift
      ;;
    -h | --help) usage ;;
    -*)
      echo "fuzz.sh: unknown option $1" >&2
      usage
      ;;
    *)
      case " $all_targets " in
        *" $1 "*) targets="$targets $1" ;;
        *)
          echo "fuzz.sh: unknown target $1 (targets: $all_targets)" >&2
          exit 2
          ;;
      esac
      shift
      ;;
  esac
done
case $seconds in
  '' | *[!0-9]* | 0)
    echo "fuzz.sh: --seconds needs a positive whole number, got '$seconds'" >&2
    exit 2
    ;;
esac
[ -n "$targets" ] || targets=$all_targets

root=$(cd "$(dirname "$0")/.." && pwd)
fuzz_dir=$root/fuzz
toolchain=$(cat "$fuzz_dir/nightly-toolchain")

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "fuzz.sh: cargo-fuzz is not installed: cargo install cargo-fuzz --version '=0.13.2' --locked" >&2
  exit 2
fi
if ! rustup run "$toolchain" rustc --version >/dev/null 2>&1; then
  echo "fuzz.sh: toolchain $toolchain is not installed: rustup toolchain install $toolchain" >&2
  exit 2
fi

cd "$root"
mkdir -p "$fuzz_dir/artifacts"
build_log=$fuzz_dir/artifacts/build.log
if ! cargo "+$toolchain" fuzz build --fuzz-dir fuzz >"$build_log" 2>&1; then
  echo "fuzz.sh: cargo fuzz build failed; see $build_log" >&2
  exit 2
fi

crashed=0
for t in $targets; do
  corpus=$fuzz_dir/corpus/$t
  artifacts=$fuzz_dir/artifacts/$t
  log=$artifacts/run.log
  mkdir -p "$corpus" "$artifacts"
  cp -R "$fuzz_dir/seeds/$t/." "$corpus/"
  if cargo "+$toolchain" fuzz run --fuzz-dir fuzz "$t" "$corpus" -- \
    "-max_total_time=$seconds" "-dict=$fuzz_dir/jose.dict" -max_len=65536 \
    -rss_limit_mb=2048 -timeout=10 -print_final_stats=1 >"$log" 2>&1; then
    echo "$t: ok"
  else
    crashed=1
    artifact=$(sed -n 's/.*Test unit written to \(.*\)$/\1/p' "$log" | tail -n 1)
    echo "$t: CRASH ${artifact:-$log}"
  fi
done
exit "$crashed"
