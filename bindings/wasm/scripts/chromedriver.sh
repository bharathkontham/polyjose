#!/usr/bin/env bash
# Prints the path of a chromedriver for the installed Google Chrome (feature 0006 T02), for
# `wasm-pack test --headless --chrome --chromedriver <path>` in bindings/wasm/test.sh.
#
#   bindings/wasm/scripts/chromedriver.sh
#
# Why: wasm-pack downloads the newest chromedriver, which refuses a Chrome of another major
# version ("session not created"; 0006 research §7, measured with chromedriver 157 and
# Chrome 156). ChromeDriver supports exactly its own Chrome major version.
#
#   1. Chrome: $CHROME if set, else Google Chrome's standard macOS location or google-chrome /
#      google-chrome-stable on PATH; its version from `--version`. No Chrome: prints
#      `SKIPPED (<reason>)` and exits 0, so the caller skips the Chrome run.
#   2. A cached driver: target/chromedriver-<version>/chromedriver at the repository root, the
#      newest whose own `--version` has Chrome's major version, preferring Chrome's exact build
#      (major.minor.build). No network is used when one exists.
#   3. Otherwise a download from Chrome for Testing
#      (https://github.com/GoogleChromeLabs/chrome-for-testing#json-api-endpoints): the newest patch
#      of Chrome's build from latest-patch-versions-per-build-with-downloads.json, or else the
#      newest of its milestone from latest-versions-per-milestone-with-downloads.json, for this
#      platform. If the JSON entry carries a `sha256`, the archive must match it; the endpoint
#      publishes none today (checked 2026-11-07: download entries are only `platform` and `url`), and
#      the script says so on stderr, so integrity then rests on HTTPS to storage.googleapis.com. The
#      driver must then report the same major version. It is unpacked into
#      target/chromedriver-<version>/ and moved there only when complete.
#
# The driver is a test-time tool in target/, never a dependency of any package. Exit status: 0 a
# path or SKIPPED was printed; 1 Chrome is installed but no matching driver could be found or
# fetched (the Chrome run must not be skipped then). Needs curl, unzip and python3 for a download.
# Runs on macOS /bin/bash 3.2 and Linux bash.
set -euo pipefail
export LC_ALL=C

me=chromedriver.sh
die() { echo "$me: $*" >&2; exit 1; }
repo=$(cd "$(dirname "$0")/../../.." && pwd -P) || exit 1
cft=https://googlechromelabs.github.io/chrome-for-testing

# --- 1. Chrome ---------------------------------------------------------------------------------

chrome=${CHROME:-}
if [ -z "$chrome" ]; then
  for candidate in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "$HOME/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    if [ -x "$candidate" ]; then chrome=$candidate; break; fi
  done
fi
if [ -z "$chrome" ]; then
  for name in google-chrome google-chrome-stable; do
    if command -v "$name" >/dev/null 2>&1; then chrome=$(command -v "$name"); break; fi
  done
fi
if [ -z "$chrome" ]; then
  echo "SKIPPED (no Google Chrome found: set CHROME or install it)"
  exit 0
fi
[ -x "$chrome" ] || die "CHROME=$chrome is not an executable"
chrome_version=$("$chrome" --version 2>/dev/null | sed -n 's/^.* \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*$/\1/p' | head -n 1)
[ -n "$chrome_version" ] || die "could not read the version of $chrome"
major=${chrome_version%%.*}
build=${chrome_version%.*}
echo "$me: Chrome $chrome_version ($chrome)" >&2

# The four-part version a chromedriver reports, or nothing.
driver_version() {
  "$1" --version 2>/dev/null | sed -n 's/^ChromeDriver \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*$/\1/p' | head -n 1
}

# --- 2. A cached driver --------------------------------------------------------------------------

best=""; best_rank=0
for dir in "$repo"/target/chromedriver-"$major".*; do
  [ -x "$dir/chromedriver" ] || continue
  v=$(driver_version "$dir/chromedriver")
  [ "${dir##*/chromedriver-}" = "$v" ] || continue # the directory must name what it holds
  [ "${v%%.*}" = "$major" ] || continue
  rank=1; [ "${v%.*}" = "$build" ] && rank=2
  if [ "$rank" -gt "$best_rank" ] || { [ "$rank" -eq "$best_rank" ] && [ "$(printf '%s\n%s\n' "$best" "$v" | sort -t. -k4,4n | tail -n 1)" = "$v" ]; }; then
    best=$v; best_rank=$rank
  fi
done
if [ -n "$best" ]; then
  echo "$me: cached chromedriver $best" >&2
  echo "$repo/target/chromedriver-$best/chromedriver"
  exit 0
fi

# --- 3. Download from Chrome for Testing ---------------------------------------------------------

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) platform=mac-arm64 ;;
  Darwin-x86_64) platform=mac-x64 ;;
  Linux-x86_64) platform=linux64 ;;
  Linux-aarch64 | Linux-arm64) platform=linux-arm64 ;;
  *) die "no Chrome for Testing chromedriver for $(uname -s) $(uname -m)" ;;
esac
for tool in curl unzip python3; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH (needed to download chromedriver)"
done

mkdir -p "$repo/target" || die "could not create $repo/target"
work=$(mktemp -d "$repo/target/.chromedriver.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$work"' EXIT

# lookup <json file> <section> <key>: prints "<version> <url> <sha256 or ->" for this platform's
# chromedriver, or nothing. The JSON is downloaded data: read with python3 -I, never executed.
lookup() {
  python3 -I -c '
import json, sys
path, section, key, platform = sys.argv[1:5]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
entry = data.get(section, {}).get(key)
if not isinstance(entry, dict):
    sys.exit(0)
for d in entry.get("downloads", {}).get("chromedriver", []):
    if d.get("platform") == platform:
        print(entry.get("version", ""), d.get("url", ""), d.get("sha256") or "-")
        break
' "$1" "$2" "$3" "$platform"
}

found=""
for spec in "latest-patch-versions-per-build-with-downloads.json builds $build" \
  "latest-versions-per-milestone-with-downloads.json milestones $major"; do
  set -- $spec
  curl -fsS --proto '=https' --tlsv1.2 --max-time 60 -o "$work/index.json" "$cft/$1" \
    || die "could not download $cft/$1"
  found=$(lookup "$work/index.json" "$2" "$3")
  [ -n "$found" ] && break
done
[ -n "$found" ] || die "Chrome for Testing lists no chromedriver for Chrome $build or milestone $major on $platform"
set -- $found
version=$1; url=$2; sha256=$3
case $version in
  "$major".*) ;;
  *) die "Chrome for Testing offered chromedriver $version for Chrome $chrome_version" ;;
esac
case $url in
  https://storage.googleapis.com/chrome-for-testing-public/*) ;;
  *) die "unexpected download URL $url" ;;
esac

echo "$me: downloading chromedriver $version ($platform)" >&2
curl -fsS --proto '=https' --tlsv1.2 --max-time 300 -o "$work/chromedriver.zip" "$url" || die "could not download $url"
if [ "$sha256" != "-" ]; then
  got=$(python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$work/chromedriver.zip")
  [ "$got" = "$sha256" ] || die "SHA-256 mismatch for $url: got $got, the JSON says $sha256"
  echo "$me: SHA-256 verified" >&2
else
  echo "$me: the Chrome for Testing JSON publishes no SHA-256 for $url; relying on HTTPS" >&2
fi
mkdir "$work/unpacked"
unzip -q "$work/chromedriver.zip" -d "$work/unpacked" || die "could not unpack $url"
binary="$work/unpacked/chromedriver-$platform/chromedriver"
[ -f "$binary" ] || die "the archive has no chromedriver-$platform/chromedriver"
chmod +x "$binary"
got_version=$(driver_version "$binary")
[ "$got_version" = "$version" ] || die "the downloaded chromedriver reports ${got_version:-nothing}, expected $version"

dest="$repo/target/chromedriver-$version"
mkdir "$work/dest"
mv "$binary" "$work/dest/chromedriver"
rm -rf "$dest"
mv "$work/dest" "$dest" || die "could not move the driver to $dest"
echo "$dest/chromedriver"
