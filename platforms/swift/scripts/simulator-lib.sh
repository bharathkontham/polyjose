# shellcheck shell=bash
# Helpers of platforms/swift/scripts/test-simulators.sh (feature 0009 T03), sourced; tested on
# fixtures by platforms/swift/scripts/test-simulator-lib.sh. Needs plutil and shasum (macOS).
# Bash 3.2 compatible. Callers set LC_ALL=C.

# sim_runtime_available <runtimes.json> <runtime identifier>: succeeds when the document
# (`xcrun simctl list runtimes -j`) lists that runtime, by exact identifier, with
# `isAvailable: true`. A missing runtime, an unavailable one or an unreadable document fails.
sim_runtime_available() {
  local json=$1 want=$2 i=0 id
  while id=$(plutil -extract "runtimes.$i.identifier" raw -o - "$json" 2>/dev/null); do
    if [ "$id" = "$want" ]; then
      [ "$(plutil -extract "runtimes.$i.isAvailable" raw -o - "$json" 2>/dev/null)" = true ]
      return
    fi
    i=$((i + 1))
  done
  return 1
}

# sim_iphone_type <runtimes.json> <runtime identifier>: prints the first device type with
# `productFamily: iPhone` among that runtime's `supportedDeviceTypes` (Xcode lists the newest
# first); fails when the runtime is not listed or supports no iPhone.
sim_iphone_type() {
  local json=$1 want=$2 i=0 j=0 id family
  while id=$(plutil -extract "runtimes.$i.identifier" raw -o - "$json" 2>/dev/null); do
    if [ "$id" = "$want" ]; then
      while id=$(plutil -extract "runtimes.$i.supportedDeviceTypes.$j.identifier" raw -o - "$json" 2>/dev/null); do
        family=$(plutil -extract "runtimes.$i.supportedDeviceTypes.$j.productFamily" raw -o - "$json" 2>/dev/null || true)
        if [ "$family" = iPhone ]; then
          echo "$id"
          return 0
        fi
        j=$((j + 1))
      done
      return 1
    fi
    i=$((i + 1))
  done
  return 1
}

# vectors_digest_reference <vectors dir>: prints the ADR 0060 §4 vector-set digest of the
# directory, the shell reference: one `<path>#0<TAB><sha256 of the raw bytes><LF>` line per regular
# `*.json` file (symbolic links get none, ADR 0060 §2), sorted by bytes, then the lowercase hex
# SHA-256 of the lines. Fails, printing nothing, on an empty corpus (ADR 0060 §3).
vectors_digest_reference() {
  local lines
  lines=$(cd "$1" && find . -type f -name '*.json' -exec shasum -a 256 {} + |
    awk '{ h = substr($0, 1, 64); p = substr($0, 67); sub(/^\.\//, "", p); printf "%s#0\t%s\n", p, h }' |
    LC_ALL=C sort) || return 1
  [ -n "$lines" ] || return 1
  printf '%s\n' "$lines" | shasum -a 256 | cut -d' ' -f1
}

# extract_results <log> <marker> <out>: the results document of a test log is the one line that
# starts with <marker>; writes the rest of that line plus one LF to <out>, byte for byte. Fails,
# writing nothing, unless exactly one line starts with <marker>.
extract_results() {
  local log=$1 marker=$2 out=$3 count
  count=$(awk -v m="$marker" 'index($0, m) == 1 { n++ } END { print n + 0 }' "$log")
  [ "$count" = 1 ] || { echo "found $count lines starting with \"$marker\" in $log, expected one"; return 1; }
  awk -v m="$marker" 'index($0, m) == 1 { printf "%s\n", substr($0, length(m) + 1) }' "$log" >"$out"
}
