#!/usr/bin/env bash
# Writes addon-sha256.json, the map of the main package's addon hash pin (feature 0007 F07;
# bindings security audit N-M1; src/backend.ts steps a-d): one SHA-256 (FIPS 180-4, lowercase hex)
# per platform, `{ "<platform>": "<hash>" }`, keys sorted. backend.js loads an addon only when its
# SHA-256 is the one this map pins for the host, so the map is generated here and never edited.
#
# Usage: scripts/addon-hashes.sh <out.json> <addon>...
#   each <addon> is a `polyjose.<platform>.node` file, <platform> one of npm/*/ (the eight
#   published platforms); each platform at most once.
#
# Run by scripts/build.sh for the addons of a local build, and by scripts/pack.sh through it. The
# release assembly of the main package runs it once over all eight prebuilt addons (the 0012
# release hook; until then a main package without a map, or without this host, refuses to load).
# Hashing and JSON are Node's (node:crypto, node:fs), the same on macOS, Linux and Git Bash.
set -euo pipefail
cd "$(dirname "$0")/.."
[ $# -ge 2 ] || { echo "usage: scripts/addon-hashes.sh <out.json> <polyjose.<platform>.node>..." >&2; exit 2; }

# shellcheck disable=SC2016 # the ${...} below are JavaScript template literals, not shell expansions
node -e '
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const [out, ...addons] = process.argv.slice(1);
const published = fs.readdirSync("npm", { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
const pins = {};
for (const file of addons) {
  const m = /^polyjose\.([a-z0-9-]+)\.node$/.exec(path.basename(file));
  if (m === null || !published.includes(m[1])) {
    console.error(`addon-hashes.sh: ${file} is not polyjose.<platform>.node for a published platform (${published.join(", ")})`);
    process.exit(1);
  }
  if (Object.hasOwn(pins, m[1])) {
    console.error(`addon-hashes.sh: two addons for ${m[1]}`);
    process.exit(1);
  }
  pins[m[1]] = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}
const sorted = Object.fromEntries(Object.keys(pins).sort().map((k) => [k, pins[k]]));
fs.writeFileSync(`${out}.tmp`, JSON.stringify(sorted, null, 2) + "\n");
fs.renameSync(`${out}.tmp`, out);
for (const [k, v] of Object.entries(sorted)) console.log(`    ${k} ${v}`);
' "$@"
