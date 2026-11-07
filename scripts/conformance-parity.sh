#!/usr/bin/env bash
# Conformance parity check (ADR 0034 §5, §8): compares every runner's results file with the
# rust-core reference run, so a binding cannot pass by running fewer vectors, by skipping one for
# another reason, or by getting `ok: false` with another error code.
#
# Usage: scripts/conformance-parity.sh [dir]
#   dir  the results directory (default: target/conformance at the repository root), holding the
#        files of conformance/schema/results.schema.json: rust-core.json, the reference
#        (cargo test -p polyjose --test conformance, default features), and <runner>.json or
#        <runner>-<suffix>.json from each other runner. A <runner>-<suffix>.json file (a CI matrix
#        run) is compared like <runner>; a rust-core-<suffix>.json file (a Rust build with
#        features) is not the reference and is ignored.
#
# Each file must be schema-valid, name its runner (`runner` equals the file's runner name), list
# each id once, and hold no `fail`. Against rust-core.json each file must have:
#   - the same `polyjose` version, so a stale prebuild cannot pass on an older build's results;
#   - the same set of ids;
#   - the same status per id, and the same reason for a skip;
#   - the same actual (ok, and the error code) per executed id;
#   - the same error_codes list, in the same order (ADR 0034 §8).
# rust-core.json must exist, be built with no features (ADR 0034 §4) and hold no `fail`. Every
# difference is printed as a FAIL line with the id and both outcomes. A runner of ADR 0034 §2
# (the `runner` enum of the schema) without a file is printed as `SKIPPED (no results: <runner>)`,
# never as passing, and does not fail the check (pipeline rule 9).
#
# Exit status: 0 parity holds; 1 a difference, a fail, or a missing or malformed file; 2 a usage
# or tool error (no node, an unreadable schema).
# Needs node (already a required toolchain); no other runtime. Runs on macOS /bin/bash 3.2 and
# Linux bash.
set -euo pipefail
export LC_ALL=C

repo=$(cd "$(dirname "$0")/.." && pwd -P)
die() { echo "ERROR: $*" >&2; exit 2; }
[ $# -le 1 ] || die "usage: scripts/conformance-parity.sh [dir]"
dir=${1:-$repo/target/conformance}
schema=$repo/conformance/schema/results.schema.json
command -v node >/dev/null 2>&1 || die "node not found on PATH (the parity check needs it)"
[ -f "$schema" ] || die "$schema not found"

exec node - "$dir" "$schema" <<'EOF'
'use strict';
const fs = require('fs');
const path = require('path');

const [dir, schemaPath] = process.argv.slice(2);
const REFERENCE = 'rust-core';

function toolError(message) {
  console.error(`ERROR: ${message}`);
  process.exit(2);
}

let schema;
try {
  schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
} catch (e) {
  toolError(`${schemaPath}: ${e.message}`);
}
const RUNNERS = schema && schema.properties && schema.properties.runner && schema.properties.runner.enum;
if (!Array.isArray(RUNNERS) || !RUNNERS.includes(REFERENCE)) {
  toolError(`${schemaPath}: no runner enum naming ${REFERENCE}`);
}

// --- A JSON Schema 2020-12 validator for the keywords results.schema.json uses -------------------
// The same subset as the Rust runner's check (crates/polyjose/tests/conformance.rs); any other
// keyword is a tool error, so no rule of the schema is ignored.
const KEYWORDS = new Set(['$schema', 'title', 'description', '$defs', '$ref', 'type', 'required',
  'additionalProperties', 'properties', 'items', 'enum', 'const', 'minLength', 'minItems',
  'uniqueItems', 'pattern', 'oneOf']);

function checkKeywords(node, pointer) {
  if (node === null || typeof node !== 'object' || Array.isArray(node)) toolError(`schema ${pointer}: not an object`);
  for (const [keyword, value] of Object.entries(node)) {
    if (!KEYWORDS.has(keyword)) toolError(`schema ${pointer}: unsupported keyword ${keyword}`);
    if (keyword === 'properties' || keyword === '$defs') {
      for (const [name, sub] of Object.entries(value)) checkKeywords(sub, `${pointer}/${keyword}/${name}`);
    } else if (keyword === 'items') {
      checkKeywords(value, `${pointer}/items`);
    } else if (keyword === 'oneOf') {
      value.forEach((sub, i) => checkKeywords(sub, `${pointer}/oneOf/${i}`));
    } else if (keyword === 'additionalProperties' && value !== false) {
      toolError(`schema ${pointer}: additionalProperties must be false`);
    }
  }
}
checkKeywords(schema, '');

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value; // boolean, string, object
}

function equal(a, b) {
  return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const name of Object.keys(value).sort()) out[name] = canonical(value[name]);
    return out;
  }
  return value;
}

// Returns null, or the first violation as "<pointer>: <problem>".
function validate(node, value, pointer) {
  const at = (problem) => `${pointer || '/'}: ${problem}`;
  if (node.$ref !== undefined) {
    const name = String(node.$ref).replace(/^#\/\$defs\//, '');
    const target = schema.$defs && schema.$defs[name];
    if (!target || name === node.$ref) toolError(`schema ${pointer}: unsupported $ref ${node.$ref}`);
    const problem = validate(target, value, pointer);
    if (problem) return problem;
  }
  if (node.type !== undefined) {
    const actual = typeOf(value);
    if (actual !== node.type && !(node.type === 'number' && actual === 'integer')) {
      return at(`must be of type ${node.type}, is ${actual}`);
    }
  }
  if (node.enum !== undefined && !node.enum.some((allowed) => equal(allowed, value))) {
    return at(`must be one of ${JSON.stringify(node.enum)}`);
  }
  if (node.const !== undefined && !equal(node.const, value)) return at(`must be ${JSON.stringify(node.const)}`);
  if (typeof value === 'string') {
    if (node.minLength !== undefined && [...value].length < node.minLength) {
      return at(`must have at least ${node.minLength} character(s)`);
    }
    if (node.pattern !== undefined && !new RegExp(node.pattern, 'u').test(value)) {
      return at(`${JSON.stringify(value)} must match ${node.pattern}`);
    }
  }
  if (Array.isArray(value)) {
    if (node.minItems !== undefined && value.length < node.minItems) return at(`must have at least ${node.minItems} item(s)`);
    if (node.uniqueItems === true) {
      for (let i = 0; i < value.length; i++) {
        if (value.slice(0, i).some((earlier) => equal(earlier, value[i]))) return at(`item ${i} repeats an earlier one`);
      }
    }
    if (node.items !== undefined) {
      for (let i = 0; i < value.length; i++) {
        const problem = validate(node.items, value[i], `${pointer}/${i}`);
        if (problem) return problem;
      }
    }
  }
  if (typeOf(value) === 'object') {
    for (const name of node.required || []) {
      if (!Object.prototype.hasOwnProperty.call(value, name)) return at(`missing required member ${name}`);
    }
    const properties = node.properties || {};
    for (const [name, member] of Object.entries(value)) {
      if (Object.prototype.hasOwnProperty.call(properties, name)) {
        const problem = validate(properties[name], member, `${pointer}/${name}`);
        if (problem) return problem;
      } else if (node.additionalProperties === false) {
        return at(`unknown member ${name}`);
      }
    }
  }
  if (node.oneOf !== undefined) {
    const problems = node.oneOf.map((branch) => validate(branch, value, pointer)).filter((p) => p);
    const matched = node.oneOf.length - problems.length;
    if (matched !== 1) return at(`must match exactly one oneOf branch, matches ${matched} (${problems.join('; ')})`);
  }
  return null;
}

// --- Results files -----------------------------------------------------------------------------
// The runner a file name stands for: the longest runner name that is the file's stem, or the
// stem's prefix followed by "-" (a CI matrix suffix). null for none.
function runnerOf(stem) {
  let best = null;
  for (const runner of RUNNERS) {
    if ((stem === runner || stem.startsWith(`${runner}-`)) && (best === null || runner.length > best.length)) best = runner;
  }
  return best;
}

// Loads and checks one results file: { file, runner, doc, byId } or { file, problems }.
function load(file, runner) {
  const problems = [];
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
  } catch (e) {
    return { file, problems: [`not readable as JSON: ${e.message}`] };
  }
  const invalid = validate(schema, doc, '');
  if (invalid) return { file, problems: [`not valid per conformance/schema/results.schema.json: ${invalid}`] };
  if (doc.runner !== runner) problems.push(`runner is ${JSON.stringify(doc.runner)}, but the file name is runner ${runner}'s`);
  const byId = new Map();
  for (const result of doc.results) {
    if (byId.has(result.id)) problems.push(`${result.id}: listed twice`);
    else byId.set(result.id, result);
  }
  return problems.length ? { file, problems } : { file, runner, doc, byId };
}

function outcome(result) {
  if (result === undefined) return '(missing)';
  let text = result.status;
  if (result.status === 'skipped') text += ` ${result.reason}`;
  else text += ` ${result.actual ? JSON.stringify(result.actual) : '(no outcome)'}`;
  if (result.status === 'fail') text += ` (reason: ${result.reason})`;
  return text;
}

function actualKey(result) {
  const actual = result.actual;
  return actual ? JSON.stringify([actual.ok, actual.ok ? null : actual.error]) : null;
}

let files;
try {
  files = fs.readdirSync(dir).filter((name) => name.endsWith('.json') && !name.startsWith('.')).sort();
} catch (e) {
  files = [];
  console.log(`NOTE: ${dir}: ${e.code === 'ENOENT' ? 'no such directory' : e.message}`);
}
files = files.filter((name) => fs.statSync(path.join(dir, name)).isFile());

const failures = [];
const fail = (line) => {
  failures.push(line);
  console.log(`FAIL: ${line}`);
};
const seen = new Set();
const compared = [];

console.log(`conformance parity: ${dir}`);
let reference = null;
if (!files.includes(`${REFERENCE}.json`)) {
  fail(`${REFERENCE}.json: missing; the reference run writes it (cargo test -p polyjose --test conformance, default features)`);
} else {
  const loaded = load(`${REFERENCE}.json`, REFERENCE);
  if (loaded.problems) {
    for (const problem of loaded.problems) fail(`${REFERENCE}.json: ${problem}`);
  } else if (loaded.doc.features.length !== 0) {
    fail(`${REFERENCE}.json: built with features ${JSON.stringify(loaded.doc.features)}; the reference is the default-features build (ADR 0034 §4)`);
  } else {
    reference = loaded;
    seen.add(REFERENCE);
    for (const result of loaded.doc.results) {
      if (result.status === 'fail') fail(`${REFERENCE}.json: ${result.id}: ${outcome(result)}`);
    }
    console.log(`reference: ${REFERENCE}.json (polyjose ${loaded.doc.polyjose}, ${loaded.byId.size} ids)`);
  }
}

for (const file of files) {
  if (file === `${REFERENCE}.json`) continue;
  const stem = file.slice(0, -'.json'.length);
  const runner = runnerOf(stem);
  if (runner === null) {
    fail(`${file}: names no runner of ADR 0034 §2 (${RUNNERS.join(', ')})`);
    continue;
  }
  if (runner === REFERENCE) {
    console.log(`IGNORED: ${file} (a ${REFERENCE} build with features, not the reference run; ADR 0034 §4)`);
    continue;
  }
  seen.add(runner);
  const loaded = load(file, runner);
  if (loaded.problems) {
    for (const problem of loaded.problems) fail(`${file}: ${problem}`);
    continue;
  }
  compared.push(loaded);
}

for (const other of compared) {
  const before = failures.length;
  const { file, doc, byId } = other;
  for (const result of doc.results) {
    if (result.status === 'fail') fail(`${file}: ${result.id}: ${outcome(result)}`);
  }
  if (reference !== null) {
    const ref = reference.doc;
    // The version the runner tested (the binding's version(), ADR 0030 §4) is the reference's:
    // equal results from another build prove nothing about this one (review N1).
    if (ref.polyjose !== doc.polyjose) {
      fail(`${file}: polyjose version differs: ${REFERENCE} ${ref.polyjose} | ${doc.runner} ${doc.polyjose}`);
    }
    if (!equal(ref.error_codes, doc.error_codes)) {
      fail(`${file}: error_codes differ: ${REFERENCE} ${JSON.stringify(ref.error_codes)} | ${doc.runner} ${JSON.stringify(doc.error_codes)}`);
    }
    const ids = [...new Set([...reference.byId.keys(), ...byId.keys()])].sort();
    for (const id of ids) {
      const want = reference.byId.get(id);
      const got = byId.get(id);
      if (got !== undefined && got.status === 'fail') continue; // printed above
      const same = want !== undefined && got !== undefined && want.status === got.status
        && (got.status === 'skipped' ? want.reason === got.reason : actualKey(want) === actualKey(got));
      if (!same) fail(`${file}: ${id}: ${REFERENCE} ${outcome(want)} | ${doc.runner} ${outcome(got)}`);
    }
  }
  const differences = failures.length - before;
  if (differences === 0) console.log(`PASS: ${file} (${doc.runner}, polyjose ${doc.polyjose}, ${byId.size} ids, equal to ${REFERENCE})`);
  else console.log(`${file}: ${differences} difference(s)`);
}

const missing = RUNNERS.filter((runner) => runner !== REFERENCE && !seen.has(runner));
for (const runner of missing) console.log(`SKIPPED (no results: ${runner})`);

if (failures.length) {
  console.log(`conformance parity: FAILED (${failures.length} problem(s))`);
  process.exit(1);
}
console.log(`conformance parity: OK (${compared.length} file(s) equal to ${REFERENCE}; ${missing.length} runner(s) SKIPPED)`);
EOF
