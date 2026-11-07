// The CI build of @polyjose/node and its workflow (feature 0007 T05; ADR 0031 §2, ADR 0034 §2,
// ADR 0037 §1, ADR 0044), checked as text on every run of test.sh:
//   - .github/workflows/binding-node.yml is triggered by workflow_dispatch and nothing else, never
//     on PRs or pushes (ADR 0044; owner, 2026-11-07: the platform matrix runs once, at the 0.1.0
//     release candidate, inside the 0012 release workflow, which calls it through workflow_call);
//   - it reads the repository only (`permissions: contents: read`), holds no credentials, no
//     registry upload and no OIDC (`id-token`), and does not depend on PR or event context;
//   - every action is pinned to a full commit SHA with its release tag (ci.yml's convention,
//     ADR 0037 §1);
//   - its prebuild matrix is exactly the eight napi targets of package.json (ADR 0031 §2), each
//     built by scripts/ci-build.sh and uploaded with a stable artifact name, plus the Node 22, 24
//     and 26 runs and the parity job (ADR 0034 §5);
//   - scripts/ci-build.sh and scripts/pack-platform.sh never publish (Gate 3, ADR 0011);
//   - the build is reproducible from the committed lockfiles (review-code.md SF-3, N2): ci-build.sh
//     first checks Cargo.lock with `cargo metadata --locked`, every cargo and napi build or test
//     the scripts run passes `--locked`, and every `npm ci` passes `--ignore-scripts`.
// The YAML is read with the minimal line reader below (indentation, keys, flow mappings), enough
// for the shape this workflow uses; no YAML dependency (ADR 0047: typescript is the only one).
import { assert, fs, os, path, test } from "../../js/dist/node/builtins.js";

interface NodeUrl {
  fileURLToPath(url: string): string;
}
interface SpawnResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: Error;
}
interface NodeChildProcess {
  spawnSync(file: string, args: readonly string[], options: { encoding: "utf8" }): SpawnResult;
}
interface NodeFsBytes {
  readFileSync(path: string): Uint8Array;
  writeFileSync(path: string, data: Uint8Array): void;
}
interface Host {
  readonly platform: string;
  getBuiltinModule(id: "node:url"): NodeUrl;
  getBuiltinModule(id: "node:child_process"): NodeChildProcess;
  getBuiltinModule(id: "node:fs"): NodeFsBytes;
}
const host = (globalThis as unknown as { process: Host }).process;
const cp = host.getBuiltinModule("node:child_process");
const fsb = host.getBuiltinModule("node:fs");
const thisFile = host.getBuiltinModule("node:url").fileURLToPath((import.meta as unknown as { url: string }).url);
/** bindings/node: this file is bindings/node/dist/ci.test.js. */
const pkgDir = path.resolve(path.dirname(thisFile), "..");
const repo = path.resolve(pkgDir, "..", "..");
const workflowFile = path.join(repo, ".github", "workflows", "binding-node.yml");
const ciBuildFile = path.join(pkgDir, "scripts", "ci-build.sh");
const packPlatformFile = path.join(pkgDir, "scripts", "pack-platform.sh");
const buildFile = path.join(pkgDir, "scripts", "build.sh");
const testShFile = path.join(pkgDir, "test.sh");

const read = (file: string): string => fs.readFileSync(file, "utf8");
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;

/** package.json `napi.targets`: the eight Rust targets of ADR 0031 §2. */
function napiTargets(): string[] {
  const pkg: unknown = JSON.parse(read(path.join(pkgDir, "package.json")));
  assert.ok(isRecord(pkg) && isRecord(pkg["napi"]), "package.json has a napi section");
  const targets = pkg["napi"]["targets"];
  assert.ok(Array.isArray(targets) && targets.every((t) => typeof t === "string"), "napi.targets is a string array");
  return [...(targets as string[])].sort();
}

// --- A minimal YAML line reader ------------------------------------------------------------------

interface Line {
  /** 1-based line number in the file. */
  readonly no: number;
  /** Leading spaces. */
  readonly indent: number;
  /** The line without its indentation and without a trailing ` # comment`. */
  readonly text: string;
}

/**
 * The non-blank, non-comment lines. A trailing comment is cut at the first ` #` outside quotes;
 * block scalars (`run: |`) need no special case here, because their lines are always indented
 * deeper than their key and the readers below only look at one indentation level.
 */
function yamlLines(src: string): Line[] {
  const lines: Line[] = [];
  src.split(/\r?\n/).forEach((raw, i) => {
    assert.ok(!raw.includes("\t"), `binding-node.yml:${i + 1}: no tab characters (YAML indents with spaces)`);
    const body = raw.trimStart();
    if (body === "" || body.startsWith("#")) return;
    let quote = "";
    let end = body.length;
    for (let j = 0; j < body.length; j++) {
      const c = body[j];
      if (quote !== "") {
        if (c === quote) quote = "";
      } else if (c === '"' || c === "'") {
        quote = c;
      } else if (c === "#" && j > 0 && body[j - 1] === " ") {
        end = j;
        break;
      }
    }
    lines.push({ no: i + 1, indent: raw.length - body.length, text: body.slice(0, end).trimEnd() });
  });
  return lines;
}

/** `key: value` (or `key:`) of a mapping line, the key unquoted; undefined for other lines. */
function keyOf(text: string): { key: string; value: string } | undefined {
  const m = /^("[^"]*"|'[^']*'|[^\s:'"][^:]*?)\s*:(?:\s+(.*))?$/.exec(text);
  if (m === null) return undefined;
  const key = (m[1] ?? "").replace(/^(["'])(.*)\1$/, "$2");
  return { key, value: (m[2] ?? "").trim() };
}

/** The lines of the block under the line at `at`: every later line indented deeper than it. */
function blockUnder(lines: readonly Line[], at: number): Line[] {
  const head = lines[at];
  assert.ok(head !== undefined);
  const out: Line[] = [];
  for (const line of lines.slice(at + 1)) {
    if (line.indent <= head.indent) break;
    out.push(line);
  }
  return out;
}

/** The entries (`key` or `- item`) at the first indentation level of a block. */
function entriesOf(block: readonly Line[]): { key: string; value: string; line: Line }[] {
  const first = block[0];
  if (first === undefined) return [];
  return block
    .filter((l) => l.indent === first.indent)
    .map((line) => {
      const item = /^-\s+(.*)$/.exec(line.text);
      if (item !== null) return { key: (item[1] ?? "").trim(), value: "", line };
      const kv = keyOf(line.text);
      assert.ok(kv !== undefined, `binding-node.yml:${line.no}: a mapping entry or list item`);
      return { ...kv, line };
    });
}

/** The top-level entries of the workflow, with the index of each in `lines`. */
function topLevel(lines: readonly Line[]): { key: string; value: string; index: number }[] {
  const out: { key: string; value: string; index: number }[] = [];
  lines.forEach((line, index) => {
    if (line.indent !== 0) return;
    const kv = keyOf(line.text);
    assert.ok(kv !== undefined, `binding-node.yml:${line.no}: a top-level key`);
    out.push({ ...kv, index });
  });
  return out;
}

/** A flow sequence `[a, b]` as its items, or a plain scalar as one item. */
function flowItems(value: string): string[] {
  const seq = /^\[(.*)\]$/.exec(value);
  const items = seq === null ? [value] : (seq[1] ?? "").split(",");
  return items.map((s) => s.trim().replace(/^(["'])(.*)\1$/, "$2")).filter((s) => s !== "");
}

/** A one-line flow mapping `{ a: x, b: y }` (no nested braces or quoted commas). */
function flowMapping(text: string, where: string): Record<string, string> {
  const m = /^\{(.*)\}$/.exec(text);
  assert.ok(m !== null, `${where}: a one-line flow mapping`);
  const out: Record<string, string> = {};
  for (const part of (m[1] ?? "").split(",")) {
    const kv = keyOf(part.trim());
    assert.ok(kv !== undefined && kv.value !== "", `${where}: '${part.trim()}' is key: value`);
    out[kv.key] = kv.value.replace(/^(["'])(.*)\1$/, "$2");
  }
  return out;
}

const workflow = (): { src: string; lines: Line[] } => {
  const src = read(workflowFile);
  return { src, lines: yamlLines(src) };
};

/** The child entries of the one top-level key named `name`. */
function topLevelBlock(lines: readonly Line[], ...names: string[]): { value: string; block: Line[] } {
  const found = topLevel(lines).filter((e) => names.includes(e.key));
  assert.equal(found.length, 1, `binding-node.yml: exactly one top-level ${names[0]} key`);
  const entry = found[0];
  assert.ok(entry !== undefined);
  return { value: entry.value, block: blockUnder(lines, entry.index) };
}

/** The block of job `id` under the top-level `jobs:`. */
function jobBlock(lines: readonly Line[], id: string): Line[] {
  const jobs = topLevelBlock(lines, "jobs").block;
  const entry = entriesOf(jobs).find((e) => e.key === id);
  assert.ok(entry !== undefined, `binding-node.yml: job ${id}`);
  return blockUnder(lines, lines.indexOf(entry.line));
}

// --- The reader itself -----------------------------------------------------------------------------

test("the YAML line reader finds keys, blocks, flow sequences and flow mappings", () => {
  const lines = yamlLines(
    [
      "# a comment",
      "name: x # trailing",
      '"on":',
      "  workflow_dispatch:",
      "    inputs: {}",
      "  push:",
      "jobs:",
      "  a:",
      "    run: |",
      "      echo 'not: a # comment'",
      "    matrix: [22, '24', 26]",
      "    item: { k: v, n: 2 }",
    ].join("\r\n"),
  );
  assert.deepEqual(
    topLevel(lines).map((e) => e.key),
    ["name", "on", "jobs"],
  );
  assert.equal(lines[0]?.text, "name: x");
  assert.deepEqual(
    entriesOf(topLevelBlock(lines, "on").block).map((e) => e.key),
    ["workflow_dispatch", "push"],
  );
  assert.deepEqual(flowItems(keyOf(lines[9]?.text ?? "")?.value ?? ""), ["22", "24", "26"]);
  assert.deepEqual(flowMapping(keyOf(lines[10]?.text ?? "")?.value ?? "", "test"), { k: "v", n: "2" });
  assert.equal(lines[8]?.text, "echo 'not: a # comment'");
});

// --- The workflow ----------------------------------------------------------------------------------

test("binding-node.yml is triggered by workflow_dispatch only (ADR 0044; owner, 2026-11-07)", () => {
  const { lines } = workflow();
  // YAML 1.1 readers turn a bare `on` key into `true`, so both spellings count as the trigger key.
  const on = topLevelBlock(lines, "on", "true");
  const triggers = on.value === "" ? entriesOf(on.block).map((e) => e.key) : flowItems(on.value);
  assert.deepEqual(triggers, ["workflow_dispatch"], "the trigger set is exactly workflow_dispatch");
});

test("binding-node.yml reads the repository only and holds no credentials, registry upload or OIDC", () => {
  const { src, lines } = workflow();
  // Comments included: a step commented out is one edit away from running.
  for (const [pattern, what] of [
    [/publish/i, "a publish step"],
    [/\bsecrets\b/i, "a repository secret"],
    [/token/i, "a token (NPM_TOKEN, NODE_AUTH_TOKEN, GITHUB_TOKEN, github.token)"],
    [/id-token/i, "an OIDC id-token"],
    [/pull_request/, "a PR trigger or PR context"],
    [/github\.(event|head_ref|base_ref)\b/, "event or PR context (inputs map one-to-one onto workflow_call)"],
    [/registry-url|npm\.pkg\.github\.com|registry\.npmjs\.org/, "an npm registry"],
    [/write-all|:\s*write\b/, "a write permission"],
    [/continue-on-error/, "a step allowed to fail"],
  ] as const) {
    assert.doesNotMatch(src, pattern, `binding-node.yml has no ${what}`);
  }
  const permissions = topLevelBlock(lines, "permissions");
  assert.equal(permissions.value, "", "permissions is a mapping");
  assert.deepEqual(
    entriesOf(permissions.block).map((e) => `${e.key}: ${e.value}`),
    ["contents: read"],
    "permissions: contents: read",
  );
  for (const m of src.matchAll(/\bnpm[ \t]+([a-z-]+)/g)) {
    assert.ok(["ci", "pack"].includes(m[1] ?? ""), `binding-node.yml: npm ${m[1]} is ci or pack`);
  }
  const checkouts = src.match(/uses:\s+actions\/checkout@/g)?.length ?? 0;
  assert.ok(checkouts > 0, "binding-node.yml checks the repository out");
  assert.equal(
    src.match(/persist-credentials:\s+false\b/g)?.length ?? 0,
    checkouts,
    "every checkout sets persist-credentials: false",
  );
});

test("every action in binding-node.yml is pinned to a full commit SHA with its release tag", () => {
  const { lines } = workflow();
  const uses = lines.filter((l) => /^(-\s+)?uses:/.test(l.text));
  assert.ok(uses.length > 0, "binding-node.yml uses actions");
  const raw = read(workflowFile).split(/\r?\n/);
  for (const line of uses) {
    assert.match(
      raw[line.no - 1]?.trim() ?? "",
      /^(-\s+)?uses:\s+[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$/,
      `binding-node.yml:${line.no}: pinned as <owner>/<repo>@<40-hex sha> # vX.Y.Z`,
    );
  }
});

test("binding-node.yml builds the eight napi targets with ci-build.sh and uploads stable artifacts", () => {
  const { src, lines } = workflow();
  const prebuild = jobBlock(lines, "prebuild");
  const include = prebuild.find((l) => l.text === "include:");
  assert.ok(include !== undefined, "prebuild has a matrix include list");
  const entries = entriesOf(blockUnder(prebuild, prebuild.indexOf(include))).map((e) =>
    flowMapping(e.key, `binding-node.yml:${e.line.no}`),
  );
  assert.deepEqual(
    entries.map((e) => e["target"]).sort(),
    napiTargets(),
    "the matrix targets are exactly package.json napi.targets",
  );
  const table = ciBuildTable();
  for (const e of entries) {
    assert.equal(e["platform"], table.get(e["target"] ?? ""), `${e["target"]}: platform matches ci-build.sh`);
    assert.ok((e["os"] ?? "") !== "", `${e["target"]}: a runner`);
  }
  // musl runs inside Alpine (ADR 0031 §2); the others build on the runner itself.
  for (const e of entries) {
    const musl = (e["target"] ?? "").endsWith("-musl");
    assert.equal(/^node:\d+-alpine[\w.]*@sha256:[0-9a-f]{64}$/.test(e["image"] ?? ""), musl, `${e["target"]}: Alpine image iff musl, by digest`);
  }
  const text = prebuild.map((l) => l.text).join("\n");
  assert.match(text, /bindings\/node\/scripts\/ci-build\.sh "?\$\{\{ matrix\.target \}\}"?/, "each target runs ci-build.sh <target>");
  assert.match(text, /name: npm-\$\{\{ matrix\.target \}\}/, "platform tarball artifact npm-<target>");
  assert.match(text, /name: conformance-node-\$\{\{ matrix\.target \}\}/, "results artifact conformance-node-<target>");
  assert.match(text, /target\/conformance\/node-\$\{\{ matrix\.target \}\}\.json/, "uploads node-<target>.json (ADR 0034 §2)");
  assert.match(src, /if-no-files-found: error/, "a missing artifact fails the job");
});

test("binding-node.yml runs Node 22, 24 and 26 on linux-x64 and the parity check over every results file", () => {
  const { lines } = workflow();
  const versions = jobBlock(lines, "node-versions");
  const node = versions.map((l) => keyOf(l.text)).find((kv) => kv?.key === "node");
  assert.ok(node !== undefined, "node-versions has a node matrix");
  assert.deepEqual(flowItems(node.value), ["22", "24", "26"]);
  const vtext = versions.map((l) => l.text).join("\n");
  assert.match(vtext, /runs-on: ubuntu-latest/, "on linux-x64");
  assert.match(vtext, /ci-build\.sh x86_64-unknown-linux-gnu "?x86_64-unknown-linux-gnu-node\$\{\{ matrix\.node \}\}"?/);

  const parity = jobBlock(lines, "parity");
  const ptext = parity.map((l) => l.text).join("\n");
  assert.match(ptext, /needs: \[prebuild, node-versions\]/, "parity waits for every results file");
  assert.match(ptext, /actions\/download-artifact@/, "downloads the results");
  assert.match(ptext, /pattern: conformance-node-\*/, "every conformance-node-* artifact");
  assert.match(ptext, /cargo test --locked -p polyjose --test conformance/, "the rust-core reference (ADR 0034 §4)");
  assert.match(ptext, /scripts\/conformance-parity\.sh/, "the parity check (ADR 0034 §5)");
  for (const target of napiTargets()) {
    assert.ok(ptext.includes(target), `parity requires node-${target}.json`);
  }
});

// --- The scripts ------------------------------------------------------------------------------------

/** The lines of a shell script that are not comments. */
function codeLines(file: string): string[] {
  return read(file)
    .split(/\r?\n/)
    .filter((line) => !line.trim().startsWith("#"));
}

/** ci-build.sh's `<triple>) platform=<npm dir> ;;` table. */
function ciBuildTable(): Map<string, string> {
  const table = new Map<string, string>();
  for (const line of codeLines(ciBuildFile)) {
    const m = /^\s*([a-z0-9_]+(?:-[a-z0-9_]+)+)\)\s*platform=([a-z0-9-]+)\s*;;/.exec(line);
    if (m !== null) table.set(m[1] ?? "", m[2] ?? "");
  }
  return table;
}

test("ci-build.sh maps each napi target to its npm/<platform> package", () => {
  const table = ciBuildTable();
  assert.deepEqual([...table.keys()].sort(), napiTargets(), "ci-build.sh knows exactly the napi targets");
  const dirs = fs
    .readdirSync(path.join(pkgDir, "npm"), { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
  assert.deepEqual([...table.values()].sort(), dirs, "one npm/<platform> directory per target");
  for (const [triple, platform] of table) {
    const pkg: unknown = JSON.parse(read(path.join(pkgDir, "npm", platform, "package.json")));
    assert.ok(isRecord(pkg), `npm/${platform}/package.json is an object`);
    assert.equal(pkg["name"], `@polyjose/node-${platform}`, `${triple}: package name`);
    assert.equal(pkg["main"], `polyjose.${platform}.node`, `${triple}: the addon napi build --platform writes`);
  }
});

test("ci-build.sh and pack-platform.sh never publish (npm publish and napi pre-publish are Gate 3)", () => {
  for (const file of [ciBuildFile, packPlatformFile]) {
    const name = path.relative(pkgDir, file);
    const code = codeLines(file).join("\n");
    assert.doesNotMatch(code, /publish/i, `${name}: no publish command`);
    assert.doesNotMatch(code, /token/i, `${name}: no registry token`);
    for (const m of code.matchAll(/\bnpm[ \t]+([a-z-]+)/g)) {
      assert.ok(["pack", "ci"].includes(m[1] ?? ""), `${name}: npm ${m[1]} is pack or ci`);
    }
    for (const m of code.matchAll(/\bnapi\b"?[ \t]+([a-z-]+)/g)) {
      assert.equal(m[1], "build", `${name}: napi ${m[1]} is build`);
    }
  }
});

// --- Lockfiles (review-code.md SF-3, N2) ------------------------------------------------------------

/** Every script ci-build.sh runs, directly or through test.sh and build.sh. */
const buildScripts = (): string[] => [ciBuildFile, testShFile, buildFile, packPlatformFile];

/** The code lines of a script with quoted text emptied, so a message that names a command is not a run of it. */
const commands = (file: string): string[] =>
  codeLines(file).map((line) => line.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, '""'));

test("ci-build.sh checks Cargo.lock with cargo metadata --locked before anything else", () => {
  const code = commands(ciBuildFile);
  const metadata = code.findIndex((line) => line.trim() === "cargo metadata --locked --format-version 1 >/dev/null");
  assert.ok(metadata >= 0, "ci-build.sh runs `cargo metadata --locked --format-version 1 >/dev/null`");
  // Only the shell preamble and the argument check may come first: no node, no build, no test.
  const first = code.findIndex((line) => /\b(node|npm|napi|cargo)\b|test\.sh|scripts\//.test(line));
  assert.equal(first, metadata, `the first tool ci-build.sh runs is cargo metadata, not: ${code[first] ?? ""}`);
});

test("every cargo and napi build or test the CI build reaches passes --locked", () => {
  let cargoRuns = 0;
  let napiBuilds = 0;
  for (const file of buildScripts()) {
    const name = path.relative(pkgDir, file);
    const raw = codeLines(file);
    commands(file).forEach((line, i) => {
      if (/\bcargo[ \t]+(build|test|run|check|metadata|clippy|install)\b/.test(line)) {
        cargoRuns += 1;
        assert.match(line, /[ \t]--locked\b/, `${name}: cargo without --locked: ${line.trim()}`);
      }
      // The raw line: build.sh runs napi as "$napi", which the quote stripping would empty. An
      // echo that names the command is a message, not a run.
      const napiLine = raw[i] ?? "";
      if (!/^\s*echo\b/.test(napiLine) && /\bnapi\b"?[ \t]+build\b/.test(napiLine)) {
        napiBuilds += 1;
        // napi build passes the options after `--` on to cargo build (and to its cargo metadata).
        assert.match(napiLine, /[ \t]--[ \t]+--locked\b/, `${name}: napi build without \`-- --locked\`: ${napiLine.trim()}`);
      }
    });
  }
  assert.ok(cargoRuns >= 2, `found the cargo metadata and cargo test runs (${cargoRuns})`);
  assert.equal(napiBuilds, 1, "build.sh's napi build is the one addon build");
});

test("every npm ci in the build scripts passes --ignore-scripts", () => {
  let runs = 0;
  for (const file of buildScripts()) {
    const name = path.relative(pkgDir, file);
    for (const line of commands(file)) {
      if (!/\bnpm[ \t]+ci\b/.test(line)) continue;
      runs += 1;
      assert.match(line, /\bnpm[ \t]+ci\b[^;&|)]*[ \t]--ignore-scripts\b/, `${name}: npm ci without --ignore-scripts: ${line.trim()}`);
    }
  }
  assert.equal(runs, 4, "test.sh and build.sh each run npm ci in bindings/node and bindings/js");
});

// --- The PE import reader (review-code.md SF-1) -----------------------------------------------------

const peReader = path.join(pkgDir, "scripts", "pe-imports.py");
const peFixture = (name: string): string => path.join(pkgDir, "test", "fixtures", "pe", name);
/** As ci-build.sh runs it. Windows runners have python.exe only; their python3 is a shim for bash. */
const python = host.platform === "win32" ? "python" : "python3";

function peImports(...args: string[]): { status: number | null; lines: string[]; stderr: string } {
  const r = cp.spawnSync(python, ["-I", peReader, ...args], { encoding: "utf8" });
  assert.equal(r.error, undefined, `${python} runs`);
  return { status: r.status, lines: r.stdout.split(/\r?\n/).filter((l) => l !== ""), stderr: r.stderr };
}

/** A scratch directory for edited copies of the fixtures, removed after `fn`. */
function withScratch(fn: (dir: string) => void): void {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyjose-pe-"));
  try {
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** `bytes` with every ASCII occurrence of `from` replaced by `to` (the same length). */
function replaceAscii(bytes: Uint8Array, from: string, to: string): Uint8Array {
  assert.equal(from.length, to.length);
  const out = Uint8Array.from(bytes);
  let hits = 0;
  for (let i = 0; i + from.length <= out.length; i++) {
    if ([...from].every((c, j) => out[i + j] === c.charCodeAt(0))) {
      [...to].forEach((c, j) => (out[i + j] = c.charCodeAt(0)));
      hits += 1;
    }
  }
  assert.ok(hits > 0, `${from} occurs in the fixture`);
  return out;
}

test("the PE import reader lists the DLLs a PE file imports (fixtures: test/fixtures/pe/regen.sh)", () => {
  const dynamic = peImports(peFixture("crt-dynamic-x64.dll"));
  assert.equal(dynamic.status, 0, dynamic.stderr);
  assert.deepEqual(dynamic.lines, ["KERNEL32.dll", "VCRUNTIME140.dll", "MSVCP140.dll"], "x86-64, in import-table order");
  const stat = peImports(peFixture("crt-static-arm64.dll"));
  assert.equal(stat.status, 0, stat.stderr);
  assert.deepEqual(stat.lines, ["KERNEL32.dll"], "ARM64");
});

test("--deny-crt fails on a VCRUNTIME*.dll or MSVCP*.dll import, in any case, and passes a static-CRT DLL", () => {
  const dynamic = peImports("--deny-crt", peFixture("crt-dynamic-x64.dll"));
  assert.equal(dynamic.status, 1, "the dynamic-CRT DLL fails");
  assert.match(dynamic.stderr, /VCRUNTIME140\.dll/);
  assert.match(dynamic.stderr, /MSVCP140\.dll/);
  assert.equal(peImports("--deny-crt", peFixture("crt-static-arm64.dll")).status, 0, "the static-CRT DLL passes");
  withScratch((dir) => {
    const original = fsb.readFileSync(peFixture("crt-dynamic-x64.dll"));
    // DLL names are case-insensitive on Windows: each forbidden name alone, lowercased, still
    // fails. The other forbidden name is renamed to a harmless one of the same length.
    for (const { lower, upper, other, harmless } of [
      { lower: "vcruntime140.dll", upper: "VCRUNTIME140.dll", other: "MSVCP140.dll", harmless: "WS2_32XX.dll" },
      { lower: "msvcp140.dll", upper: "MSVCP140.dll", other: "VCRUNTIME140.dll", harmless: "BCRYPTPRIMXX.dll" },
    ]) {
      const file = path.join(dir, lower);
      fsb.writeFileSync(file, replaceAscii(replaceAscii(original, other, harmless), upper, lower));
      assert.deepEqual(peImports(file).lines, ["KERNEL32.dll", ...(upper === "VCRUNTIME140.dll" ? [lower, harmless] : [harmless, lower])]);
      const r = peImports("--deny-crt", file);
      assert.equal(r.status, 1, `${lower} alone fails`);
      assert.ok(r.stderr.includes(lower), `the failure names ${lower}`);
      assert.ok(!r.stderr.includes(harmless), `and not ${harmless}`);
    }
  });
});

test("the PE import reader fails closed (exit 2) on anything that is not a well-formed PE file", () => {
  withScratch((dir) => {
    const original = fsb.readFileSync(peFixture("crt-dynamic-x64.dll"));
    const cases: [string, Uint8Array][] = [
      ["empty", new Uint8Array(0)],
      ["the DOS header only", original.slice(0, 64)],
      ["headers without the import table", original.slice(0, 512)],
      ["not a PE file", Uint8Array.from("{\"name\": \"x\"}", (c) => c.charCodeAt(0))],
    ];
    // e_lfanew (offset 0x3c) pointing past the end of the file.
    const lfanew = Uint8Array.from(original);
    lfanew.set([0xf0, 0xff, 0x00, 0x00], 0x3c);
    cases.push(["e_lfanew past the end", lfanew]);
    for (const [what, bytes] of cases) {
      const file = path.join(dir, "case.dll");
      fsb.writeFileSync(file, bytes);
      for (const args of [[file], ["--deny-crt", file]]) {
        const r = peImports(...args);
        assert.equal(r.status, 2, `${what} (${args.join(" ")}): exit 2, not a pass; stderr: ${r.stderr}`);
        assert.deepEqual(r.lines, [], `${what}: no import is listed`);
      }
    }
    assert.equal(peImports(path.join(dir, "missing.dll")).status, 2, "a missing file");
    assert.equal(peImports().status, 2, "no file");
    assert.equal(peImports("--deny-crt").status, 2, "--deny-crt and no file");
  });
});

// --- The glibc floor check (review-code.md SF-2, feature 0007 F04) ---------------------------------

const glibcCheck = path.join(pkgDir, "scripts", "glibc-floor.sh");
const glibcFixture = (name: string): string => path.join(pkgDir, "test", "fixtures", "glibc", name);

function glibcFloor(...args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = cp.spawnSync("bash", [glibcCheck, ...args], { encoding: "utf8" });
  assert.equal(r.error, undefined, "bash runs");
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** glibc-floor.sh --output <floor> on `text`, a tool output written to a scratch file. */
function glibcFloorOn(floor: string, text: string): { status: number | null; stdout: string; stderr: string } {
  let r = { status: null as number | null, stdout: "", stderr: "" };
  withScratch((dir) => {
    const file = path.join(dir, "output.txt");
    fs.writeFileSync(file, text);
    r = glibcFloor("--output", floor, file);
  });
  return r;
}

test("the glibc floor check passes the 2.28 fixtures and fails the 2.34 ones, readelf and objdump (fixtures: test/fixtures/glibc/regen.sh)", () => {
  for (const tool of ["readelf", "objdump"]) {
    const pass = glibcFloor("--output", "2.28", glibcFixture(`floor-2.28-arm64.${tool}.txt`));
    assert.equal(pass.status, 0, `${tool}: 2.28 at floor 2.28 passes; stderr: ${pass.stderr}`);
    assert.match(pass.stdout, /highest GLIBC_2\.28 \(floor 2\.28\)/, `${tool}: names the highest version`);

    const fail = glibcFloor("--output", "2.28", glibcFixture(`above-2.34-x64.${tool}.txt`));
    assert.equal(fail.status, 1, `${tool}: 2.34 at floor 2.28 fails`);
    assert.match(fail.stderr, /GLIBC_2\.34/, `${tool}: the failure names GLIBC_2.34`);
    assert.doesNotMatch(fail.stderr, /GLIBC_2\.28\b|GLIBC_2\.2\.5/, `${tool}: and only the versions above the floor`);

    // The floor is the only threshold: the same outputs at other floors.
    assert.equal(glibcFloor("--output", "2.34", glibcFixture(`above-2.34-x64.${tool}.txt`)).status, 0, `${tool}: 2.34 at floor 2.34`);
    assert.equal(glibcFloor("--output", "2.27", glibcFixture(`floor-2.28-arm64.${tool}.txt`)).status, 1, `${tool}: 2.28 at floor 2.27`);
  }
});

test("the glibc floor check compares versions as integers, not text (no sort -V on macOS bash 3.2)", () => {
  const out = (...versions: string[]): string =>
    versions.map((v, i) => `  0x00${i}0:   Name: GLIBC_${v}  Flags: none  Version: ${i + 2}\n`).join("");
  const cases: [string, string[], number][] = [
    ["2.28", ["2.9"], 0], // 9 < 28, though "2.9" > "2.28" as text
    ["2.28", ["2.2.5", "2.3.4", "2.17"], 0], // x86-64's three-component base versions
    ["2.28", ["2.28"], 0],
    ["2.28", ["2.29"], 1],
    ["2.28", ["2.100"], 1], // 100 > 28, though "2.100" < "2.28" as text
    ["2.28", ["3.0"], 1],
    ["2.28", ["2.28.1"], 1], // above 2.28 itself
    ["2.28", ["2.08"], 0], // a leading zero is decimal, not octal
    ["2.9", ["2.10"], 1],
    ["2.34", ["2.17", "2.34", "2.28"], 0], // the maximum, in any order
  ];
  for (const [floor, versions, status] of cases) {
    const r = glibcFloorOn(floor, out(...versions));
    assert.equal(r.status, status, `floor ${floor}, ${versions.join(" ")}: exit ${status}; stderr: ${r.stderr}`);
  }
  // Versions of other libraries are not glibc's: libgcc_s's GCC_*, libstdc++'s GLIBCXX_*.
  assert.equal(glibcFloorOn("2.28", out("2.17") + "  Name: GCC_7.0.0\n  Name: GLIBCXX_3.4.30\n").status, 0);
});

test("the glibc floor check fails on GLIBC_PRIVATE and any other unnumbered glibc version", () => {
  const base = fs.readFileSync(glibcFixture("floor-2.28-arm64.readelf.txt"), "utf8");
  // GLIBC_PRIVATE is glibc's internal ABI, which changes between builds of the same release;
  // GLIBC_ABI_DT_RELR is written by a link with -z pack-relative-relocs and needs glibc 2.36.
  for (const name of ["GLIBC_PRIVATE", "GLIBC_ABI_DT_RELR"]) {
    const r = glibcFloorOn("2.28", `${base}  0x0090:   Name: ${name}  Flags: none  Version: 7\n`);
    assert.equal(r.status, 1, `${name}: exit 1`);
    assert.ok(r.stderr.includes(name), `the failure names ${name}`);
  }
  const objdump = fs.readFileSync(glibcFixture("floor-2.28-arm64.objdump.txt"), "utf8");
  const priv = glibcFloorOn("2.28", `${objdump}0000000000000000      DF *UND*\t0000000000000000 (GLIBC_PRIVATE) _dl_x\n`);
  assert.equal(priv.status, 1, "GLIBC_PRIVATE in objdump -T output");
});

test("the glibc floor check fails closed (exit 2) when it finds no glibc version or cannot run", () => {
  withScratch((dir) => {
    const empty = path.join(dir, "empty.txt");
    fs.writeFileSync(empty, "");
    const musl = path.join(dir, "musl.txt");
    fs.writeFileSync(musl, "\nVersion needs section '.gnu.version_r' contains 1 entries:\n  0x0000: Version: 1  File: libgcc_s.so.1  Cnt: 1\n  0x0010:   Name: GCC_3.0  Flags: none  Version: 2\n");
    const none = path.join(dir, "none.txt");
    fs.writeFileSync(none, "\nNo version information found in this file.\n");
    for (const [what, file] of [["empty output", empty], ["no GLIBC_ version (musl, libgcc_s only)", musl], ["no version information", none]] as const) {
      const r = glibcFloor("--output", "2.28", file);
      assert.equal(r.status, 2, `${what}: exit 2, not a pass; stderr: ${r.stderr}`);
      assert.match(r.stderr, /no GLIBC_ symbol version/, `${what}: says why`);
    }
    // The addon mode: a file that is not an ELF object fails, whatever tool reads it.
    const notElf = path.join(dir, "polyjose.linux-x64-gnu.node");
    fs.writeFileSync(notElf, "{}\n");
    assert.notEqual(glibcFloor("2.28", notElf).status, 0, "a file that is not ELF");
    assert.equal(glibcFloor("2.28", path.join(dir, "missing.node")).status, 2, "a missing addon");
    assert.equal(glibcFloor("--output", "2.28", path.join(dir, "missing.txt")).status, 2, "a missing output file");
  });
  assert.equal(glibcFloor().status, 2, "no arguments");
  assert.equal(glibcFloor("2.28").status, 2, "no file");
  for (const floor of ["", "2", "2.28.1", "v2.28", "2.x", "2.1000"]) {
    assert.equal(glibcFloor("--output", floor, glibcFixture("floor-2.28-arm64.readelf.txt")).status, 2, `floor '${floor}' is rejected`);
  }
});

/** The index of the only line of `lines` matching `pattern`. */
function onlyLine(lines: readonly string[], pattern: RegExp, what: string): number {
  const found = lines.flatMap((line, i) => (pattern.test(line) ? [i] : []));
  assert.equal(found.length, 1, `${what}: exactly one line (found ${found.length})`);
  return found[0] ?? -1;
}

/** Whether line `at` is inside an `if <condition>; then ... fi` whose condition line matches `cond`. */
function insideIf(lines: readonly string[], at: number, cond: RegExp): boolean {
  let depth = 0;
  for (let i = at - 1; i >= 0; i--) {
    const line = (lines[i] ?? "").trim();
    if (/^fi\b/.test(line)) depth += 1;
    else if (/^if\b/.test(line)) {
      if (depth === 0) return cond.test(line);
      depth -= 1;
    }
  }
  return false;
}

test("ci-build.sh links the msvc addons' C runtime statically and checks they import no VC++ runtime DLL", () => {
  const raw = codeLines(ciBuildFile);
  const gate = /^if \[ "\$crt_static" = true \]; then$/;
  onlyLine(raw, /^\s*case \$target in \*-pc-windows-msvc\) crt_static=true ;; esac$/, "crt_static is set for the *-pc-windows-msvc targets only");
  onlyLine(raw, /^\s*crt_static=false$/, "and false otherwise");
  const flags = onlyLine(
    raw,
    /^\s*export RUSTFLAGS="\$\{RUSTFLAGS:\+\$RUSTFLAGS \}-C target-feature=\+crt-static"$/,
    "RUSTFLAGS gains -C target-feature=+crt-static (napi build appends its own flags to it)",
  );
  const build = onlyLine(raw, /^\s*CARGO_BUILD_TARGET=\S+ POLYJOSE_CONFORMANCE_SUFFIX=\S+ \.\/test\.sh$/, "the build and test run");
  const check = onlyLine(
    raw,
    /^\s*python3 -I scripts\/pe-imports\.py --deny-crt "polyjose\.\$platform\.node"$/,
    "the import check on the built addon",
  );
  const pack = onlyLine(raw, /^\s*scripts\/pack-platform\.sh /, "the platform pack");
  assert.ok(insideIf(raw, flags, gate), "the flag is set only when crt_static is true");
  assert.ok(insideIf(raw, check, gate), "the check runs only when crt_static is true");
  assert.ok(flags < build && build < check && check < pack, "flag, then build, then the check, then the pack");
});

/** The glibc floor of the gnu addons (F04): the README, ci-build.sh and the build images agree. */
const glibcFloorValue = "2.28";

test("ci-build.sh checks the gnu addons' glibc floor after the build, and only on the gnu targets", () => {
  const raw = codeLines(ciBuildFile);
  const gate = /^if \[ "\$glibc_check" = true \]; then$/;
  onlyLine(raw, new RegExp(`^glibc_floor=${glibcFloorValue.replace(".", "\\.")}$`), `the floor is ${glibcFloorValue}`);
  onlyLine(raw, /^\s*glibc_check=false$/, "glibc_check is false by default");
  onlyLine(raw, /^\s*case \$target in \*-unknown-linux-gnu\) glibc_check=true ;; esac$/, "and true for the *-unknown-linux-gnu targets only");
  const build = onlyLine(raw, /^\s*CARGO_BUILD_TARGET=\S+ POLYJOSE_CONFORMANCE_SUFFIX=\S+ \.\/test\.sh$/, "the build and test run");
  const check = onlyLine(
    raw,
    /^\s*scripts\/glibc-floor\.sh "\$glibc_floor" "polyjose\.\$platform\.node"$/,
    "the check on the built addon, the file pack-platform.sh packs",
  );
  const pack = onlyLine(raw, /^\s*scripts\/pack-platform\.sh /, "the platform pack");
  assert.ok(insideIf(raw, check, gate), "the check runs only when glibc_check is true");
  assert.ok(build < check && check < pack, "build, then the check, then the pack");
  assert.ok(!raw.some((l) => /glibc_check=true/.test(l) && !/-unknown-linux-gnu\)/.test(l)), "nothing else turns it on");
  assert.deepEqual(
    napiTargets().filter((t) => t.endsWith("-unknown-linux-gnu")),
    ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"],
    "the pattern matches the two gnu targets of package.json",
  );
});

/** The text of `const <name> = ...` in `src` up to its closing `\n}\n`. */
function definition(src: string, name: string): string {
  const start = src.indexOf(`const ${name} = `);
  assert.ok(start >= 0, `${name} is defined`);
  const end = src.indexOf("\n}\n", start);
  assert.ok(end > start, `${name} ends`);
  return src.slice(start, end);
}

/** The positions of `markers` in `src`, each found exactly once, in that order. */
function inOrder(src: string, markers: readonly string[], where: string): void {
  let last = -1;
  for (const m of markers) {
    const at = src.indexOf(m);
    assert.ok(at >= 0, `${where}: ${m}`);
    assert.equal(src.indexOf(m, at + 1), -1, `${where}: ${m} once`);
    assert.ok(at > last, `${where}: ${m} comes after the previous probe`);
    last = at;
  }
}

test("ci-build.sh tells glibc from musl as the loader does: /usr/bin/ldd, the process report, ldd --version", () => {
  // The generated loader (binding.cjs, built before the tests run): isMusl() tries its three
  // probes in this order, each returning null to pass on (review-code.md N4).
  const loader = read(path.join(pkgDir, "binding.cjs"));
  inOrder(definition(loader, "isMusl"), ["isMuslFromFilesystem()", "isMuslFromReport()", "isMuslFromChildProcess()"], "binding.cjs isMusl");
  assert.match(definition(loader, "isMuslFromFilesystem"), /readFileSync\('\/usr\/bin\/ldd', 'utf-8'\)\.includes\('musl'\)/);
  const report = definition(loader, "isMuslFromReport");
  assert.match(report, /process\.report\.excludeNetwork = true\s+report = process\.report\.getReport\(\)/);
  assert.match(report, /glibcVersionRuntime\)\s*\{\s*return false/);
  assert.match(definition(loader, "isFileMusl"), /f\.includes\('libc\.musl-'\) \|\| f\.includes\('ld-musl-'\)/);
  assert.match(definition(loader, "isMuslFromChildProcess"), /execSync\('ldd --version', \{ encoding: 'utf8' \}\)\.includes\('musl'\)/);

  // ci-build.sh's host check makes the same three probes, in the same order, with the same tests.
  const script = codeLines(ciBuildFile).join("\n");
  inOrder(
    script,
    [
      'readFileSync("/usr/bin/ldd", "utf8").includes("musl")',
      "process.report.excludeNetwork = true;",
      "process.report.getReport()",
      "report.header.glibcVersionRuntime",
      'f.includes("libc.musl-") || f.includes("ld-musl-")',
      'execSync("ldd --version", { encoding: "utf8" }).includes("musl")',
    ],
    "ci-build.sh",
  );
  assert.match(script, /name \+= isMusl\(\) \? "-musl" : "-gnu"/, "the libc suffix comes from that order alone");
});

/** The steps of a job block: each `- ...` item of its `steps:` list with the lines under it. */
function stepsOf(job: readonly Line[]): { line: Line; text: string }[] {
  const at = job.findIndex((l) => l.text === "steps:");
  assert.ok(at >= 0, "the job has steps");
  const block = blockUnder(job, at);
  const items = entriesOf(block).map((e) => block.indexOf(e.line));
  return items.map((start, i) => ({
    line: block[start] as Line,
    text: block
      .slice(start, items[i + 1] ?? block.length)
      .map((l) => l.text.replace(/^-\s+/, ""))
      .join("\n"),
  }));
}

test("binding-node.yml runs the compiled tests on Node 22.12.0 exactly, the engines floor, with its own label", () => {
  const { lines } = workflow();
  const pkg: unknown = JSON.parse(read(path.join(pkgDir, "package.json")));
  assert.ok(isRecord(pkg) && isRecord(pkg["engines"]));
  assert.equal(pkg["engines"]["node"], ">=22.12", "the floor the run below proves (ADR 0031 §2)");
  const floor = "22.12.0";
  const label = "x86_64-unknown-linux-gnu-node22.12";

  const steps = stepsOf(jobBlock(lines, "node-versions"));
  const build = steps.findIndex((s) => /ci-build\.sh x86_64-unknown-linux-gnu /.test(s.text));
  assert.ok(build >= 0, "node-versions builds with ci-build.sh first");
  const setup = steps.findIndex((s) => /^uses: actions\/setup-node@/.test(s.text) && /node-version: 22\.12\.0$/m.test(s.text));
  assert.ok(setup > build, `after the build, setup-node installs exactly ${floor} (not a range or 22.x)`);
  const run = steps.findIndex((s) => /\bnode --test\b/.test(s.text));
  assert.ok(run > setup, "then runs node --test");
  const upload = steps.findIndex((s) => s.text.includes(`name: conformance-node-${label}`));
  assert.ok(upload > run, "then uploads its results");
  for (const i of [setup, run, upload]) {
    assert.match(steps[i]?.text ?? "", /^if: matrix\.node == 22$/m, "on the Node 22 leg, whose build is the newest 22.x");
  }

  const floorRun = steps[run]?.text ?? "";
  assert.match(floorRun, /^working-directory: bindings\/node$/m);
  assert.match(floorRun, new RegExp(`^POLYJOSE_CONFORMANCE_SUFFIX: ${label.replace(/\./g, "\\.")}$`, "m"), "its own results label");
  assert.match(floorRun, /\[ "\$\(node --version\)" = v22\.12\.0 \]/, "it checks that the Node it runs is 22.12.0");
  assert.match(floorRun, /for f in dist\/\*\.test\.js; do/, "the already compiled tests ...");
  assert.match(floorRun, /\[ "\$f" = dist\/package\.test\.js \] \|\| tests\+=\("\$f"\)/, "... except package.test.js, as in test.sh");
  assert.match(floorRun, /node --test --test-reporter=spec "\$\{tests\[@\]\}"/);
  assert.doesNotMatch(floorRun, /\b(npm|npx|napi|cargo|tsc)\b|test\.sh|build\.sh/, "nothing is built or installed on 22.12.0");
  assert.match(steps[upload]?.text ?? "", new RegExp(`path: target/conformance/node-${label.replace(/\./g, "\\.")}\\.json`));

  const parity = jobBlock(lines, "parity").map((l) => l.text).join("\n");
  assert.ok(parity.includes(label), `parity requires node-${label}.json`);
});

test("every prebuild job runs the RSA symbol guard on its own runner after the build (review-security.md L2)", () => {
  const { lines } = workflow();
  const guard = "scripts/check-rsa-symbols.sh --only polyjose-node --only polyjose-node-release";
  const steps = stepsOf(jobBlock(lines, "prebuild"));
  assert.equal(steps.map((s) => s.text.split(guard).length - 1).reduce((a, b) => a + b, 0), 2, "the guard runs twice in the job text: native and Alpine");

  // Native runners (every target but musl): a step after ci-build.sh (native), with llvm-tools.
  const build = steps.findIndex((s) => /^name: ci-build\.sh \(native\)$/m.test(s.text));
  const native = steps.findIndex((s) => s.text.includes(guard) && !/docker run/.test(s.text));
  assert.ok(build >= 0 && native > build, "the native guard step comes after the native build");
  const nativeText = steps[native]?.text ?? "";
  assert.match(nativeText, /^if: \$\{\{ !matrix\.image \}\}$/m, "on the same jobs as the native build");
  assert.ok(nativeText.indexOf("rustup component add llvm-tools") >= 0, "the toolchain's llvm-nm and llvm-ar");
  assert.ok(nativeText.indexOf("rustup component add llvm-tools") < nativeText.indexOf(guard));

  // musl: inside the same Alpine container, right after ci-build.sh.
  const alpine = steps.find((s) => /^name: ci-build\.sh \(Alpine\)$/m.test(s.text))?.text ?? "";
  assert.match(alpine, /^if: \$\{\{ matrix\.image \}\}$/m);
  const tools = alpine.indexOf("rustup component add llvm-tools");
  const ciBuild = alpine.indexOf('bindings/node/scripts/ci-build.sh "$TARGET"');
  const inAlpine = alpine.indexOf(guard);
  assert.ok(tools >= 0 && tools < ciBuild && ciBuild < inAlpine, "llvm-tools, then ci-build.sh, then the guard, in Alpine");
});

test("check-rsa-symbols.sh's residual-risk note names the node prebuild targets only binding-node.yml reads", () => {
  const src = read(path.join(repo, "scripts", "check-rsa-symbols.sh"));
  const start = src.indexOf("# Residual risk:");
  assert.ok(start >= 0, "the guard has a residual-risk note");
  const note = src.slice(start, src.indexOf("\n#\n", start));
  // The guard itself builds for the host (aarch64-apple-darwin here); every other napi target is
  // read only by the prebuild job on its own runner.
  for (const target of napiTargets().filter((t) => t !== "aarch64-apple-darwin")) {
    assert.ok(note.includes(target), `the note names ${target}`);
  }
  assert.ok(note.includes("binding-node.yml"), "and where they are checked");
});

/** The workflow's header comment (the lines before `name:`) as one line of prose, without the `#`s. */
const headerProse = (src: string): string =>
  src
    .slice(0, src.indexOf("\nname:"))
    .split(/\r?\n/)
    .map((l) => l.replace(/^#\s?/, "").trim())
    .join(" ")
    .replace(/\s+/g, " ");

/** The text of every `run:` of a workflow: the value and, for a block scalar, the lines under it. */
function runBlocks(lines: readonly Line[]): { line: Line; text: string }[] {
  return lines.flatMap((line, i) => {
    const kv = keyOf(line.text.replace(/^-\s+/, ""));
    if (kv?.key !== "run") return [];
    return [{ line, text: [kv.value, ...blockUnder(lines, i).map((l) => l.text)].join("\n") }];
  });
}

test("no run: block of binding-node.yml interpolates an input; inputs reach scripts through env: (review-security.md I6)", () => {
  // The reader itself: an inputs expression in a block or inline run is found, in env: it is not.
  const sample = yamlLines(
    ["steps:", "  - env:", "      MODE: ${{ inputs.mode }}", "    run: |", '      echo "$MODE"', "  - run: echo ${{ inputs.mode }}"].join("\n"),
  );
  assert.deepEqual(
    runBlocks(sample).map((r) => r.text.includes("${{ inputs.")),
    [false, true],
  );
  const { src, lines } = workflow();
  const runs = runBlocks(lines);
  assert.ok(runs.length > 5, "binding-node.yml has run steps");
  for (const r of runs) {
    assert.ok(!r.text.includes("${{ inputs."), `binding-node.yml:${r.line.no}: an input inside run: (pass it through env:)`);
  }
  // The rule is stated where 0012 will add the inputs.
  assert.ok(headerProse(src).includes("never as `${{ inputs.mode }}` inside `run:`"), "the header states the env:-only rule");
});

test("binding-node.yml pins the Alpine packages, or states the exception and its reason (review-code.md N3)", () => {
  const { src } = workflow();
  const apk = [...src.matchAll(/^\s*apk add (.*)$/gm)];
  assert.equal(apk.length, 1, "one apk add");
  const packages = (apk[0]?.[1] ?? "").split(/\s+/).filter((p) => p !== "" && !p.startsWith("-"));
  assert.ok(packages.length > 0);
  const unpinned = packages.filter((p) => !/^[a-z0-9+._-]+=\S+$/.test(p));
  if (unpinned.length === 0) return;
  const header = headerProse(src);
  const at = header.indexOf("Exception, apk packages (review-code.md N3):");
  assert.ok(at >= 0, "the header states the exception");
  const exception = header.slice(at);
  for (const p of unpinned) assert.ok(exception.includes(p), `the exception names ${p}`);
  assert.ok(exception.includes("keeps one build of each package per release branch"), "and why a version pin would not hold");
});
