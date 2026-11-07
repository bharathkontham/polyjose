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
import { assert, fs, path, test } from "../../js/dist/node/builtins.js";

interface NodeUrl {
  fileURLToPath(url: string): string;
}
const host = (globalThis as unknown as { process: { getBuiltinModule(id: "node:url"): NodeUrl } }).process;
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
      // The raw line: build.sh runs napi as "$napi", which the quote stripping would empty.
      const napiLine = raw[i] ?? "";
      if (/\bnapi\b"?[ \t]+build\b/.test(napiLine)) {
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
