// node-main: reads conformance/vectors/**/*.json, runs them and writes the ADR 0034 results file.
import { assert, fs, os, path, process, test } from "../node/builtins.js";
import { createApi } from "../src/api.js";
import { ERROR_CODES } from "../src/error-codes.js";
import { main, runConformance, RUNNER_NAMES } from "../conformance/node-main.js";
import { schemaViolation } from "../conformance/schema.js";
import { toyBackend } from "./toy-backend.js";

const FIXTURES = path.resolve(process.cwd(), "test/fixtures/vectors");
const REPO = path.resolve(process.cwd(), "../..");

/** A scratch repo root with conformance/schema.json and a copy of some fixture files. */
function scratchRoot(copy: (rel: string) => boolean = () => true): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "polyjose-js-runner-"));
  fs.mkdirSync(path.join(root, "conformance/vectors"), { recursive: true });
  fs.writeFileSync(path.join(root, "conformance/schema.json"), fs.readFileSync(path.join(REPO, "conformance/schema.json"), "utf8"));
  const walk = (dir: string): void => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      const rel = path.relative(FIXTURES, p);
      if (e.isDirectory()) walk(p);
      else if (copy(rel)) {
        fs.mkdirSync(path.dirname(path.join(root, "conformance/vectors", rel)), { recursive: true });
        fs.writeFileSync(path.join(root, "conformance/vectors", rel), fs.readFileSync(p, "utf8"));
      }
    }
  };
  walk(FIXTURES);
  return root;
}

const api = () => createApi(toyBackend().backend);

test("writes target/conformance/<runner>.json with runner, version, features, error codes and results", async () => {
  const root = scratchRoot();
  try {
    const summary = await runConformance(api(), { runner: "node", root });
    assert.equal(summary.file, path.join(root, "target/conformance/node.json"));
    assert.equal(summary.failed, 0);
    assert.equal(summary.skipped, 2);
    assert.equal(summary.passed + summary.skipped, summary.total);
    const written = JSON.parse(fs.readFileSync(summary.file, "utf8")) as Record<string, unknown>;
    assert.deepEqual(Object.keys(written), ["runner", "polyjose", "vectors_digest", "features", "error_codes", "results"]);
    assert.equal(written["runner"], "node");
    assert.equal(written["polyjose"], "0.1.1");
    assert.match(String(written["vectors_digest"]), /^[0-9a-f]{64}$/);
    assert.deepEqual(written["features"], []);
    assert.deepEqual(written["error_codes"], [...ERROR_CODES]);
    const results = written["results"] as { id: string }[];
    assert.equal(results.length, summary.total);
    // Recursive, sorted, ids relative to conformance/vectors with "/" separators.
    assert.ok(results.some((r) => r.id === "jwt/issue-roundtrip.json#0"));
    assert.deepEqual(results.map((r) => r.id), [...results.map((r) => r.id)].sort());
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("main returns 1 and prints the failure when a vector fails, 0 when all pass", async () => {
  const root = scratchRoot((rel) => rel.startsWith("b64url"));
  try {
    assert.equal(await main(api(), { runner: "wasm-pkg-node", root }), 0);
    fs.writeFileSync(path.join(root, "conformance/vectors/b64url/broken.json"), '{"source":"polyjose"}');
    assert.equal(await main(api(), { runner: "wasm-pkg-node", root }), 1);
    const written = JSON.parse(fs.readFileSync(path.join(root, "target/conformance/wasm-pkg-node.json"), "utf8")) as { results: { id: string; status: string }[] };
    assert.equal(written.results.find((r) => r.id === "b64url/broken.json#0")?.status, "fail");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("no vector files is a failure, never a vacuous pass", async () => {
  const root = scratchRoot(() => false);
  try {
    await assert.rejects(runConformance(api(), { runner: "node", root }), /no vector files/);
    assert.equal(await main(api(), { runner: "node", root }), 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("vectors_digest is the ADR 0060 §4 worked example's, from the raw bytes read (BOM and LF kept)", async () => {
  const root = scratchRoot(() => false);
  const vectors = path.join(root, "conformance/vectors");
  try {
    fs.mkdirSync(path.join(vectors, "jws"), { recursive: true });
    fs.mkdirSync(path.join(vectors, "jws-x"), { recursive: true });
    fs.writeFileSync(path.join(vectors, "a.json"), "{}");
    fs.writeFileSync(path.join(vectors, "jws/b.json"), "{}\n");
    fs.writeFileSync(path.join(vectors, "jws-x/c.json"), "\u{feff}{}");
    fs.writeFileSync(path.join(vectors, "README.md"), "notes");
    const summary = await runConformance(api(), { runner: "node", root });
    assert.equal(summary.total, 3, "README.md is not a vector");
    const written = JSON.parse(fs.readFileSync(summary.file, "utf8")) as { vectors_digest: string };
    assert.equal(written.vectors_digest, "9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a run that reads no vector file writes no results file (ADR 0060 §3)", async () => {
  const root = scratchRoot((rel) => rel.startsWith("b64url"));
  const vectors = path.join(root, "conformance/vectors");
  try {
    // Only a symbolic link: it fails and gets no digest line, so nothing was read.
    const target = path.join(root, "outside.json");
    fs.writeFileSync(target, fs.readFileSync(path.join(vectors, "b64url/encode.json"), "utf8"));
    fs.rmSync(vectors, { recursive: true, force: true });
    fs.mkdirSync(vectors, { recursive: true });
    fs.symlinkSync(target, path.join(vectors, "link.json"));
    await assert.rejects(runConformance(api(), { runner: "node", root }), /no vector file could be read/);
    assert.ok(!fs.existsSync(path.join(root, "target/conformance/node.json")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a symbolic link is a failing result, not a followed or skipped file", async () => {
  const root = scratchRoot((rel) => rel.startsWith("b64url"));
  try {
    fs.symlinkSync(path.join(root, "conformance/vectors/b64url/encode.json"), path.join(root, "conformance/vectors/b64url/link.json"));
    const summary = await runConformance(api(), { runner: "node", root });
    assert.equal(summary.failed, 1);
    assert.match(summary.failures[0] ?? "", /symbolic link/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

/** The runner names of ADR 0034 §2, copied from the ADR (not from conformance/node-main.ts). */
const ADR_0034_RUNNERS = [
  "rust-core",
  "rust-surface",
  "wasm-node",
  "wasm-chrome",
  "wasm-pkg-node",
  "wasm-pkg-chrome",
  "wasm-pkg-workerd",
  "node",
  "jvm",
  "android-emulator",
  "swift-macos",
  "swift-ios-sim",
  "swift-tvos-sim",
];

test("RUNNER_NAMES is ADR 0034 §2's list", () => {
  assert.deepEqual([...RUNNER_NAMES], ADR_0034_RUNNERS);
});

test("a CI matrix suffix goes in the file name only; the runner member stays the bare name (B01)", async () => {
  const root = scratchRoot((rel) => rel.startsWith("b64url"));
  try {
    const summary = await runConformance(api(), { runner: "node", suffix: "x86_64-unknown-linux-musl", root });
    assert.equal(summary.file, path.join(root, "target/conformance/node-x86_64-unknown-linux-musl.json"));
    const written = JSON.parse(fs.readFileSync(summary.file, "utf8")) as { runner: string };
    assert.equal(written.runner, "node");
    assert.ok(ADR_0034_RUNNERS.includes(written.runner));
    assert.ok(!fs.existsSync(path.join(root, "target/conformance/node.json")), "no unsuffixed file is written too");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a runner name outside ADR 0034 §2, or a suffixed or path-like name, is refused (B01)", async () => {
  for (const runner of ["node-x86_64-unknown-linux-musl", "nodejs", "Node", "", "../escape", "rust-core-deflate"]) {
    await assert.rejects(runConformance(api(), { runner: runner as "node", root: REPO }), TypeError, runner);
  }
  for (const suffix of ["", "../x", "a/b", "-lead", "UPPER", "a b"]) {
    await assert.rejects(runConformance(api(), { runner: "node", suffix, root: REPO }), TypeError, suffix);
  }
  assert.equal(await main(api(), { runner: "nodejs" as "node", root: REPO }), 1);
});

test("the results file validates against conformance/schema/results.schema.json (when present)", async (t) => {
  // results.schema.json lands with 0013 T02; until that merges into this branch, skip (never pass).
  const schemaFile = path.join(REPO, "conformance/schema/results.schema.json");
  if (!fs.existsSync(schemaFile)) {
    t.skip("conformance/schema/results.schema.json is not in this tree yet (0013 T02)");
    return;
  }
  const schema = JSON.parse(fs.readFileSync(schemaFile, "utf8")) as { properties: { runner: { enum: string[] } } };
  assert.deepEqual([...RUNNER_NAMES], schema.properties.runner.enum, "node-main's runner list is the schema's enum");
  const root = scratchRoot();
  try {
    for (const options of [{ runner: "node" as const }, { runner: "wasm-pkg-node" as const, suffix: "linux-x64" }]) {
      const summary = await runConformance(api(), { ...options, root });
      assert.equal(schemaViolation(schema, JSON.parse(fs.readFileSync(summary.file, "utf8"))), undefined);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("vectors_digest over an edge corpus equals the independent oracle (non-ASCII ids by UTF-8 bytes, non-UTF-8 bytes as read, symlink without a line)", async () => {
  // Expected value: a Python hashlib walk and the ADR 0060 §4 shell reference over the same files.
  const root = scratchRoot(() => false);
  const vectors = path.join(root, "conformance/vectors");
  try {
    const files: [string, number[]][] = [
      ["a.json", [0x7b, 0x7d]],
      ["jws/b.json", [0x7b, 0x7d, 0x0a]],
      ["jws-x/c.json", [0xef, 0xbb, 0xbf, 0x7b, 0x7d]],
      ["\u{e9}/d.json", [0x7b, 0x7d]],
      ["\u{ff61}.json", [0x31]],
      ["\u{1f600}.json", [0x32]],
      ["bad.json", [0xff, 0xfe, 0x7b, 0x7d]],
    ];
    for (const [rel, octets] of files) {
      fs.mkdirSync(path.dirname(path.join(vectors, rel)), { recursive: true });
      fs.writeFileSync(path.join(vectors, rel), Uint8Array.from(octets) as unknown as string /* the shim types only string data; Node writes the bytes */);
    }
    fs.symlinkSync("a.json", path.join(vectors, "link.json"));
    const summary = await runConformance(api(), { runner: "node", root });
    assert.equal(summary.total, 8, "7 files and the link (a fail, no digest line)");
    const written = JSON.parse(fs.readFileSync(summary.file, "utf8")) as { vectors_digest: string };
    assert.equal(written.vectors_digest, "c743cb52d786b61176972303ee0cfa56b8940d655723a9a3debfe691760ead93");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
