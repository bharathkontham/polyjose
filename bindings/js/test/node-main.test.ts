// node-main: reads conformance/vectors/**/*.json, runs them and writes the ADR 0034 results file.
import { assert, fs, os, path, process, test } from "../node/builtins.js";
import { createApi } from "../src/api.js";
import { ERROR_CODES } from "../src/error-codes.js";
import { main, runConformance } from "../conformance/node-main.js";
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
    assert.deepEqual(Object.keys(written), ["runner", "polyjose", "features", "error_codes", "results"]);
    assert.equal(written["runner"], "node");
    assert.equal(written["polyjose"], "0.1.0");
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

test("a runner name that isn't a plain identifier is refused", async () => {
  await assert.rejects(runConformance(api(), { runner: "../escape", root: REPO }), TypeError);
});
