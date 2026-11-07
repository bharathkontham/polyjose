/**
 * [WASM-pkg-node] Module formats and `exports` conditions of the installed package
 * (ADR 0031 §3, "Entries and `exports` conditions"; ADR 0031 option 3a):
 * - CommonJS code can `require("@polyjose/wasm")` through `require(esm)` (unflagged since Node
 *   22.12, the package's `engines` floor): it loads the `node` entry, and gets the very same
 *   module as `import`;
 * - `node -C workerd` and `node -C worker` resolve `workerd.mjs`, and plain `node` resolves
 *   `node.mjs` (the `workerd`/`worker` conditions come before `node` in the map).
 */
import * as esm from "@polyjose/wasm";
import { assert, childProcess, nodeModule, path, process, stageRoot, test } from "./node.js";

const ENTRY = /\/node_modules\/@polyjose\/wasm\/(node|workerd|browser)\.mjs$/;

/** The package entry a child `node <flags> print-resolve.js` resolves. */
function resolvedEntry(flags: readonly string[]): string {
  const stage = stageRoot(import.meta);
  const run = childProcess.spawnSync(process.execPath, [...flags, path.join(stage, "dist", "print-resolve.js")], {
    cwd: stage,
    encoding: "utf8",
    timeout: 60_000,
  });
  if (run.error !== undefined) throw run.error;
  assert.equal(run.status, 0, `node ${flags.join(" ")} print-resolve.js failed: ${run.stderr}`);
  const entry = ENTRY.exec(run.stdout);
  assert.ok(entry !== null, `node ${flags.join(" ")}: unexpected resolution ${run.stdout}`);
  return `${entry[1]}.mjs`;
}

await test("require(esm): require('@polyjose/wasm') loads node.mjs and is the import's module", async () => {
  const require = nodeModule.createRequire(import.meta.url);
  assert.match(require.resolve("@polyjose/wasm"), /\/node_modules\/@polyjose\/wasm\/node\.mjs$/);
  const cjs = require("@polyjose/wasm") as typeof esm;
  assert.equal(cjs.jwsSignCompact, esm.jwsSignCompact, "require and import must share one module instance");
  assert.equal(cjs.PolyjoseError, esm.PolyjoseError);

  // It works, not only loads: an HS256 round trip (RFC 7515 §3.1), and a PolyjoseError.
  const key = await cjs.jwkGenerateOct(32);
  const payload = new TextEncoder().encode("required");
  const token = await cjs.jwsSignCompact(payload, key, { protectedHeader: { alg: "HS256" } });
  const verified = await cjs.jwsVerifyCompact(token, key, { allowedAlgs: ["HS256"] });
  assert.deepEqual(Array.from(verified.payload), Array.from(payload));
  await assert.rejects(cjs.jwsVerifyCompact(token, key, { allowedAlgs: ["ES256"] }), (e: unknown) => {
    assert.ok(e instanceof cjs.PolyjoseError);
    assert.equal(e.code, "AlgorithmNotAllowed");
    return true;
  });
});

await test("node -C workerd and -C worker resolve workerd.mjs; plain node resolves node.mjs", () => {
  assert.equal(resolvedEntry(["-C", "workerd"]), "workerd.mjs");
  assert.equal(resolvedEntry(["-C", "worker"]), "workerd.mjs");
  assert.equal(resolvedEntry([]), "node.mjs");
});
