/**
 * [WASM-pkg-node] Module formats and `exports` conditions of the installed package
 * (ADR 0031 §3, "Entries and `exports` conditions", and ADR 0063, which drops `worker`;
 * ADR 0031 option 3a):
 * - CommonJS code can `require("@polyjose/wasm")` through `require(esm)` (unflagged since Node
 *   22.12, the package's `engines` floor): it loads the `node` entry, and gets the very same
 *   module as `import`;
 * - `node -C workerd` resolves `workerd.mjs`, and plain `node` resolves `node.mjs` (`workerd`
 *   comes before `node` in the map);
 * - `worker` selects nothing (ADR 0063): `node -C worker` resolves `node.mjs`, and the
 *   `worker` condition without `node`, alone or in webpack's sets for a browser Web Worker,
 *   resolves `browser.mjs`.
 */
import * as esm from "@polyjose/wasm";
import { assert, childProcess, nodeModule, path, process, stageRoot, test } from "./node.js";

const ENTRY = /\/node_modules\/@polyjose\/wasm\/(node|workerd|browser)\.mjs$/;

/** The package entry a child `node <flags> print-resolve.js <args>` resolves. */
function resolvedEntry(flags: readonly string[], args: readonly string[] = []): string {
  const stage = stageRoot(import.meta);
  const argv = [...flags, path.join(stage, "dist", "print-resolve.js"), ...args];
  const run = childProcess.spawnSync(process.execPath, argv, { cwd: stage, encoding: "utf8", timeout: 60_000 });
  const command = `node ${[...flags, "print-resolve.js", ...args].join(" ")}`;
  if (run.error !== undefined) throw run.error;
  assert.equal(run.status, 0, `${command} failed: ${run.stderr}`);
  const entry = ENTRY.exec(run.stdout);
  assert.ok(entry !== null, `${command}: unexpected resolution ${run.stdout}`);
  return `${entry[1]}.mjs`;
}

/** The entry Node's resolver picks under exactly `conditions` (no implicit `node`/`import`). */
function resolvedUnder(conditions: readonly string[]): string {
  return resolvedEntry([], ["--exact-conditions", conditions.join(",")]);
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

await test("node -C workerd resolves workerd.mjs; plain node and node -C worker resolve node.mjs", () => {
  assert.equal(resolvedEntry(["-C", "workerd"]), "workerd.mjs");
  assert.equal(resolvedEntry([]), "node.mjs");
  // Node keeps its own `node` condition beside -C worker; before ADR 0063 this was workerd.mjs.
  assert.equal(resolvedEntry(["-C", "worker"]), "node.mjs");
});

await test("exact condition sets: worker alone and webpack's Web Worker sets resolve browser.mjs (ADR 0063)", () => {
  // The hook replaces Node's set: wrangler's (workerd, worker, browser) still gets the Cloudflare
  // entry, and node with import still gets the Node one.
  assert.equal(resolvedUnder(["workerd", "worker", "browser", "import"]), "workerd.mjs");
  assert.equal(resolvedUnder(["node", "import"]), "node.mjs");

  // The `worker` condition alone (no `node`): only `default` matches, the browser entry.
  assert.equal(resolvedUnder(["worker"]), "browser.mjs");

  // webpack 5.112.2, `target: "webworker"`: lib/config/target.js:183-203 gives the target
  // properties `webworker`, `web` and `browser` (and `node: false`); lib/config/defaults.js:2793
  // turns `webworker` into the `worker` condition (`if (targetProperties.webworker)
  // conditions.push("worker")`), :2795 `web` into `browser`, and an ESM import adds `import`
  // (:2840). First the set as ADR 0063 states it, with the target properties' names beside the
  // conditions, then webpack's exact list for a production ESM import (defaults.js:2786-2797
  // and :2840-2846).
  assert.equal(resolvedUnder(["worker", "webworker", "web", "browser", "import"]), "browser.mjs");
  assert.equal(
    resolvedUnder(["webpack", "production", "worker", "browser", "import", "module-sync", "module"]),
    "browser.mjs",
  );
  // A worker that a `target: "web"` bundle starts with `new Worker(new URL(…))` also gets
  // `worker`, ahead of the ESM set (defaults.js:2851-2856, workerDeps).
  assert.equal(
    resolvedUnder(["webpack", "development", "browser", "worker", "import", "module-sync", "module"]),
    "browser.mjs",
  );
});
