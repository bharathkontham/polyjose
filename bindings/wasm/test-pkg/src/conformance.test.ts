/**
 * [WASM-pkg-node] The installed `@polyjose/wasm` tarball, imported as a user would
 * (`import "@polyjose/wasm"`, which the `node` condition resolves to `node.mjs`; ADR 0031 §3),
 * runs every conformance vector through the shared facade and the shared JS runner
 * (`bindings/js/conformance/node-main.ts`), which writes `target/conformance/wasm-pkg-node.json`
 * (ADR 0034 §2). `scripts/conformance-parity.sh` then compares it with `rust-core`.
 */
import * as api from "@polyjose/wasm";
import { main } from "../js/conformance/node-main.js";
import { assert, repoRoot, resolveFrom, test } from "./node.js";

await test("import resolves the installed package's node entry (ADR 0031 §3)", () => {
  assert.match(resolveFrom(import.meta, "@polyjose/wasm"), /\/node_modules\/@polyjose\/wasm\/node\.mjs$/);
});

await test("wasm-pkg-node: every conformance vector passes through the facade (ADR 0034)", async () => {
  const code = await main(api, { runner: "wasm-pkg-node", root: repoRoot() });
  assert.equal(code, 0, "the runner reported failing vectors (see the FAIL lines above)");
});
