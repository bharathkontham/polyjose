/**
 * The `node` entry of `@polyjose/wasm` (ADR 0031 §3): Node ≥ 22.12, for `import` and, through
 * `require(esm)`, for `require`. On the first call, the module bytes are read next to this file
 * with `readFileSync` and instantiated with the glue's `initSync`. Nothing runs at import time,
 * and there is no top-level await.
 */
import { initSync } from "./polyjose_wasm.js";
import { setLoader } from "./backend.js";

/** The one Node built-in used here. Typed by hand: there is no @types/node (ADR 0047). */
interface NodeFs {
  readFileSync(path: URL): Uint8Array<ArrayBuffer>;
}

/** `process.getBuiltinModule` (Node ≥ 22.3), as `bindings/js/node/builtins.ts` uses it. */
interface NodeProcess {
  getBuiltinModule(id: "node:fs"): NodeFs;
}

setLoader(() => {
  const { process } = globalThis as unknown as { process: NodeProcess };
  const bytes = process.getBuiltinModule("node:fs").readFileSync(new URL("./polyjose_wasm_bg.wasm", import.meta.url));
  initSync({ module: bytes });
});

export * from "./index.js";
