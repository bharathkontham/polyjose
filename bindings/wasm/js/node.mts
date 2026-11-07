/**
 * The `node` entry of `@polyjose/wasm` (ADR 0031 §3): Node ≥ 22.12, for `import` and, through
 * `require(esm)`, for `require`. On the first call, the module bytes are read next to this file
 * with `readFileSync`, checked against the SHA-384 baked into `integrity.js` at build time, and
 * only then compiled; the backend instantiates the result (0006 F05, audit L1). Nothing runs at
 * import time, and there is no top-level await.
 */
import { setLoader } from "./backend.js";
import { WASM_SHA384 } from "./integrity.js";

/** The Node built-ins used here, typed by hand: there is no @types/node (ADR 0047). */
interface NodeFs {
  readFileSync(path: URL): Uint8Array<ArrayBuffer>;
}

interface NodeHash {
  update(data: Uint8Array): NodeHash;
  digest(encoding: "base64"): string;
}

interface NodeCrypto {
  createHash(algorithm: "sha384"): NodeHash;
}

/** `process.getBuiltinModule` (Node ≥ 22.3), as `bindings/js/node/builtins.ts` uses it. */
interface NodeProcess {
  getBuiltinModule(id: "node:fs"): NodeFs;
  getBuiltinModule(id: "node:crypto"): NodeCrypto;
}

setLoader(() => {
  const { process } = globalThis as unknown as { process: NodeProcess };
  const bytes = process.getBuiltinModule("node:fs").readFileSync(new URL("./polyjose_wasm_bg.wasm", import.meta.url));
  // SHA-384 (FIPS 180-4) of the file as read, the same bytes that are compiled below. The digest
  // is public, so a plain comparison is fine.
  const digest = process.getBuiltinModule("node:crypto").createHash("sha384").update(bytes).digest("base64");
  if (digest !== WASM_SHA384) {
    throw new Error("polyjose: polyjose_wasm_bg.wasm does not have the SHA-384 this package was built with; refusing to load it");
  }
  return WebAssembly.compile(bytes);
});

export * from "./index.js";
