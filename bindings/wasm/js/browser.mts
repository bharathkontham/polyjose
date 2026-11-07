/**
 * The `browser`, `import` and `default` entry of `@polyjose/wasm` (ADR 0031 §3): browsers and
 * bundlers that resolve `new URL("...", import.meta.url)` (webpack 5, Vite, esbuild). On the
 * first call, the glue's `init()` fetches and instantiates the module next to this file. Nothing
 * runs at import time, and there is no top-level await.
 */
import init from "./polyjose_wasm.js";
import { setLoader } from "./backend.js";

setLoader(async () => {
  await init({ module_or_path: new URL("./polyjose_wasm_bg.wasm", import.meta.url) });
});

export * from "./index.js";
