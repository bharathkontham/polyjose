/**
 * The `browser`, `import` and `default` entry of `@polyjose/wasm` (ADR 0031 §3): browsers and
 * bundlers that resolve `new URL("...", import.meta.url)` (webpack 5, Vite, esbuild). On the
 * first call, the module next to this file is fetched with the SHA-384 baked into
 * `integrity.js` at build time as its `integrity` (W3C Subresource Integrity, Fetch), so the
 * browser refuses any other bytes, and only then compiled; the backend instantiates the result
 * (0006 F05, audit L1). Nothing runs at import time, and there is no top-level await.
 */
import { setLoader } from "./backend.js";
import { WASM_SHA384 } from "./integrity.js";

setLoader(async () => {
  const integrity = `sha384-${WASM_SHA384}`;
  let response: Response;
  try {
    response = await fetch(new URL("./polyjose_wasm_bg.wasm", import.meta.url), { integrity });
  } catch (e) {
    // Fetch reports an integrity mismatch as a network error, so it lands here (W3C SRI, Fetch).
    throw new Error(`polyjose: could not fetch polyjose_wasm_bg.wasm with integrity ${integrity} (a different file, or a network error)`, { cause: e });
  }
  if (!response.ok) {
    throw new Error(`polyjose: fetching polyjose_wasm_bg.wasm failed: ${response.status} ${response.statusText}`);
  }
  return WebAssembly.compile(await response.arrayBuffer());
});

export * from "./index.js";
