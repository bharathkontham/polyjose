/**
 * The `workerd` and `worker` entry of `@polyjose/wasm` (ADR 0031 §3): Cloudflare Workers. The
 * static `.wasm` import is a compiled `WebAssembly.Module` there, because Workers forbid
 * compiling wasm from bytes at run time (0006 research §5). On the first call, the glue's
 * `initSync({ module })` instantiates it. There is no top-level await.
 */
import wasmModule from "./polyjose_wasm_bg.wasm";
import { initSync } from "./polyjose_wasm.js";
import { setLoader } from "./backend.js";

setLoader(() => {
  initSync({ module: wasmModule });
});

export * from "./index.js";
