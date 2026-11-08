/**
 * The `workerd` entry of `@polyjose/wasm` (ADR 0031 §3; ADR 0063 dropped `worker`): Cloudflare
 * Workers. The static `.wasm` import is a compiled `WebAssembly.Module` there, because Workers
 * forbid compiling wasm from bytes at run time (0006 research §5). On the first call, the backend
 * instantiates it, refusing a glue that other code initialised first and a module of another
 * version (0006 F05, audit L1). There is no top-level await.
 */
import wasmModule from "./polyjose_wasm_bg.wasm";
import { setLoader } from "./backend.js";

// No byte check here, by owner decision (2026-11-07, feature 0006 F05, audit L1, option A):
// - the static import gives a compiled WebAssembly.Module, never its bytes, and a Module exposes
//   none (only exports/imports/customSections);
// - Workers forbid compiling wasm from bytes, so the bytes can't be hashed first and then compiled;
// - a hash baked into the package reaches the Worker in the same deploy upload as the module, so
//   whoever could swap the module could swap the hash: it would add nothing.
// An exports/imports shape check is deliberately absent too: the audit's forged module has the same
// shape. What protects this entry is the backend's one-shot loader, its check that this package's
// call is the one that initialised the glue, and its version check.
setLoader(() => wasmModule);

export * from "./index.js";
