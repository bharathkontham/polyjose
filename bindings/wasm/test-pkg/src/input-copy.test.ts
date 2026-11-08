/**
 * [WASM-pkg-node] Input copy on a cold module (ADR 0030 §7; 0007 T03's "input copy" criterion,
 * applied to `@polyjose/wasm`): the **first** call of a process starts before the WebAssembly
 * module is instantiated (the facade's lazy `ready()`, ADR 0031 §3). Mutating the caller's
 * `Uint8Array` right after starting that call, before awaiting it, must not change what is signed.
 * The check is `security-checks.ts`'s, which the Chrome page and the workerd worker also run
 * first (review N8).
 *
 * This file makes no other call before the one under test, and `node --test` runs every test file
 * in its own process, so the module is cold here.
 */
import * as api from "@polyjose/wasm";
import { assert, test } from "./node.js";
import { COLD_COPY, payloadCopy } from "./security-checks.js";

await test(COLD_COPY, async () => {
  const check = await payloadCopy(api, COLD_COPY);
  assert.ok(check.ok, `${check.what}: ${check.detail}`);
});
