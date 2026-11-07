/**
 * [WASM-pkg-node] Input copy on a cold module (ADR 0030 §7; 0007 T03's "input copy" criterion,
 * applied to `@polyjose/wasm`): the **first** call of a process starts before the WebAssembly
 * module is instantiated (the facade's lazy `ready()`, ADR 0031 §3). Mutating the caller's
 * `Uint8Array` right after starting that call, before awaiting it, must not change what is signed.
 *
 * This file makes no other call before the one under test, and `node --test` runs every test file
 * in its own process, so the module is cold here.
 */
import * as api from "@polyjose/wasm";
import { assert, test } from "./node.js";

/** RFC 7515 Appendix A.1's HMAC key: no API call is needed to make it. */
const KEY = {
  kty: "oct",
  k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
};

await test("mutating the payload after the first jwsSignCompact starts doesn't change what is signed (cold)", async () => {
  const original = [1, 2, 3, 4, 5, 6, 7, 8];
  const payload = new Uint8Array(original);
  const pending = api.jwsSignCompact(payload, KEY, { protectedHeader: { alg: "HS256" } });
  payload.fill(0xee);
  const verified = await api.jwsVerifyCompact(await pending, KEY, { allowedAlgs: ["HS256"] });
  assert.deepEqual(Array.from(verified.payload), original);
});
