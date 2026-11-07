/**
 * [WASM-pkg-node] The security decisions of ADR 0030 §5-§7 and RFC 8725, as JS call shapes on
 * the installed package (the same checks as 0007 T03 for `@polyjose/node`). The checks live in
 * `security-checks.ts`, shared with the Chrome page and the workerd worker (review N8):
 * - no input in errors (ADR 0030 §5);
 * - a missing `allowedAlgs`/`allowedEnc`, `[]` and `["none"]` are `AlgorithmNotAllowed`
 *   (RFC 8725 §3.1, §3.2; ADR 0031 §1);
 * - mutating the caller's `Uint8Array` after the call has started doesn't change the result
 *   (here on a warm module; `input-copy.test.ts` checks the first call of a process).
 */
import * as api from "@polyjose/wasm";
import { assert, test } from "./node.js";
import type { ProbeCheck } from "./results.js";
import { WARM_COPY, missingAllowLists, noInputInErrors, payloadCopy } from "./security-checks.js";

/** Every check passed; a failing one is reported by its name and detail. */
function assertChecks(checks: readonly ProbeCheck[]): void {
  assert.ok(checks.length > 0, "no checks ran");
  for (const c of checks) assert.ok(c.ok, `${c.what}: ${c.detail}`);
}

await test("no input in errors: JWK, JWS, JWE and JWT failures don't echo key or payload (ADR 0030 §5)", async () => {
  assertChecks(await noInputInErrors(api));
});

await test("a missing allowedAlgs/allowedEnc, [] and ['none'] are AlgorithmNotAllowed (RFC 8725 §3.1)", async () => {
  assertChecks(await missingAllowLists(api));
});

await test(WARM_COPY, async () => {
  assertChecks([await payloadCopy(api, WARM_COPY)]);
});
