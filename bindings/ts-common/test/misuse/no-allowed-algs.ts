// expect-error: no-allowed-algs.ts(
// expect-error: Property 'allowedAlgs' is missing
// Must not type-check: a verify without its allow-list (ADR 0007, RFC 8725 §3.1). Compiled by
// test.sh against the generated declarations (the package's own name resolves to dist/).
import { createApi, type Backend } from "@polyjose/js-facade";

declare const backend: Backend;

export async function misuse(): Promise<void> {
  await createApi(backend).jwsVerifyCompact("a.b.c", { kty: "oct", k: "AAAA" }, {});
}
