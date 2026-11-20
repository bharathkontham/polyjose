// expect-error: jwe-decrypt-json-no-allowed-enc.ts(9,76): error TS2741: Property 'allowedEnc' is missing in type '{ allowedAlgs: string[]; }' but required in type 'JweDecryptOptions'.
// Must not type-check: a JSON JWE decrypt without its enc allow-list (ADR 0007, ADR 0030 §3, RFC 8725 §3.1;
// review N4). Compiled by test.sh against the generated declarations (dist/).
import { createApi, type Backend } from "@polyjose/js-facade";

declare const backend: Backend;

export async function misuse(): Promise<void> {
  await createApi(backend).jweDecryptJson("{}", { kty: "oct", k: "AAAA" }, { allowedAlgs: ["dir"] });
}
