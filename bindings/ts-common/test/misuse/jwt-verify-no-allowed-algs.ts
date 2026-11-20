// expect-error: jwt-verify-no-allowed-algs.ts(9,74): error TS2741: Property 'allowedAlgs' is missing in type '{ issuers: string[]; }' but required in type 'JwtVerifyOptions'.
// Must not type-check: a JWT verify without its alg allow-list (ADR 0007, ADR 0030 §3, RFC 8725 §3.1;
// review N4). Compiled by test.sh against the generated declarations (dist/).
import { createApi, type Backend } from "@polyjose/js-facade";

declare const backend: Backend;

export async function misuse(): Promise<void> {
  await createApi(backend).jwtVerify("a.b.c", { kty: "oct", k: "AAAA" }, { issuers: ["https://issuer.example"] });
}
