/**
 * `@polyjose/node`: the shared facade (`bindings/js`, ADR 0031 §1, ADR 0047) bound once to the
 * napi-rs backend (ADR 0031 §2), re-exported as the package's API (BACKEND.md, "A package entry").
 *
 * Every operation of ADR 0030 §4 returns a Promise and runs on the libuv thread pool; a core
 * failure rejects with a `PolyjoseError` whose `code` is one of `ERROR_CODES` (ADR 0030 §5).
 * ESM only; CommonJS callers load it with `require()` (require(esm), Node >= 22.12, ADR 0031 §3).
 */

import { createApi } from "./facade/api.js";
import { backend } from "./backend.js";

export const {
  version,
  errorCodes,
  base64urlEncode,
  base64urlDecode,
  jwkParse,
  jwkToPublic,
  jwkThumbprint,
  jwkThumbprintUri,
  jwksSelect,
  jwkGenerateOct,
  jwkGenerateEc,
  jwkGenerateOkp,
  jwkGenerateForAlg,
  jwkFromPem,
  jwkFromDer,
  jwkToPem,
  jwkToDer,
  jwsSignCompact,
  jwsSignFlattened,
  jwsSignGeneral,
  jwsVerifyCompact,
  jwsVerifyJson,
  jweEncryptCompact,
  jweEncryptJson,
  jweDecryptCompact,
  jweDecryptJson,
  jwtSign,
  jwtVerify,
  jwtVerifyWithJwks,
  jwtEncryptNested,
  jwtDecryptNested,
  jwtDecryptNestedWithJwks,
  PolyjoseError,
} = createApi(backend);

export { ERROR_CODES } from "./facade/api.js";
export type * from "./facade/api.js";
