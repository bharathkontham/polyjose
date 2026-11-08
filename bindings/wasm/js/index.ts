/**
 * The `@polyjose/wasm` API: the shared facade bound to the wasm backend (BACKEND.md, "A package
 * entry"; ADR 0031 §1). Every runtime entry re-exports exactly this module, so the package has
 * one export list and one set of declarations, which the `types` condition points at
 * (ADR 0047).
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
