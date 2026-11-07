// A package entry exactly as @polyjose/node and @polyjose/wasm write theirs (BACKEND.md), bound
// to the fake backend: the bound API is re-exported by destructuring createApi's result.
import { createApi } from "../src/api.js";
import { fakeBackend } from "./fake-backend.js";

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
} = createApi(fakeBackend().backend);

export { ERROR_CODES } from "../src/api.js";
export type * from "../src/api.js";
