/**
 * The backend contract: what each native layer (`@polyjose/node`'s napi-rs loader,
 * `@polyjose/wasm`'s wasm-bindgen glue) exports for the facade (ADR 0031 §1). Documented in
 * `bindings/js/BACKEND.md`.
 *
 * - Every ADR 0030 §4 operation, camelCase, with the ADR's argument order.
 * - JSON-valued arguments and result fields are JSON **text**; the facade does the
 *   object↔JSON idiom (ADR 0030 §2). Rust parses with the core's strict I-JSON parser.
 * - Records are plain objects with camelCase fields. The facade only ever passes fields it has
 *   validated; an absent optional field is **left out** (never `undefined` or `null`: napi
 *   throws on `null`, research §3).
 * - Integers are already range-checked (u32 sizes and counts, safe-integer `now`), because
 *   wasm-bindgen coerces `-1` to `4294967295` (research §3).
 * - Results may be returned directly or as a Promise (napi `AsyncTask`). Errors are thrown or
 *   rejected with an object whose `code` is one of `errorCodes()` (ADR 0030 §5).
 * - `version()` and `errorCodes()` are synchronous; `ready()` is optional and awaited once,
 *   lazily, before the first call (WASM initialisation without top-level await).
 */

/** A value or a Promise of it. */
export type MaybePromise<T> = T | Promise<T>;

export interface BackendJwkSelector {
  kid?: string;
  alg?: string;
  keyUse?: string;
}

export interface BackendJwsSignOptions {
  protectedHeader?: string;
  protectedB64u?: string;
  detached?: boolean;
}

export interface BackendJwsSigner {
  key: string;
  protectedHeader?: string;
  protectedB64u?: string;
  unprotectedHeader?: string;
}

export interface BackendJwsVerifyOptions {
  allowedAlgs: string[];
  detachedPayload?: Uint8Array;
  maxInputLen?: number;
  maxSignatures?: number;
}

export interface BackendJwsVerified {
  alg: string;
  payload: Uint8Array;
  protectedHeader?: string | null | undefined;
  unprotectedHeader?: string | null | undefined;
  signatureIndex: number;
}

export interface BackendJweRecipient {
  alg: string;
  key: string;
  header?: string;
  apu?: Uint8Array;
  apv?: Uint8Array;
  p2c?: number;
  p2sLen?: number;
}

export interface BackendJweEncryptOptions {
  enc: string;
  recipients: BackendJweRecipient[];
  protectedHeader?: string;
  sharedUnprotectedHeader?: string;
  aad?: Uint8Array;
  compress?: boolean;
}

export interface BackendJweDecryptOptions {
  allowedAlgs: string[];
  allowedEnc: string[];
  maxPbes2Count?: number;
  maxDecompressedLen?: number;
  maxInputLen?: number;
  maxRecipients?: number;
  understoodCrit?: string[];
}

export interface BackendJweDecrypted {
  plaintext: Uint8Array;
  header: string;
  protectedHeader?: string | null | undefined;
  sharedUnprotectedHeader?: string | null | undefined;
  recipientHeader?: string | null | undefined;
  aad?: Uint8Array | null | undefined;
  recipientIndex: number;
}

export interface BackendJwtSignOptions {
  alg: string;
  typ?: string;
  omitTyp?: boolean;
  accessToken?: boolean;
  header?: string;
}

/** `now` is always present: the facade reads the JS clock when the caller gives none (ADR 0030 §4). */
export interface BackendJwtVerifyOptions {
  allowedAlgs: string[];
  now: number;
  issuers?: string[];
  audiences?: string[];
  subject?: string;
  leeway?: number;
  maxAge?: number;
  requiredClaims?: string[];
  allowMissingExp?: boolean;
  ignoreAudience?: boolean;
  typ?: string;
  anyTyp?: boolean;
  profile?: string;
  maxKeyCandidates?: number;
  maxInputLen?: number;
}

export interface BackendJwtVerified {
  claims: string;
  header: string;
  alg: string;
  keyIndex?: number | null | undefined;
  kid?: string | null | undefined;
}

export interface BackendJwtNestedVerified {
  inner: BackendJwtVerified;
  outerHeader: string;
  recipientIndex: number;
}

/** The functions a native layer provides (BACKEND.md). */
export interface Backend {
  /** Optional one-time initialisation, awaited lazily before the first call. */
  ready?(): Promise<void>;
  version(): string;
  errorCodes(): readonly string[];

  base64urlEncode(bytes: Uint8Array): MaybePromise<string>;
  base64urlDecode(text: string): MaybePromise<Uint8Array>;

  jwkParse(jwk: string): MaybePromise<string>;
  jwkToPublic(jwk: string): MaybePromise<string>;
  jwkThumbprint(jwk: string, hash: string): MaybePromise<string>;
  jwkThumbprintUri(jwk: string, hash: string): MaybePromise<string>;
  jwksSelect(jwks: string, selector: BackendJwkSelector): MaybePromise<string>;
  jwkGenerateOct(lenBytes: number): MaybePromise<string>;
  jwkGenerateEc(crv: string): MaybePromise<string>;
  jwkGenerateOkp(crv: string): MaybePromise<string>;
  jwkGenerateForAlg(alg: string): MaybePromise<string>;
  jwkFromPem(pem: string): MaybePromise<string>;
  jwkFromDer(der: Uint8Array, format: string): MaybePromise<string>;
  jwkToPem(jwk: string, format: string): MaybePromise<string>;
  jwkToDer(jwk: string, format: string): MaybePromise<Uint8Array>;

  jwsSignCompact(payload: Uint8Array, key: string, options: BackendJwsSignOptions): MaybePromise<string>;
  jwsSignFlattened(payload: Uint8Array, signer: BackendJwsSigner, detached: boolean): MaybePromise<string>;
  jwsSignGeneral(payload: Uint8Array, signers: BackendJwsSigner[], detached: boolean): MaybePromise<string>;
  jwsVerifyCompact(token: string, key: string, options: BackendJwsVerifyOptions): MaybePromise<BackendJwsVerified>;
  jwsVerifyJson(jws: string, key: string, options: BackendJwsVerifyOptions): MaybePromise<BackendJwsVerified>;

  jweEncryptCompact(plaintext: Uint8Array, options: BackendJweEncryptOptions): MaybePromise<string>;
  jweEncryptJson(plaintext: Uint8Array, options: BackendJweEncryptOptions, form: string): MaybePromise<string>;
  jweDecryptCompact(token: string, key: string, options: BackendJweDecryptOptions): MaybePromise<BackendJweDecrypted>;
  jweDecryptJson(jwe: string, key: string, options: BackendJweDecryptOptions): MaybePromise<BackendJweDecrypted>;

  jwtSign(claims: string, key: string, options: BackendJwtSignOptions): MaybePromise<string>;
  jwtVerify(token: string, key: string, options: BackendJwtVerifyOptions): MaybePromise<BackendJwtVerified>;
  jwtVerifyWithJwks(token: string, jwks: string, options: BackendJwtVerifyOptions): MaybePromise<BackendJwtVerified>;
  jwtEncryptNested(signedJwt: string, options: BackendJweEncryptOptions): MaybePromise<string>;
  jwtDecryptNested(
    token: string,
    decryptKey: string,
    decryptOptions: BackendJweDecryptOptions,
    key: string,
    verifyOptions: BackendJwtVerifyOptions,
  ): MaybePromise<BackendJwtNestedVerified>;
  jwtDecryptNestedWithJwks(
    token: string,
    decryptKey: string,
    decryptOptions: BackendJweDecryptOptions,
    jwks: string,
    verifyOptions: BackendJwtVerifyOptions,
  ): MaybePromise<BackendJwtNestedVerified>;
}
