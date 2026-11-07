/**
 * The polyjose JS facade (ADR 0030, ADR 0031 §1, ADR 0047), shared unchanged by
 * `@polyjose/node` and `@polyjose/wasm`. Each package's entry binds it to its native layer:
 *
 * ```ts
 * export const { version, errorCodes, jwsVerifyCompact, ... } = createApi(backend);
 * export { PolyjoseError, ERROR_CODES } from "./api.js";
 * ```
 *
 * The facade adds idiom only (ADR 0030 §1): Promises, object↔JSON, JS type checks
 * (`TypeError`), `null` → `undefined`, the JS clock for JWT `now`, and `PolyjoseError`.
 * Policy, defaults and every JOSE check stay in the core.
 */

import type {
  Backend,
  BackendJweDecryptOptions,
  BackendJweEncryptOptions,
  BackendJweRecipient,
  BackendJwkSelector,
  BackendJwsSigner,
  BackendJwsSignOptions,
  BackendJwsVerifyOptions,
  BackendJwtSignOptions,
  BackendJwtVerifyOptions,
  MaybePromise,
} from "./backend.js";
import { ERROR_CODES, type ErrorCode } from "./error-codes.js";
import {
  allowList,
  bare,
  bool,
  bytes,
  isAbsent,
  json,
  list,
  member,
  optBool,
  optBytes,
  optJson,
  optSeconds,
  optStr,
  optStrList,
  optU32,
  outBytes,
  outIndex,
  outList,
  outObject,
  outStr,
  put,
  record,
  str,
  u32,
  wipe,
} from "./normalize.js";
import type {
  EcCurve,
  JsonInput,
  JsonObject,
  JweDecrypted,
  JweDecryptOptions,
  JweEncryptOptions,
  JweJsonForm,
  Jwk,
  JwkObject,
  JwkSelector,
  JwkSet,
  JwsSigner,
  JwsSignOptions,
  JwsVerified,
  JwsVerifyOptions,
  JwtNestedVerified,
  JwtSignOptions,
  JwtVerified,
  JwtVerifyOptions,
  KeyFormat,
  OkpCurve,
  ThumbprintHash,
} from "./types.js";

export type * from "./types.js";
export type { Backend } from "./backend.js";
export { ERROR_CODES, type ErrorCode } from "./error-codes.js";

/**
 * A polyjose failure (ADR 0030 §5). `code` is one of {@link ERROR_CODES}, the core's stable
 * `Error::code()` (ADR 0007): match on it, never on `message`, which may be reworded. Neither
 * ever contains key material or input bytes.
 */
export class PolyjoseError extends Error {
  override readonly name = "PolyjoseError";
  /** The stable error code. */
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

/** Every operation of ADR 0030 §4, camelCase (§2), each returning a Promise (ADR 0031 §1). */
export interface PolyjoseApi {
  /** The polyjose crate version. */
  version(): Promise<string>;
  /** The stable error codes, equal to the core's `Error::CODES` (ADR 0030 §5). */
  errorCodes(): Promise<string[]>;

  /** base64url without padding (RFC 4648 §5, RFC 7515 §2). */
  base64urlEncode(bytes: Uint8Array): Promise<string>;
  /** Strict, canonical base64url decoding (RFC 4648 §5, §3.5). */
  base64urlDecode(text: string): Promise<Uint8Array>;

  /** Validates a JWK (RFC 7517 §4, RFC 7518 §6, RFC 8037 §2) and returns the core's serialization. */
  jwkParse(jwk: Jwk): Promise<JwkObject>;
  /** The public half of a JWK (RFC 7517 §4, RFC 7518 §6.2.1, §6.3.1). */
  jwkToPublic(jwk: Jwk): Promise<JwkObject>;
  /**
   * The JWK Thumbprint (RFC 7638 §3, §3.4), base64url: 43, 64 or 86 characters for SHA-256,
   * SHA-384 or SHA-512. An absent `hash` (or `null`) is the core default, SHA-256 (ADR 0054 §9,
   * RFC 9278 §5). Any other name fails with `UnsupportedAlgorithm` from the core, after the key's
   * own import errors (ADR 0057 §2). Never publish the thumbprint of a password or other
   * low-entropy `oct` key, or use it as a `kid`: it is an unsalted fast hash of the secret
   * (ADR 0057 §4, RFC 7638 §7).
   */
  jwkThumbprint(jwk: Jwk, hash?: ThumbprintHash): Promise<string>;
  /**
   * The JWK Thumbprint URI (RFC 9278 §3), `urn:ietf:params:oauth:jwk-thumbprint:<name>:<thumbprint>`,
   * always with the IANA hash name (`sha-256`, `sha-384`, `sha-512`; RFC 9278 §4). `hash` is as
   * for `jwkThumbprint`.
   */
  jwkThumbprintUri(jwk: Jwk, hash?: ThumbprintHash): Promise<string>;
  /**
   * The one key of a JWK Set (RFC 7517 §5) that `selector` picks by `kid`, `alg` and `keyUse`,
   * under the core rule (`JwkSet::select`, ADR 0054 §2). An absent selector (or `{}`) matches
   * every member. No match rejects with `NoMatchingKey`, two or more with `MultipleMatchingKeys`
   * (RFC 7517 §5.1 gives a set's order no meaning); an `alg` or `keyUse` the core refuses with
   * `UnsupportedAlgorithm`, after the set's own import errors (ADR 0054 §4).
   *
   * The key may be private (`d`, `k`): call `jwkToPublic` before publishing it. Selection never
   * authorizes an algorithm, so pass the key only to an operation with an allow-list, and pair a
   * `kid` from an untrusted header with `alg` (ADR 0054 §7). A server maps `NoMatchingKey` and
   * `MultipleMatchingKeys` to one opaque client error, such as `invalid_token` (RFC 6750 §3.1).
   */
  jwksSelect(jwks: JwkSet, selector?: JwkSelector): Promise<JwkObject>;
  /** A random `oct` key of `lenBytes` octets (RFC 7518 §6.4), from the OS CSPRNG (ADR 0005). */
  jwkGenerateOct(lenBytes: number): Promise<JwkObject>;
  /** A random EC private key (RFC 7518 §6.2). */
  jwkGenerateEc(crv: EcCurve): Promise<JwkObject>;
  /** A random OKP private key (RFC 8037 §2). */
  jwkGenerateOkp(crv: OkpCurve): Promise<JwkObject>;
  /** A random key for a JWS `alg`, JWE `alg` or `enc` (RFC 7518 §7.1 registry), with `alg` set. */
  jwkGenerateForAlg(alg: string): Promise<JwkObject>;
  /** Imports one RFC 7468 PEM block (ADR 0018 §3). */
  jwkFromPem(pem: string): Promise<JwkObject>;
  /** Imports DER in the structure `format` names; no sniffing (ADR 0018 §3, ADR 0007). */
  jwkFromDer(der: Uint8Array, format: KeyFormat): Promise<JwkObject>;
  /** Exports a JWK as PEM (RFC 7468, ADR 0018 §3). */
  jwkToPem(jwk: Jwk, format: KeyFormat): Promise<string>;
  /** Exports a JWK as DER (ADR 0018 §3). */
  jwkToDer(jwk: Jwk, format: KeyFormat): Promise<Uint8Array>;

  /** Signs in the JWS Compact Serialization (RFC 7515 §5.1, §7.1). */
  jwsSignCompact(payload: Uint8Array, key: Jwk, options: JwsSignOptions): Promise<string>;
  /** Signs in the flattened JWS JSON Serialization (RFC 7515 §7.2.2); returns JSON text. */
  jwsSignFlattened(payload: Uint8Array, signer: JwsSigner, detached?: boolean): Promise<string>;
  /** Signs in the general JWS JSON Serialization (RFC 7515 §7.2.1); returns JSON text. */
  jwsSignGeneral(payload: Uint8Array, signers: readonly JwsSigner[], detached?: boolean): Promise<string>;
  /** Verifies a compact JWS against an explicit allow-list (RFC 7515 §5.2, RFC 8725 §3.1). */
  jwsVerifyCompact(token: string, key: Jwk, options: JwsVerifyOptions): Promise<JwsVerified>;
  /** Verifies a flattened or general JWS JSON Serialization (RFC 7515 §7.2, §5.2). */
  jwsVerifyJson(jws: JsonInput, key: Jwk, options: JwsVerifyOptions): Promise<JwsVerified>;

  /** Encrypts to one recipient in the JWE Compact Serialization (RFC 7516 §5.1, §7.1). */
  jweEncryptCompact(plaintext: Uint8Array, options: JweEncryptOptions): Promise<string>;
  /** Encrypts in a JWE JSON Serialization (RFC 7516 §7.2); returns JSON text. */
  jweEncryptJson(plaintext: Uint8Array, options: JweEncryptOptions, form: JweJsonForm): Promise<string>;
  /** Decrypts a compact JWE against explicit allow-lists (RFC 7516 §5.2, RFC 8725 §3.1). */
  jweDecryptCompact(token: string, key: Jwk, options: JweDecryptOptions): Promise<JweDecrypted>;
  /** Decrypts a flattened or general JWE JSON Serialization (RFC 7516 §7.2, §5.2). */
  jweDecryptJson(jwe: JsonInput, key: Jwk, options: JweDecryptOptions): Promise<JweDecrypted>;

  /** Issues a signed JWT (RFC 7519 §7.1; ADR 0027 §8). */
  jwtSign(claims: JsonInput, key: Jwk, options: JwtSignOptions): Promise<string>;
  /** Validates a signed JWT with one key (RFC 7519 §7.2; ADR 0027 policy and error order). */
  jwtVerify(token: string, key: Jwk, options: JwtVerifyOptions): Promise<JwtVerified>;
  /** Validates a signed JWT with a JWK Set (RFC 7517 §5; ADR 0029 selection). */
  jwtVerifyWithJwks(token: string, jwks: JwkSet, options: JwtVerifyOptions): Promise<JwtVerified>;
  /** Encrypts a signed JWT as a nested JWT, `cty: "JWT"` (RFC 7519 §5.2, §11.2; ADR 0027 §7). */
  jwtEncryptNested(signedJwt: string, options: JweEncryptOptions): Promise<string>;
  /** Decrypts and validates a nested JWT with one verification key (RFC 7519 §7.2 step 8). */
  jwtDecryptNested(
    token: string,
    decryptKey: Jwk,
    decryptOptions: JweDecryptOptions,
    key: Jwk,
    verifyOptions: JwtVerifyOptions,
  ): Promise<JwtNestedVerified>;
  /** Decrypts and validates a nested JWT with a JWK Set for the inner signature. */
  jwtDecryptNestedWithJwks(
    token: string,
    decryptKey: Jwk,
    decryptOptions: JweDecryptOptions,
    jwks: JwkSet,
    verifyOptions: JwtVerifyOptions,
  ): Promise<JwtNestedVerified>;

  /** The error class every operation rejects with for a core failure. */
  readonly PolyjoseError: typeof PolyjoseError;
}

// --- records: validated, rebuilt with only known, present members -------------------------
// Each reads the caller's members only from `record`'s own-member copy and returns a `bare`
// (prototype-less) record, so a polluted `Object.prototype` reaches neither (0013 F04).
// A record with byte members takes the call's `copies` list: see `bytes` and `run`.

function signOptions(v: unknown, at: string): BackendJwsSignOptions {
  const o = record(v, at, ["protectedHeader", "protectedB64u", "detached"]);
  const out = bare<BackendJwsSignOptions>({});
  put(out, "protectedHeader", optJson(o["protectedHeader"], `${at}.protectedHeader`));
  put(out, "protectedB64u", optStr(o["protectedB64u"], `${at}.protectedB64u`));
  put(out, "detached", optBool(o["detached"], `${at}.detached`));
  return out;
}

function signer(v: unknown, at: string): BackendJwsSigner {
  const o = record(v, at, ["key", "protectedHeader", "protectedB64u", "unprotectedHeader"]);
  const out = bare<BackendJwsSigner>({ key: json(o["key"], `${at}.key`) });
  put(out, "protectedHeader", optJson(o["protectedHeader"], `${at}.protectedHeader`));
  put(out, "protectedB64u", optStr(o["protectedB64u"], `${at}.protectedB64u`));
  put(out, "unprotectedHeader", optJson(o["unprotectedHeader"], `${at}.unprotectedHeader`));
  return out;
}

function jwsVerifyOptions(v: unknown, at: string, copies: Uint8Array[]): BackendJwsVerifyOptions {
  const o = record(v, at, ["allowedAlgs", "detachedPayload", "maxInputLen", "maxSignatures"]);
  const out = bare<BackendJwsVerifyOptions>({ allowedAlgs: allowList(o["allowedAlgs"], `${at}.allowedAlgs`) });
  put(out, "detachedPayload", optBytes(o["detachedPayload"], `${at}.detachedPayload`, copies));
  put(out, "maxInputLen", optU32(o["maxInputLen"], `${at}.maxInputLen`));
  put(out, "maxSignatures", optU32(o["maxSignatures"], `${at}.maxSignatures`));
  return out;
}

function recipient(v: unknown, at: string, copies: Uint8Array[]): BackendJweRecipient {
  const o = record(v, at, ["alg", "key", "header", "apu", "apv", "p2c", "p2sLen"]);
  const out = bare<BackendJweRecipient>({ alg: str(o["alg"], `${at}.alg`), key: json(o["key"], `${at}.key`) });
  put(out, "header", optJson(o["header"], `${at}.header`));
  put(out, "apu", optBytes(o["apu"], `${at}.apu`, copies));
  put(out, "apv", optBytes(o["apv"], `${at}.apv`, copies));
  put(out, "p2c", optU32(o["p2c"], `${at}.p2c`));
  put(out, "p2sLen", optU32(o["p2sLen"], `${at}.p2sLen`));
  return out;
}

function encryptOptions(v: unknown, at: string, copies: Uint8Array[]): BackendJweEncryptOptions {
  const o = record(v, at, ["enc", "recipients", "protectedHeader", "sharedUnprotectedHeader", "aad", "compress"]);
  const out = bare<BackendJweEncryptOptions>({
    enc: str(o["enc"], `${at}.enc`),
    recipients: list(o["recipients"], `${at}.recipients`, (r, rat) => recipient(r, rat, copies)),
  });
  put(out, "protectedHeader", optJson(o["protectedHeader"], `${at}.protectedHeader`));
  put(out, "sharedUnprotectedHeader", optJson(o["sharedUnprotectedHeader"], `${at}.sharedUnprotectedHeader`));
  put(out, "aad", optBytes(o["aad"], `${at}.aad`, copies));
  put(out, "compress", optBool(o["compress"], `${at}.compress`));
  return out;
}

function decryptOptions(v: unknown, at: string): BackendJweDecryptOptions {
  const o = record(v, at, [
    "allowedAlgs",
    "allowedEnc",
    "maxPbes2Count",
    "maxDecompressedLen",
    "maxInputLen",
    "maxRecipients",
    "understoodCrit",
  ]);
  const out = bare<BackendJweDecryptOptions>({
    allowedAlgs: allowList(o["allowedAlgs"], `${at}.allowedAlgs`),
    allowedEnc: allowList(o["allowedEnc"], `${at}.allowedEnc`),
  });
  put(out, "maxPbes2Count", optU32(o["maxPbes2Count"], `${at}.maxPbes2Count`));
  put(out, "maxDecompressedLen", optU32(o["maxDecompressedLen"], `${at}.maxDecompressedLen`));
  put(out, "maxInputLen", optU32(o["maxInputLen"], `${at}.maxInputLen`));
  put(out, "maxRecipients", optU32(o["maxRecipients"], `${at}.maxRecipients`));
  put(out, "understoodCrit", optStrList(o["understoodCrit"], `${at}.understoodCrit`));
  return out;
}

function jwtSignOptions(v: unknown, at: string): BackendJwtSignOptions {
  const o = record(v, at, ["alg", "typ", "omitTyp", "accessToken", "header"]);
  const out = bare<BackendJwtSignOptions>({ alg: str(o["alg"], `${at}.alg`) });
  put(out, "typ", optStr(o["typ"], `${at}.typ`));
  put(out, "omitTyp", optBool(o["omitTyp"], `${at}.omitTyp`));
  put(out, "accessToken", optBool(o["accessToken"], `${at}.accessToken`));
  put(out, "header", optJson(o["header"], `${at}.header`));
  return out;
}

/** `JwtVerifyOptions` without `now`, plus the caller's `now` if given. */
interface PreparedJwtVerify {
  options: Omit<BackendJwtVerifyOptions, "now">;
  now: number | undefined;
}

function jwtVerifyOptions(v: unknown, at: string): PreparedJwtVerify {
  const o = record(v, at, [
    "allowedAlgs",
    "now",
    "issuers",
    "audiences",
    "subject",
    "leeway",
    "maxAge",
    "requiredClaims",
    "allowMissingExp",
    "ignoreAudience",
    "typ",
    "anyTyp",
    "profile",
    "maxKeyCandidates",
    "maxInputLen",
  ]);
  const options = bare<Omit<BackendJwtVerifyOptions, "now">>({ allowedAlgs: allowList(o["allowedAlgs"], `${at}.allowedAlgs`) });
  put(options, "issuers", optStrList(o["issuers"], `${at}.issuers`));
  put(options, "audiences", optStrList(o["audiences"], `${at}.audiences`));
  put(options, "subject", optStr(o["subject"], `${at}.subject`));
  put(options, "leeway", optU32(o["leeway"], `${at}.leeway`));
  put(options, "maxAge", optU32(o["maxAge"], `${at}.maxAge`));
  put(options, "requiredClaims", optStrList(o["requiredClaims"], `${at}.requiredClaims`));
  put(options, "allowMissingExp", optBool(o["allowMissingExp"], `${at}.allowMissingExp`));
  put(options, "ignoreAudience", optBool(o["ignoreAudience"], `${at}.ignoreAudience`));
  put(options, "typ", optStr(o["typ"], `${at}.typ`));
  put(options, "anyTyp", optBool(o["anyTyp"], `${at}.anyTyp`));
  put(options, "profile", optStr(o["profile"], `${at}.profile`));
  put(options, "maxKeyCandidates", optU32(o["maxKeyCandidates"], `${at}.maxKeyCandidates`));
  put(options, "maxInputLen", optU32(o["maxInputLen"], `${at}.maxInputLen`));
  return { options, now: optSeconds(o["now"], `${at}.now`) };
}

/**
 * The JWT clock (ADR 0028 §4, ADR 0030 §4): the caller's `now` wins; otherwise the JS wall
 * clock, floored to whole seconds, read at the call (in `run`'s synchronous preparation, so a
 * pending `ready()` can't delay the reading). A clock reading, not a policy default:
 * `@polyjose/node` and `@polyjose/wasm` behave identically and no Rust code reads time.
 */
function withNow(prepared: PreparedJwtVerify): BackendJwtVerifyOptions {
  return bare<BackendJwtVerifyOptions>({ ...prepared.options, now: prepared.now ?? Math.floor(Date.now() / 1000) });
}

function selector(v: unknown, at: string): BackendJwkSelector {
  const o = record(v, at, ["kid", "alg", "keyUse"]);
  const out = bare<BackendJwkSelector>({});
  put(out, "kid", optStr(o["kid"], `${at}.kid`));
  put(out, "alg", optStr(o["alg"], `${at}.alg`));
  put(out, "keyUse", optStr(o["keyUse"], `${at}.keyUse`));
  return out;
}

/** A positional `detached` flag: absent is `false`, the ADR 0030 `detached: bool = false`. */
function detachedFlag(v: unknown, at: string): boolean {
  return isAbsent(v) ? false : bool(v, at);
}

// --- results ------------------------------------------------------------------------------

/** An optional JSON-object member of a backend result; absent (`null`/`undefined`) is left out. */
function optObject(v: unknown, name: string, at: string): JsonObject | undefined {
  const raw = member(v, name, at);
  return isAbsent(raw) ? undefined : outObject(raw, `${at}.${name}`);
}

function jwsVerified(v: unknown, at: string): JwsVerified {
  const out: JwsVerified = {
    alg: outStr(member(v, "alg", at), `${at}.alg`),
    payload: outBytes(member(v, "payload", at), `${at}.payload`),
    signatureIndex: outIndex(member(v, "signatureIndex", at), `${at}.signatureIndex`),
  };
  put(out, "protectedHeader", optObject(v, "protectedHeader", at));
  put(out, "unprotectedHeader", optObject(v, "unprotectedHeader", at));
  return out;
}

function jweDecrypted(v: unknown, at: string): JweDecrypted {
  const out: JweDecrypted = {
    plaintext: outBytes(member(v, "plaintext", at), `${at}.plaintext`),
    header: outObject(member(v, "header", at), `${at}.header`),
    recipientIndex: outIndex(member(v, "recipientIndex", at), `${at}.recipientIndex`),
  };
  put(out, "protectedHeader", optObject(v, "protectedHeader", at));
  put(out, "sharedUnprotectedHeader", optObject(v, "sharedUnprotectedHeader", at));
  put(out, "recipientHeader", optObject(v, "recipientHeader", at));
  const aad = member(v, "aad", at);
  put(out, "aad", isAbsent(aad) ? undefined : outBytes(aad, `${at}.aad`));
  return out;
}

function jwtVerified(v: unknown, at: string): JwtVerified {
  const out: JwtVerified = {
    claims: outObject(member(v, "claims", at), `${at}.claims`),
    header: outObject(member(v, "header", at), `${at}.header`),
    alg: outStr(member(v, "alg", at), `${at}.alg`),
  };
  // `keyIndex` 0 is a real index (ADR 0029 §4): only null/undefined mean absent.
  const keyIndex = member(v, "keyIndex", at);
  put(out, "keyIndex", isAbsent(keyIndex) ? undefined : outIndex(keyIndex, `${at}.keyIndex`));
  const kid = member(v, "kid", at);
  put(out, "kid", isAbsent(kid) ? undefined : outStr(kid, `${at}.kid`));
  return out;
}

function jwtNestedVerified(v: unknown, at: string): JwtNestedVerified {
  return {
    inner: jwtVerified(member(v, "inner", at), `${at}.inner`),
    outerHeader: outObject(member(v, "outerHeader", at), `${at}.outerHeader`),
    recipientIndex: outIndex(member(v, "recipientIndex", at), `${at}.recipientIndex`),
  };
}

const jwk = (v: unknown, at: string): JwkObject => outObject(v, at) as JwkObject;

// --- errors -------------------------------------------------------------------------------

/**
 * `e`'s own data member `name`, or `undefined` (0013 F09, F12): never read through a prototype,
 * so a polluted `Object.prototype.code` or `Error.prototype.message` can't stand in for one the
 * backend didn't set, and never through a getter, so reading runs no backend or caller code.
 * napi-rs (`napi_create_error`) and wasm-bindgen (`Reflect::set`) set `code` and `message` as
 * own data properties.
 */
function ownData(e: unknown, name: string): unknown {
  if ((typeof e !== "object" || e === null) && typeof e !== "function") return undefined;
  try {
    const d = Object.getOwnPropertyDescriptor(e, name);
    return d !== undefined && "value" in d ? d.value : undefined;
  } catch {
    return undefined; // a Proxy whose trap throws has no readable member
  }
}

/** `e instanceof C`, false if a hostile `Proxy` or `Symbol.hasInstance` throws. */
function isInstance(e: unknown, C: abstract new (...args: never[]) => unknown): boolean {
  try {
    return e instanceof C;
  } catch {
    return false;
  }
}

/** One of the generated {@link ERROR_CODES}, the core's `Error::CODES` this facade was built from. */
function isErrorCode(code: string): code is ErrorCode {
  return (ERROR_CODES as readonly string[]).includes(code);
}

/**
 * napi-rs's argument-conversion `Status` names: the `code` napi-rs puts on the JS error when a
 * caller's value can't be converted to the Rust parameter type (napi 3.16, `Status` and its
 * `AsRef<str>`; Node-API `napi_status`). Other statuses (`GenericFailure`, `PendingException`,
 * `Cancelled`, ...) don't say the caller misused the API, so they pass through unchanged.
 */
const NAPI_ARGUMENT_STATUSES: ReadonlySet<string> = new Set([
  "InvalidArg",
  "ObjectExpected",
  "StringExpected",
  "NameExpected",
  "FunctionExpected",
  "NumberExpected",
  "BooleanExpected",
  "ArrayExpected",
  "BigintExpected",
  "DateExpected",
  "ArrayBufferExpected",
  "DetachableArraybufferExpected",
]);

/** `e`'s own string `message`, or `fallback`: never a prototype's (0013 F12). */
function ownMessage(e: unknown, fallback: string): string {
  const m = ownData(e, "message");
  return typeof m === "string" ? m : fallback;
}

/**
 * A backend failure as the facade reports it (ADR 0030 §5, ADR 0031 §1, BACKEND.md "Errors";
 * 0013 F04, F12). `code` and `message` are read as own data members only.
 *
 * 1. An own `code` that is in the generated {@link ERROR_CODES} and in the backend's
 *    `errorCodes()` gives a `PolyjoseError` with the backend's own message, so
 *    `PolyjoseError.code` is always an {@link ErrorCode} even if the backend and the facade
 *    versions drift (F04, review N2). `codes` throws if the backend can't list its codes; that
 *    error is reported instead. It is asked only for a code in `ERROR_CODES`, the only codes
 *    that could become a `PolyjoseError`.
 * 2. A host argument error is a `TypeError` with the original message: a `TypeError` (a wasm
 *    reader's), returned as is, or an `Error` whose own `code` is one of
 *    {@link NAPI_ARGUMENT_STATUSES}, re-made as a `TypeError`.
 * 3. Anything else is returned unchanged, the same value: a `WebAssembly.RuntimeError` trap, a
 *    backend's own "unusable, reload it" refusal, another napi status, a code only one side
 *    knows. It isn't the caller's misuse, so it isn't reported as a `TypeError` (F12).
 */
function mapError(e: unknown, codes: () => ReadonlySet<string>): unknown {
  const code = ownData(e, "code");
  if (typeof code === "string" && isErrorCode(code) && codes().has(code)) return new PolyjoseError(code, ownMessage(e, code));
  if (isInstance(e, TypeError)) return e;
  if (typeof code === "string" && NAPI_ARGUMENT_STATUSES.has(code) && isInstance(e, Error)) {
    return new TypeError(ownMessage(e, `polyjose: the backend could not convert an argument (${code})`));
  }
  return e;
}

function describe(e: unknown): string {
  if ((typeof e === "object" && e !== null) || typeof e === "function") return "the backend threw a value with no message";
  try {
    return String(e);
  } catch {
    return "polyjose: the backend failed";
  }
}

/** Binds the facade to one native layer (BACKEND.md). */
export function createApi(backend: Backend): PolyjoseApi {
  let initialised = backend.ready === undefined;
  let pending: Promise<void> | undefined;
  let codeSet: ReadonlySet<string> | undefined;

  /**
   * Awaits `backend.ready()` once, lazily, on first use (ADR 0031 §3: WASM initialises without
   * top-level await). A failure is reported unchanged and the next call tries again.
   */
  function ready(): Promise<void> | undefined {
    if (initialised) return undefined;
    const init = backend.ready;
    if (init === undefined) return undefined;
    pending ??= Promise.resolve()
      .then(() => init.call(backend))
      .then(
        () => {
          initialised = true;
        },
        (e: unknown) => {
          pending = undefined;
          throw e;
        },
      );
    return pending;
  }

  /**
   * The backend's `errorCodes()`, read once, on the first failure to map (0013 F04, review N2).
   * If the backend can't list them (it throws, or returns no array), the facade can't tell a core
   * failure from a host one, so it throws an `Error` naming the cause rather than reporting every
   * core failure as a `TypeError`; nothing is cached, and the next failure asks again.
   */
  const codes = (): ReadonlySet<string> => {
    if (codeSet !== undefined) return codeSet;
    let listed: unknown;
    try {
      listed = backend.errorCodes();
    } catch (e) {
      throw new Error(`polyjose: the backend's errorCodes() failed (${ownMessage(e, describe(e))}), so a backend error can't be mapped`, {
        cause: e,
      });
    }
    if (!Array.isArray(listed)) throw new Error("polyjose: the backend's errorCodes() did not return an array, so a backend error can't be mapped");
    // Own elements only: `filter` would read a hole through a polluted `Array.prototype` and map
    // a code the backend never listed (0013 F09).
    const own = new Set<string>();
    for (let i = 0; i < listed.length; i++) {
      const c: unknown = Object.hasOwn(listed, i) ? listed[i] : undefined;
      if (typeof c === "string") own.add(c);
    }
    codeSet = own;
    return codeSet;
  };

  /** Initialises, calls the backend, and maps its sync throws and rejections. */
  async function invoke<T>(call: () => MaybePromise<T>): Promise<T> {
    const waiting = ready();
    if (waiting !== undefined) await waiting;
    try {
      return await call();
    } catch (e) {
      throw mapError(e, codes);
    }
  }

  /**
   * One operation with arguments (ADR 0030 §2, §7; ADR 0031 §1, §3; 0013 B06).
   *
   * `prepare` runs synchronously, when the operation is called and before anything is awaited:
   * it validates and normalises every argument (a `TypeError` rejects the call before
   * `ready()` or the backend is reached), copies each byte input into a fresh `Uint8Array`
   * recorded in `copies`, serialises JSON objects, reads the JWT clock, and returns the backend
   * call. Only that call waits for `ready()`, so nothing the caller does to its arrays or objects
   * after starting the call changes what is processed. Once the backend call settles, success or
   * failure, the copies are wiped with `fill(0)`; they are never handed back to the caller.
   */
  async function run<T>(prepare: (copies: Uint8Array[]) => () => MaybePromise<unknown>, output: (raw: unknown) => T): Promise<T> {
    const copies: Uint8Array[] = [];
    try {
      const call = prepare(copies);
      return output(await invoke(call));
    } finally {
      wipe(copies);
    }
  }

  const b = backend;
  return {
    version: async () => outStr(await invoke(() => b.version()), "version"),
    // Own elements only (0013 F09): a hole is reported, never read through `Array.prototype`.
    errorCodes: async () => outList(await invoke(() => b.errorCodes()), "errorCodes", outStr),

    base64urlEncode: (input) =>
      run(
        (copies) => {
          const data = bytes(input, "base64urlEncode: bytes", copies);
          return () => b.base64urlEncode(data);
        },
        (r) => outStr(r, "base64urlEncode"),
      ),
    base64urlDecode: (input) =>
      run(
        () => {
          const text = str(input, "base64urlDecode: text");
          return () => b.base64urlDecode(text);
        },
        (r) => outBytes(r, "base64urlDecode"),
      ),

    jwkParse: (key) =>
      run(
        () => {
          const k = json(key, "jwkParse: jwk");
          return () => b.jwkParse(k);
        },
        (r) => jwk(r, "jwkParse"),
      ),
    jwkToPublic: (key) =>
      run(
        () => {
          const k = json(key, "jwkToPublic: jwk");
          return () => b.jwkToPublic(k);
        },
        (r) => jwk(r, "jwkToPublic"),
      ),
    // `hash` is optional (ADR 0054 §9): null and undefined reach the backend as undefined, so
    // the core's default applies; a name is passed as given, for the core to parse (§8.2).
    jwkThumbprint: (key, hash) =>
      run(
        () => {
          const k = json(key, "jwkThumbprint: jwk");
          const h = optStr(hash, "jwkThumbprint: hash");
          return () => b.jwkThumbprint(k, h);
        },
        (r) => outStr(r, "jwkThumbprint"),
      ),
    jwkThumbprintUri: (key, hash) =>
      run(
        () => {
          const k = json(key, "jwkThumbprintUri: jwk");
          const h = optStr(hash, "jwkThumbprintUri: hash");
          return () => b.jwkThumbprintUri(k, h);
        },
        (r) => outStr(r, "jwkThumbprintUri"),
      ),
    jwksSelect: (jwks, criteria) =>
      run(
        () => {
          const set = json(jwks, "jwksSelect: jwks");
          const sel = selector(criteria, "jwksSelect: selector");
          return () => b.jwksSelect(set, sel);
        },
        (r) => jwk(r, "jwksSelect"),
      ),
    jwkGenerateOct: (lenBytes) =>
      run(
        () => {
          const n = u32(lenBytes, "jwkGenerateOct: lenBytes");
          return () => b.jwkGenerateOct(n);
        },
        (r) => jwk(r, "jwkGenerateOct"),
      ),
    jwkGenerateEc: (crv) =>
      run(
        () => {
          const c = str(crv, "jwkGenerateEc: crv");
          return () => b.jwkGenerateEc(c);
        },
        (r) => jwk(r, "jwkGenerateEc"),
      ),
    jwkGenerateOkp: (crv) =>
      run(
        () => {
          const c = str(crv, "jwkGenerateOkp: crv");
          return () => b.jwkGenerateOkp(c);
        },
        (r) => jwk(r, "jwkGenerateOkp"),
      ),
    jwkGenerateForAlg: (alg) =>
      run(
        () => {
          const a = str(alg, "jwkGenerateForAlg: alg");
          return () => b.jwkGenerateForAlg(a);
        },
        (r) => jwk(r, "jwkGenerateForAlg"),
      ),
    jwkFromPem: (pem) =>
      run(
        () => {
          const p = str(pem, "jwkFromPem: pem");
          return () => b.jwkFromPem(p);
        },
        (r) => jwk(r, "jwkFromPem"),
      ),
    jwkFromDer: (der, format) =>
      run(
        (copies) => {
          const d = bytes(der, "jwkFromDer: der", copies);
          const f = str(format, "jwkFromDer: format");
          return () => b.jwkFromDer(d, f);
        },
        (r) => jwk(r, "jwkFromDer"),
      ),
    jwkToPem: (key, format) =>
      run(
        () => {
          const k = json(key, "jwkToPem: jwk");
          const f = str(format, "jwkToPem: format");
          return () => b.jwkToPem(k, f);
        },
        (r) => outStr(r, "jwkToPem"),
      ),
    jwkToDer: (key, format) =>
      run(
        () => {
          const k = json(key, "jwkToDer: jwk");
          const f = str(format, "jwkToDer: format");
          return () => b.jwkToDer(k, f);
        },
        (r) => outBytes(r, "jwkToDer"),
      ),

    jwsSignCompact: (payload, key, options) =>
      run(
        (copies) => {
          const p = bytes(payload, "jwsSignCompact: payload", copies);
          const k = json(key, "jwsSignCompact: key");
          const o = signOptions(options, "jwsSignCompact: options");
          return () => b.jwsSignCompact(p, k, o);
        },
        (r) => outStr(r, "jwsSignCompact"),
      ),
    jwsSignFlattened: (payload, one, detached) =>
      run(
        (copies) => {
          const p = bytes(payload, "jwsSignFlattened: payload", copies);
          const s = signer(one, "jwsSignFlattened: signer");
          const d = detachedFlag(detached, "jwsSignFlattened: detached");
          return () => b.jwsSignFlattened(p, s, d);
        },
        (r) => outStr(r, "jwsSignFlattened"),
      ),
    jwsSignGeneral: (payload, signers, detached) =>
      run(
        (copies) => {
          const p = bytes(payload, "jwsSignGeneral: payload", copies);
          const s = list(signers, "jwsSignGeneral: signers", signer);
          const d = detachedFlag(detached, "jwsSignGeneral: detached");
          return () => b.jwsSignGeneral(p, s, d);
        },
        (r) => outStr(r, "jwsSignGeneral"),
      ),
    jwsVerifyCompact: (token, key, options) =>
      run(
        (copies) => {
          const t = str(token, "jwsVerifyCompact: token");
          const k = json(key, "jwsVerifyCompact: key");
          const o = jwsVerifyOptions(options, "jwsVerifyCompact: options", copies);
          return () => b.jwsVerifyCompact(t, k, o);
        },
        (r) => jwsVerified(r, "jwsVerifyCompact"),
      ),
    jwsVerifyJson: (jws, key, options) =>
      run(
        (copies) => {
          const t = json(jws, "jwsVerifyJson: jws");
          const k = json(key, "jwsVerifyJson: key");
          const o = jwsVerifyOptions(options, "jwsVerifyJson: options", copies);
          return () => b.jwsVerifyJson(t, k, o);
        },
        (r) => jwsVerified(r, "jwsVerifyJson"),
      ),

    jweEncryptCompact: (plaintext, options) =>
      run(
        (copies) => {
          const p = bytes(plaintext, "jweEncryptCompact: plaintext", copies);
          const o = encryptOptions(options, "jweEncryptCompact: options", copies);
          return () => b.jweEncryptCompact(p, o);
        },
        (r) => outStr(r, "jweEncryptCompact"),
      ),
    jweEncryptJson: (plaintext, options, form) =>
      run(
        (copies) => {
          const p = bytes(plaintext, "jweEncryptJson: plaintext", copies);
          const o = encryptOptions(options, "jweEncryptJson: options", copies);
          const f = str(form, "jweEncryptJson: form");
          return () => b.jweEncryptJson(p, o, f);
        },
        (r) => outStr(r, "jweEncryptJson"),
      ),
    jweDecryptCompact: (token, key, options) =>
      run(
        () => {
          const t = str(token, "jweDecryptCompact: token");
          const k = json(key, "jweDecryptCompact: key");
          const o = decryptOptions(options, "jweDecryptCompact: options");
          return () => b.jweDecryptCompact(t, k, o);
        },
        (r) => jweDecrypted(r, "jweDecryptCompact"),
      ),
    jweDecryptJson: (jwe, key, options) =>
      run(
        () => {
          const t = json(jwe, "jweDecryptJson: jwe");
          const k = json(key, "jweDecryptJson: key");
          const o = decryptOptions(options, "jweDecryptJson: options");
          return () => b.jweDecryptJson(t, k, o);
        },
        (r) => jweDecrypted(r, "jweDecryptJson"),
      ),

    jwtSign: (claims, key, options) =>
      run(
        () => {
          const c = json(claims, "jwtSign: claims");
          const k = json(key, "jwtSign: key");
          const o = jwtSignOptions(options, "jwtSign: options");
          return () => b.jwtSign(c, k, o);
        },
        (r) => outStr(r, "jwtSign"),
      ),
    jwtVerify: (token, key, options) =>
      run(
        () => {
          const t = str(token, "jwtVerify: token");
          const k = json(key, "jwtVerify: key");
          const o = withNow(jwtVerifyOptions(options, "jwtVerify: options"));
          return () => b.jwtVerify(t, k, o);
        },
        (r) => jwtVerified(r, "jwtVerify"),
      ),
    jwtVerifyWithJwks: (token, jwks, options) =>
      run(
        () => {
          const t = str(token, "jwtVerifyWithJwks: token");
          const s = json(jwks, "jwtVerifyWithJwks: jwks");
          const o = withNow(jwtVerifyOptions(options, "jwtVerifyWithJwks: options"));
          return () => b.jwtVerifyWithJwks(t, s, o);
        },
        (r) => jwtVerified(r, "jwtVerifyWithJwks"),
      ),
    jwtEncryptNested: (signedJwt, options) =>
      run(
        (copies) => {
          const t = str(signedJwt, "jwtEncryptNested: signedJwt");
          const o = encryptOptions(options, "jwtEncryptNested: options", copies);
          return () => b.jwtEncryptNested(t, o);
        },
        (r) => outStr(r, "jwtEncryptNested"),
      ),
    jwtDecryptNested: (token, decryptKey, decrypt, key, verify) =>
      run(
        () => {
          const t = str(token, "jwtDecryptNested: token");
          const dk = json(decryptKey, "jwtDecryptNested: decryptKey");
          const d = decryptOptions(decrypt, "jwtDecryptNested: decryptOptions");
          const k = json(key, "jwtDecryptNested: key");
          const v = withNow(jwtVerifyOptions(verify, "jwtDecryptNested: verifyOptions"));
          return () => b.jwtDecryptNested(t, dk, d, k, v);
        },
        (r) => jwtNestedVerified(r, "jwtDecryptNested"),
      ),
    jwtDecryptNestedWithJwks: (token, decryptKey, decrypt, jwks, verify) =>
      run(
        () => {
          const t = str(token, "jwtDecryptNestedWithJwks: token");
          const dk = json(decryptKey, "jwtDecryptNestedWithJwks: decryptKey");
          const d = decryptOptions(decrypt, "jwtDecryptNestedWithJwks: decryptOptions");
          const s = json(jwks, "jwtDecryptNestedWithJwks: jwks");
          const v = withNow(jwtVerifyOptions(verify, "jwtDecryptNestedWithJwks: verifyOptions"));
          return () => b.jwtDecryptNestedWithJwks(t, dk, d, s, v);
        },
        (r) => jwtNestedVerified(r, "jwtDecryptNestedWithJwks"),
      ),

    PolyjoseError,
  };
}

