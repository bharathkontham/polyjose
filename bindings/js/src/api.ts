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
  outObject,
  outStr,
  put,
  record,
  str,
  u32,
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
  /** The JWK Thumbprint (RFC 7638 §3), base64url. */
  jwkThumbprint(jwk: Jwk, hash: ThumbprintHash): Promise<string>;
  /** The JWK Thumbprint URI (RFC 9278 §3). */
  jwkThumbprintUri(jwk: Jwk, hash: ThumbprintHash): Promise<string>;
  /** Selects one key of a JWK Set (RFC 7517 §5) by `kid`, `alg` and `use`. */
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

function signOptions(v: unknown, at: string): BackendJwsSignOptions {
  const o = record(v, at, ["protectedHeader", "protectedB64u", "detached"]);
  const out: BackendJwsSignOptions = {};
  put(out, "protectedHeader", optJson(o["protectedHeader"], `${at}.protectedHeader`));
  put(out, "protectedB64u", optStr(o["protectedB64u"], `${at}.protectedB64u`));
  put(out, "detached", optBool(o["detached"], `${at}.detached`));
  return out;
}

function signer(v: unknown, at: string): BackendJwsSigner {
  const o = record(v, at, ["key", "protectedHeader", "protectedB64u", "unprotectedHeader"]);
  const out: BackendJwsSigner = { key: json(o["key"], `${at}.key`) };
  put(out, "protectedHeader", optJson(o["protectedHeader"], `${at}.protectedHeader`));
  put(out, "protectedB64u", optStr(o["protectedB64u"], `${at}.protectedB64u`));
  put(out, "unprotectedHeader", optJson(o["unprotectedHeader"], `${at}.unprotectedHeader`));
  return out;
}

function jwsVerifyOptions(v: unknown, at: string): BackendJwsVerifyOptions {
  const o = record(v, at, ["allowedAlgs", "detachedPayload", "maxInputLen", "maxSignatures"]);
  const out: BackendJwsVerifyOptions = { allowedAlgs: allowList(o["allowedAlgs"], `${at}.allowedAlgs`) };
  put(out, "detachedPayload", optBytes(o["detachedPayload"], `${at}.detachedPayload`));
  put(out, "maxInputLen", optU32(o["maxInputLen"], `${at}.maxInputLen`));
  put(out, "maxSignatures", optU32(o["maxSignatures"], `${at}.maxSignatures`));
  return out;
}

function recipient(v: unknown, at: string): BackendJweRecipient {
  const o = record(v, at, ["alg", "key", "header", "apu", "apv", "p2c", "p2sLen"]);
  const out: BackendJweRecipient = { alg: str(o["alg"], `${at}.alg`), key: json(o["key"], `${at}.key`) };
  put(out, "header", optJson(o["header"], `${at}.header`));
  put(out, "apu", optBytes(o["apu"], `${at}.apu`));
  put(out, "apv", optBytes(o["apv"], `${at}.apv`));
  put(out, "p2c", optU32(o["p2c"], `${at}.p2c`));
  put(out, "p2sLen", optU32(o["p2sLen"], `${at}.p2sLen`));
  return out;
}

function encryptOptions(v: unknown, at: string): BackendJweEncryptOptions {
  const o = record(v, at, ["enc", "recipients", "protectedHeader", "sharedUnprotectedHeader", "aad", "compress"]);
  const out: BackendJweEncryptOptions = {
    enc: str(o["enc"], `${at}.enc`),
    recipients: list(o["recipients"], `${at}.recipients`, recipient),
  };
  put(out, "protectedHeader", optJson(o["protectedHeader"], `${at}.protectedHeader`));
  put(out, "sharedUnprotectedHeader", optJson(o["sharedUnprotectedHeader"], `${at}.sharedUnprotectedHeader`));
  put(out, "aad", optBytes(o["aad"], `${at}.aad`));
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
  const out: BackendJweDecryptOptions = {
    allowedAlgs: allowList(o["allowedAlgs"], `${at}.allowedAlgs`),
    allowedEnc: allowList(o["allowedEnc"], `${at}.allowedEnc`),
  };
  put(out, "maxPbes2Count", optU32(o["maxPbes2Count"], `${at}.maxPbes2Count`));
  put(out, "maxDecompressedLen", optU32(o["maxDecompressedLen"], `${at}.maxDecompressedLen`));
  put(out, "maxInputLen", optU32(o["maxInputLen"], `${at}.maxInputLen`));
  put(out, "maxRecipients", optU32(o["maxRecipients"], `${at}.maxRecipients`));
  put(out, "understoodCrit", optStrList(o["understoodCrit"], `${at}.understoodCrit`));
  return out;
}

function jwtSignOptions(v: unknown, at: string): BackendJwtSignOptions {
  const o = record(v, at, ["alg", "typ", "omitTyp", "accessToken", "header"]);
  const out: BackendJwtSignOptions = { alg: str(o["alg"], `${at}.alg`) };
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
  const options: Omit<BackendJwtVerifyOptions, "now"> = { allowedAlgs: allowList(o["allowedAlgs"], `${at}.allowedAlgs`) };
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
 * clock, floored to whole seconds, read at the call. A clock reading, not a policy default:
 * `@polyjose/node` and `@polyjose/wasm` behave identically and no Rust code reads time.
 */
function withNow(prepared: PreparedJwtVerify): BackendJwtVerifyOptions {
  return { ...prepared.options, now: prepared.now ?? Math.floor(Date.now() / 1000) };
}

function selector(v: unknown, at: string): BackendJwkSelector {
  const o = record(v, at, ["kid", "alg", "keyUse"]);
  const out: BackendJwkSelector = {};
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

function field(e: unknown, name: string): unknown {
  return (typeof e === "object" && e !== null) || typeof e === "function" ? (e as Record<string, unknown>)[name] : undefined;
}

/**
 * A backend failure as the facade reports it (ADR 0030 §5, ADR 0031 §1): a `code` the backend's
 * `errorCodes()` lists gives a `PolyjoseError` with the backend's message; anything else (napi's
 * own `InvalidArg`/`StringExpected`, a `TypeError` of the wasm reader) is a host `TypeError`
 * with the original message.
 */
function mapError(e: unknown, codes: () => ReadonlySet<string>): Error {
  const code = field(e, "code");
  const message = field(e, "message");
  const text = typeof message === "string" ? message : describe(e);
  if (typeof code === "string" && codes().has(code)) return new PolyjoseError(code as ErrorCode, text);
  return new TypeError(text);
}

function describe(e: unknown): string {
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

  const codes = (): ReadonlySet<string> => {
    if (codeSet === undefined) {
      try {
        codeSet = new Set(backend.errorCodes());
      } catch {
        return new Set();
      }
    }
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

  const b = backend;
  return {
    version: async () => outStr(await invoke(() => b.version()), "version"),
    errorCodes: async () => {
      const raw: unknown = await invoke(() => b.errorCodes());
      if (!Array.isArray(raw)) throw new TypeError("polyjose: the backend returned errorCodes that is not an array");
      return raw.map((c: unknown, i) => outStr(c, `errorCodes[${i}]`));
    },

    base64urlEncode: async (input) => {
      const data = bytes(input, "base64urlEncode: bytes");
      return outStr(await invoke(() => b.base64urlEncode(data)), "base64urlEncode");
    },
    base64urlDecode: async (input) => {
      const text = str(input, "base64urlDecode: text");
      return outBytes(await invoke(() => b.base64urlDecode(text)), "base64urlDecode");
    },

    jwkParse: async (key) => {
      const k = json(key, "jwkParse: jwk");
      return jwk(await invoke(() => b.jwkParse(k)), "jwkParse");
    },
    jwkToPublic: async (key) => {
      const k = json(key, "jwkToPublic: jwk");
      return jwk(await invoke(() => b.jwkToPublic(k)), "jwkToPublic");
    },
    jwkThumbprint: async (key, hash) => {
      const k = json(key, "jwkThumbprint: jwk");
      const h = str(hash, "jwkThumbprint: hash");
      return outStr(await invoke(() => b.jwkThumbprint(k, h)), "jwkThumbprint");
    },
    jwkThumbprintUri: async (key, hash) => {
      const k = json(key, "jwkThumbprintUri: jwk");
      const h = str(hash, "jwkThumbprintUri: hash");
      return outStr(await invoke(() => b.jwkThumbprintUri(k, h)), "jwkThumbprintUri");
    },
    jwksSelect: async (jwks, criteria) => {
      const set = json(jwks, "jwksSelect: jwks");
      const sel = selector(criteria, "jwksSelect: selector");
      return jwk(await invoke(() => b.jwksSelect(set, sel)), "jwksSelect");
    },
    jwkGenerateOct: async (lenBytes) => {
      const n = u32(lenBytes, "jwkGenerateOct: lenBytes");
      return jwk(await invoke(() => b.jwkGenerateOct(n)), "jwkGenerateOct");
    },
    jwkGenerateEc: async (crv) => {
      const c = str(crv, "jwkGenerateEc: crv");
      return jwk(await invoke(() => b.jwkGenerateEc(c)), "jwkGenerateEc");
    },
    jwkGenerateOkp: async (crv) => {
      const c = str(crv, "jwkGenerateOkp: crv");
      return jwk(await invoke(() => b.jwkGenerateOkp(c)), "jwkGenerateOkp");
    },
    jwkGenerateForAlg: async (alg) => {
      const a = str(alg, "jwkGenerateForAlg: alg");
      return jwk(await invoke(() => b.jwkGenerateForAlg(a)), "jwkGenerateForAlg");
    },
    jwkFromPem: async (pem) => {
      const p = str(pem, "jwkFromPem: pem");
      return jwk(await invoke(() => b.jwkFromPem(p)), "jwkFromPem");
    },
    jwkFromDer: async (der, format) => {
      const d = bytes(der, "jwkFromDer: der");
      const f = str(format, "jwkFromDer: format");
      return jwk(await invoke(() => b.jwkFromDer(d, f)), "jwkFromDer");
    },
    jwkToPem: async (key, format) => {
      const k = json(key, "jwkToPem: jwk");
      const f = str(format, "jwkToPem: format");
      return outStr(await invoke(() => b.jwkToPem(k, f)), "jwkToPem");
    },
    jwkToDer: async (key, format) => {
      const k = json(key, "jwkToDer: jwk");
      const f = str(format, "jwkToDer: format");
      return outBytes(await invoke(() => b.jwkToDer(k, f)), "jwkToDer");
    },

    jwsSignCompact: async (payload, key, options) => {
      const p = bytes(payload, "jwsSignCompact: payload");
      const k = json(key, "jwsSignCompact: key");
      const o = signOptions(options, "jwsSignCompact: options");
      return outStr(await invoke(() => b.jwsSignCompact(p, k, o)), "jwsSignCompact");
    },
    jwsSignFlattened: async (payload, one, detached) => {
      const p = bytes(payload, "jwsSignFlattened: payload");
      const s = signer(one, "jwsSignFlattened: signer");
      const d = detachedFlag(detached, "jwsSignFlattened: detached");
      return outStr(await invoke(() => b.jwsSignFlattened(p, s, d)), "jwsSignFlattened");
    },
    jwsSignGeneral: async (payload, signers, detached) => {
      const p = bytes(payload, "jwsSignGeneral: payload");
      const s = list(signers, "jwsSignGeneral: signers", signer);
      const d = detachedFlag(detached, "jwsSignGeneral: detached");
      return outStr(await invoke(() => b.jwsSignGeneral(p, s, d)), "jwsSignGeneral");
    },
    jwsVerifyCompact: async (token, key, options) => {
      const t = str(token, "jwsVerifyCompact: token");
      const k = json(key, "jwsVerifyCompact: key");
      const o = jwsVerifyOptions(options, "jwsVerifyCompact: options");
      return jwsVerified(await invoke(() => b.jwsVerifyCompact(t, k, o)), "jwsVerifyCompact");
    },
    jwsVerifyJson: async (jws, key, options) => {
      const t = json(jws, "jwsVerifyJson: jws");
      const k = json(key, "jwsVerifyJson: key");
      const o = jwsVerifyOptions(options, "jwsVerifyJson: options");
      return jwsVerified(await invoke(() => b.jwsVerifyJson(t, k, o)), "jwsVerifyJson");
    },

    jweEncryptCompact: async (plaintext, options) => {
      const p = bytes(plaintext, "jweEncryptCompact: plaintext");
      const o = encryptOptions(options, "jweEncryptCompact: options");
      return outStr(await invoke(() => b.jweEncryptCompact(p, o)), "jweEncryptCompact");
    },
    jweEncryptJson: async (plaintext, options, form) => {
      const p = bytes(plaintext, "jweEncryptJson: plaintext");
      const o = encryptOptions(options, "jweEncryptJson: options");
      const f = str(form, "jweEncryptJson: form");
      return outStr(await invoke(() => b.jweEncryptJson(p, o, f)), "jweEncryptJson");
    },
    jweDecryptCompact: async (token, key, options) => {
      const t = str(token, "jweDecryptCompact: token");
      const k = json(key, "jweDecryptCompact: key");
      const o = decryptOptions(options, "jweDecryptCompact: options");
      return jweDecrypted(await invoke(() => b.jweDecryptCompact(t, k, o)), "jweDecryptCompact");
    },
    jweDecryptJson: async (jwe, key, options) => {
      const t = json(jwe, "jweDecryptJson: jwe");
      const k = json(key, "jweDecryptJson: key");
      const o = decryptOptions(options, "jweDecryptJson: options");
      return jweDecrypted(await invoke(() => b.jweDecryptJson(t, k, o)), "jweDecryptJson");
    },

    jwtSign: async (claims, key, options) => {
      const c = json(claims, "jwtSign: claims");
      const k = json(key, "jwtSign: key");
      const o = jwtSignOptions(options, "jwtSign: options");
      return outStr(await invoke(() => b.jwtSign(c, k, o)), "jwtSign");
    },
    jwtVerify: async (token, key, options) => {
      const t = str(token, "jwtVerify: token");
      const k = json(key, "jwtVerify: key");
      const o = jwtVerifyOptions(options, "jwtVerify: options");
      return jwtVerified(await invoke(() => b.jwtVerify(t, k, withNow(o))), "jwtVerify");
    },
    jwtVerifyWithJwks: async (token, jwks, options) => {
      const t = str(token, "jwtVerifyWithJwks: token");
      const s = json(jwks, "jwtVerifyWithJwks: jwks");
      const o = jwtVerifyOptions(options, "jwtVerifyWithJwks: options");
      return jwtVerified(await invoke(() => b.jwtVerifyWithJwks(t, s, withNow(o))), "jwtVerifyWithJwks");
    },
    jwtEncryptNested: async (signedJwt, options) => {
      const t = str(signedJwt, "jwtEncryptNested: signedJwt");
      const o = encryptOptions(options, "jwtEncryptNested: options");
      return outStr(await invoke(() => b.jwtEncryptNested(t, o)), "jwtEncryptNested");
    },
    jwtDecryptNested: async (token, decryptKey, decrypt, key, verify) => {
      const t = str(token, "jwtDecryptNested: token");
      const dk = json(decryptKey, "jwtDecryptNested: decryptKey");
      const d = decryptOptions(decrypt, "jwtDecryptNested: decryptOptions");
      const k = json(key, "jwtDecryptNested: key");
      const v = jwtVerifyOptions(verify, "jwtDecryptNested: verifyOptions");
      return jwtNestedVerified(await invoke(() => b.jwtDecryptNested(t, dk, d, k, withNow(v))), "jwtDecryptNested");
    },
    jwtDecryptNestedWithJwks: async (token, decryptKey, decrypt, jwks, verify) => {
      const t = str(token, "jwtDecryptNestedWithJwks: token");
      const dk = json(decryptKey, "jwtDecryptNestedWithJwks: decryptKey");
      const d = decryptOptions(decrypt, "jwtDecryptNestedWithJwks: decryptOptions");
      const s = json(jwks, "jwtDecryptNestedWithJwks: jwks");
      const v = jwtVerifyOptions(verify, "jwtDecryptNestedWithJwks: verifyOptions");
      return jwtNestedVerified(
        await invoke(() => b.jwtDecryptNestedWithJwks(t, dk, d, s, withNow(v))),
        "jwtDecryptNestedWithJwks",
      );
    },

    PolyjoseError,
  };
}

