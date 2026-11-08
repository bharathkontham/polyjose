/**
 * The public records of the JS facade: ADR 0030 §3–§4 with camelCase fields (§2).
 *
 * - Allow-lists (`allowedAlgs`, `allowedEnc`) are required, with no default (ADR 0007,
 *   RFC 8725 §3.1); omitting one does not type-check. Plain JS callers that omit one get
 *   `AlgorithmNotAllowed` from the core, never a default list.
 * - Every tunable is optional, and absent means the core default (ADR 0030 §3). The facade
 *   writes no default of its own.
 * - Algorithm names are the IANA JOSE registry strings, passed as given (ADR 0030 D1).
 * - JSON values (JWKs, JWK Sets, headers, claims, JWS/JWE JSON serializations) are accepted
 *   as JSON text or as a plain object (ADR 0030 §2); results come back as parsed objects
 *   (JWKs, headers, claims) or strings (tokens and JSON serializations).
 */

/** A JSON value as `JSON.parse` returns it. */
export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;

/** A JSON object as `JSON.parse` returns it. */
export interface JsonObject {
  [member: string]: JsonValue;
}

/** A JWK (RFC 7517 §4) as an object. */
export interface JwkObject {
  kty: string;
  [member: string]: JsonValue;
}

/** A JWK Set (RFC 7517 §5) as an object. */
export interface JwkSetObject {
  keys: JsonValue[];
  [member: string]: JsonValue;
}

/** A JWK: its JSON text or a plain object (ADR 0030 §2, C1). */
export type Jwk = string | JwkObject;

/** A JWK Set: its JSON text or a plain object. */
export type JwkSet = string | JwkSetObject;

/** A JSON object argument (a header, a Claims Set, a JWS/JWE JSON serialization): text or a plain object. */
export type JsonInput = string | JsonObject;

/**
 * JWK Thumbprint hash names (RFC 7638 §3.4, RFC 9278 §4): the nine names the core accepts,
 * matched exactly (ADR 0054 §8.2). Each hash has its IANA Named Information name (`sha-256`,
 * canonical, the one the URI carries), the ADR 0030 §4 form (`SHA-256`) and the panva/jose form
 * (`sha256`). SHA-1 is not offered (ADR 0022). The core parses the name; the facade passes it
 * as given.
 */
export type ThumbprintHash =
  | "sha-256"
  | "SHA-256"
  | "sha256"
  | "sha-384"
  | "SHA-384"
  | "sha384"
  | "sha-512"
  | "SHA-512"
  | "sha512";

/** EC curves `jwkGenerateEc` takes (RFC 7518 §6.2.1.1, RFC 8812 §3.1). */
export type EcCurve = "P-256" | "P-384" | "P-521" | "secp256k1";

/** OKP curves `jwkGenerateOkp` takes (RFC 8037 §2). */
export type OkpCurve = "Ed25519" | "X25519";

/** Key encodings (ADR 0018 §3): PKCS#8 (RFC 5958), SEC1 (RFC 5915), SPKI (RFC 5280), PKCS#1 (RFC 8017). */
export type KeyFormat = "pkcs8" | "sec1" | "spki" | "pkcs1";

/** The JWE JSON serializations (RFC 7516 §7.2.1 general, §7.2.2 flattened). */
export type JweJsonForm = "general" | "flattened";

/**
 * `jwksSelect` criteria (RFC 7517 §4.2, §4.4, §4.5; ADR 0054 §1). Each is optional and passed
 * to the core as given: `alg` a JWS or JWE key management algorithm, `keyUse` `sig` or `enc`.
 */
export interface JwkSelector {
  kid?: string | undefined;
  alg?: string | undefined;
  keyUse?: string | undefined;
}

/**
 * `jwsSignCompact` options (RFC 7515 §7.1). Exactly one of `protectedHeader` and
 * `protectedB64u`; both or neither fail with `InvalidHeader` in the core. `protectedB64u`
 * signs over the caller's exact octets (RFC 7515 §5.1 step 3).
 */
export interface JwsSignOptions {
  protectedHeader?: JsonInput | undefined;
  protectedB64u?: string | undefined;
  /** Leave the payload out of the output (RFC 7515 Appendix F). */
  detached?: boolean | undefined;
}

/**
 * One signer of a JWS JSON serialization (RFC 7515 §7.2). A signer may carry only an
 * unprotected header (RFC 7515 §7.2.1, ADR 0045 §1). This record holds a key: don't log it.
 */
export interface JwsSigner {
  key: Jwk;
  protectedHeader?: JsonInput | undefined;
  protectedB64u?: string | undefined;
  unprotectedHeader?: JsonInput | undefined;
}

/** JWS verification options (RFC 7515 §5.2, RFC 8725 §3.1; ADR 0026 §7 limits). */
export interface JwsVerifyOptions {
  /** The accepted `alg` names. Required; `none` is never accepted (ADR 0007). */
  allowedAlgs: readonly string[];
  /** The detached payload (RFC 7515 Appendix F). */
  detachedPayload?: Uint8Array | undefined;
  maxInputLen?: number | undefined;
  maxSignatures?: number | undefined;
}

/** A verified JWS. `unprotectedHeader` is not integrity-protected (ADR 0049 §2). */
export interface JwsVerified {
  alg: string;
  payload: Uint8Array;
  protectedHeader?: JsonObject;
  unprotectedHeader?: JsonObject;
  /** The index of the signature that verified (0 for compact and flattened; ADR 0026 §3). */
  signatureIndex: number;
}

/** One JWE recipient (RFC 7516 §5.1, RFC 7518 §4). This record holds a key: don't log it. */
export interface JweRecipient {
  alg: string;
  key: Jwk;
  header?: JsonInput | undefined;
  apu?: Uint8Array | undefined;
  apv?: Uint8Array | undefined;
  p2c?: number | undefined;
  p2sLen?: number | undefined;
}

/** JWE encryption options (RFC 7516 §5.1). */
export interface JweEncryptOptions {
  enc: string;
  recipients: readonly JweRecipient[];
  protectedHeader?: JsonInput | undefined;
  sharedUnprotectedHeader?: JsonInput | undefined;
  aad?: Uint8Array | undefined;
  /** `zip: "DEF"` (RFC 7516 §4.1.3); `UnsupportedAlgorithm` while bindings build without `deflate`. */
  compress?: boolean | undefined;
}

/** JWE decryption options (RFC 7516 §5.2, RFC 8725 §3.1; ADR 0023, 0017 bounds). */
export interface JweDecryptOptions {
  /** The accepted key management `alg` names. Required (ADR 0007). */
  allowedAlgs: readonly string[];
  /** The accepted content encryption `enc` names. Required (ADR 0007). */
  allowedEnc: readonly string[];
  maxPbes2Count?: number | undefined;
  maxDecompressedLen?: number | undefined;
  maxInputLen?: number | undefined;
  maxRecipients?: number | undefined;
  /** The `crit` extensions the caller understands (RFC 7516 §4.1.13). */
  understoodCrit?: readonly string[] | undefined;
}

/**
 * A decrypted JWE. Only `protectedHeader` is integrity-protected; `header`,
 * `sharedUnprotectedHeader` and `recipientHeader` may hold unprotected members (ADR 0050 §3).
 */
export interface JweDecrypted {
  plaintext: Uint8Array;
  /** The union of the headers used (RFC 7516 §5.2 step 5). */
  header: JsonObject;
  protectedHeader?: JsonObject;
  sharedUnprotectedHeader?: JsonObject;
  recipientHeader?: JsonObject;
  aad?: Uint8Array;
  recipientIndex: number;
}

/** JWT signing options (RFC 7519 §7.1; ADR 0027 §8). */
export interface JwtSignOptions {
  alg: string;
  /** The `typ` header; absent gives the core default `JWT`. */
  typ?: string | undefined;
  /** Omit `typ` (RFC 7519 §5.1). */
  omitTyp?: boolean | undefined;
  /** An RFC 9068 access token (`typ: at+jwt`). */
  accessToken?: boolean | undefined;
  /** Extra protected header parameters. */
  header?: JsonInput | undefined;
}

/**
 * JWT validation options (RFC 7519 §7.2, RFC 8725 §3; ADR 0027 policy, ADR 0029 key sets).
 * Each field maps to one core `Policy` method; absent or `false` keeps the core default.
 */
export interface JwtVerifyOptions {
  /** The accepted JWS `alg` names. Required (ADR 0007). */
  allowedAlgs: readonly string[];
  /**
   * The current time in whole seconds since the epoch (RFC 7519 §2). When absent the facade
   * passes `Math.floor(Date.now() / 1000)` (ADR 0028 §4, ADR 0030 §4).
   */
  now?: number | undefined;
  issuers?: readonly string[] | undefined;
  audiences?: readonly string[] | undefined;
  subject?: string | undefined;
  /** Clock skew in seconds (core default 60, at most 600). */
  leeway?: number | undefined;
  maxAge?: number | undefined;
  requiredClaims?: readonly string[] | undefined;
  allowMissingExp?: boolean | undefined;
  ignoreAudience?: boolean | undefined;
  typ?: string | undefined;
  anyTyp?: boolean | undefined;
  /**
   * `"access_token"`: the RFC 9068 §4 JWT access-token profile (`Policy::access_token`), the only
   * profile, so a typo fails to compile (0013 F04, review N5). The type is the only check: an
   * untyped caller's other string still reaches the core, which refuses it with
   * `UnsupportedAlgorithm` (ADR 0030 §4).
   */
  profile?: "access_token" | undefined;
  maxKeyCandidates?: number | undefined;
  maxInputLen?: number | undefined;
}

/** A validated JWT. */
export interface JwtVerified {
  claims: JsonObject;
  header: JsonObject;
  alg: string;
  /** The JWK Set position of the key that verified; present only for a key set (ADR 0029 §4). */
  keyIndex?: number;
  kid?: string;
}

/** A validated nested JWT (ADR 0027 §7). */
export interface JwtNestedVerified {
  inner: JwtVerified;
  outerHeader: JsonObject;
  recipientIndex: number;
}
