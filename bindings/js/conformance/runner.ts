/**
 * The JS conformance runner shared by `@polyjose/node` and `@polyjose/wasm` (ADR 0008 layer 4,
 * ADR 0034). It runs vector files through the **facade** (what users call), mirroring the Rust
 * reference runner `crates/polyjose/tests/conformance.rs` operation by operation, and returns the
 * ADR 0034 §2 results. No Node-only imports: `node-main.ts` feeds it files from disk, and a
 * browser page or a workerd script can feed it the same files.
 *
 * Rules (conformance/README.md "Rules for every runner"):
 * - a file that isn't strict JSON (duplicate members included, RFC 7493 §2.3) or isn't valid
 *   against `schema.json` fails, whether or not it would be skipped;
 * - a vector whose `features` this build lacks is `skipped` with `reason: "feature:<names>"`
 *   (ADR 0034 §3); nothing else is ever skipped;
 * - an unknown or unmapped operation, a broken vector, and any exception that isn't a
 *   `PolyjoseError` (a facade `TypeError`, napi's `InvalidArg`) are `fail`, never an outcome;
 * - a `PolyjoseError` is the library's outcome and is compared by its `code` (ADR 0030 §5);
 * - a success expectation lists exactly the outputs; values are compared as JSON values
 *   (member order ignored, numbers as doubles, RFC 8259; 0004 T10-r1 ambiguity 1);
 * - JSON-object inputs (keys, JWK Sets, headers, claims, JSON JWS/JWE) are handed to the library
 *   as their own compact text in file order, never re-serialized from a JS object, so `jwt.issue`
 *   claims keep their member order (ADR 0027 §1; T10-r1 ambiguity 4);
 * - the clock is the vector's `now`, always (ADR 0028 §4): the runner never reads `Date.now`;
 * - a boolean policy member set to `false` keeps the default: the opt-out is never called with
 *   `false` (T10-r1 ambiguity 6).
 */

import type { PolyjoseApi } from "../src/api.js";
import type { JsonObject, JwtVerifyOptions, JweDecryptOptions } from "../src/types.js";
import { scanJson, textAt, type JsonNode } from "./json-text.js";
import { jsonEqual, schemaViolation } from "./schema.js";

/** One vector file: its path under `conformance/vectors` (`/`-separated) and its JSON text. */
export interface VectorFile {
  readonly path: string;
  readonly json: string;
}

export interface RunOptions {
  /** The parsed `conformance/schema.json`; required, so no vector runs unchecked. */
  readonly schema: unknown;
  /** The vector-file feature names this build enables (`"deflate"`, `"fixed-rng"`); bindings: none. */
  readonly features?: readonly string[];
}

/** The observed outcome of an executed vector (ADR 0034 §2). */
export type Actual = { readonly ok: true } | { readonly ok: false; readonly error: string };

/** One ADR 0034 §2 result. `reason` is the skip reason, or a human-readable failure message. */
export interface VectorResult {
  readonly id: string;
  readonly op: string;
  readonly status: "pass" | "fail" | "skipped";
  readonly actual?: Actual;
  readonly reason?: string;
}

/** A broken vector or a failed runner check: the vector fails, with this message. */
class HarnessError extends Error {}

/** The library refused: the vector's outcome is this code. */
class LibraryError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

type Out = Record<string, unknown>;
type Outcome = { ok: true; out: Out } | { ok: false; error: string };

/** The `jwk.thumbprint` hash names of the schema, mapped to the facade's (ADR 0030 §4). */
const HASHES: Readonly<Record<string, string>> = { "sha-256": "SHA-256" };

/** The members a generated private key has (RFC 7518 §6.2.1-§6.2.2, RFC 8037 §2, RFC 7518 §6.4.1), plus `alg`. */
const GENERATED_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  EC: ["alg", "crv", "d", "kty", "x", "y"],
  OKP: ["alg", "crv", "d", "kty", "x"],
  oct: ["alg", "k", "kty"],
};

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function hexDecode(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** Runs every file and returns one result per file, in order. */
export async function runVectors(api: PolyjoseApi, files: readonly VectorFile[], options: RunOptions): Promise<VectorResult[]> {
  const results: VectorResult[] = [];
  for (const file of files) results.push(await runOne(api, file, options));
  return results;
}

async function runOne(api: PolyjoseApi, file: VectorFile, options: RunOptions): Promise<VectorResult> {
  const id = `${file.path}#0`; // one vector per file (ADR 0034 §1 as amended by ADR 0045 §4)
  let op = "unknown";
  let source = "<missing>";
  const fail = (problem: string, actual?: Actual): VectorResult => ({
    id,
    op,
    status: "fail",
    ...(actual === undefined ? {} : { actual }),
    reason: `${file.path} (source: ${source}): ${problem}`,
  });

  let tree: JsonNode;
  let value: unknown;
  try {
    tree = scanJson(file.json);
    value = JSON.parse(file.json);
  } catch (e) {
    return fail(`not a valid JSON text (${message(e)}); see conformance/schema.json`);
  }
  if (isObject(value)) {
    if (typeof value["operation"] === "string") op = value["operation"];
    if (typeof value["source"] === "string" && /\S/.test(value["source"])) source = value["source"];
  }
  try {
    if (options.schema === undefined) throw new HarnessError("no schema supplied to runVectors");
    const violation = schemaViolation(options.schema, value);
    if (violation !== undefined) return fail(violation);
    const vector = value as { operation: string; input: Out; expect: Out; features?: string[] };
    crossMemberRules(vector);
    const enabled = options.features ?? [];
    const missing = (vector.features ?? []).filter((f) => !enabled.includes(f));
    if (missing.length > 0) return { id, op, status: "skipped", reason: `feature:${missing.join(",")}` };

    const outcome = await execute(api, vector, new Text(file.json, tree));
    const actual: Actual = outcome.ok ? { ok: true } : { ok: false, error: outcome.error };
    const mismatch = compare(vector.expect, outcome);
    return mismatch === undefined ? { id, op, status: "pass", actual } : fail(mismatch, actual);
  } catch (e) {
    return fail(e instanceof HarnessError ? e.message : `exception in the runner or the binding: ${message(e)}`);
  }
}

function message(e: unknown): string {
  if (e instanceof Error) return `${e.name}: ${e.message}`;
  return String(e);
}

/**
 * The rules tying members together that the schema can't state, as the Rust runner's
 * `check_jwe_encrypt_features` and `check_jwt_issue` check them (conformance/README.md).
 */
function crossMemberRules(vector: { operation: string; input: Out; expect: Out; features?: string[] }): void {
  const { input, expect } = vector;
  const features = vector.features ?? [];
  if (vector.operation === "jwe.encrypt") {
    for (const [member, feature] of [["rng_b64u", "fixed-rng"], ["protected_b64u", "fixed-rng"], ["compress", "deflate"]] as const) {
      if (Object.hasOwn(input, member) && !features.includes(feature)) {
        throw new HarnessError(`/features: \`input/${member}\` needs "${feature}" listed in \`features\``);
      }
    }
  }
  if (vector.operation === "jwt.issue") {
    const encrypt = Object.hasOwn(input, "encrypt");
    const validate = Object.hasOwn(input, "validate");
    if (expect["ok"] === true && Object.hasOwn(expect, "token") && encrypt) {
      throw new HarnessError("/expect/token: an encrypted token is randomized (RFC 7516 §5.1); expect {\"ok\": true} and give `validate`");
    }
    if (expect["ok"] === true && !Object.hasOwn(expect, "token") && !validate && !encrypt) {
      throw new HarnessError("/input/validate: required when the expectation has no `token`");
    }
    if (expect["ok"] === false && validate) {
      throw new HarnessError("/input/validate: used only when the issue succeeds, so a failure vector has none");
    }
  }
}

/** Compares an outcome with the expectation, as the Rust runner's `compare` does. */
function compare(expect: Out, outcome: Outcome): string | undefined {
  if (expect["ok"] === true) {
    if (!outcome.ok) return `expected success, got error ${outcome.error}`;
    for (const [name, want] of Object.entries(expect)) {
      if (name === "ok") continue;
      if (!Object.hasOwn(outcome.out, name)) return `\`${name}\`: expected ${JSON.stringify(want)}, got nothing`;
      if (!jsonEqual(want, outcome.out[name])) return `\`${name}\`: expected ${JSON.stringify(want)}, got ${JSON.stringify(outcome.out[name])}`;
    }
    for (const name of Object.keys(outcome.out)) {
      if (!Object.hasOwn(expect, name)) return `\`${name}\`: expected nothing, got ${JSON.stringify(outcome.out[name])}`;
    }
    return undefined;
  }
  if (outcome.ok) return `expected error ${String(expect["error"])}, but the operation succeeded with ${JSON.stringify(outcome.out)}`;
  return outcome.error === expect["error"] ? undefined : `expected error ${String(expect["error"])}, got error ${outcome.error}`;
}

/** The vector file's text and tree: inputs are handed over as their own text (see the module doc). */
class Text {
  readonly #text: string;
  readonly #tree: JsonNode;
  constructor(text: string, tree: JsonNode) {
    this.#text = text;
    this.#tree = tree;
  }
  /** The compact text of the value at `path` (from the vector root), in file order. */
  at(...path: (string | number)[]): string {
    const text = textAt(this.#text, this.#tree, path);
    if (text === undefined) throw new HarnessError(`no value at /${path.join("/")}`);
    return text;
  }
  /** As {@link at}, or undefined when the member is absent. */
  opt(...path: (string | number)[]): string | undefined {
    return textAt(this.#text, this.#tree, path);
  }
}

/** Calls the library: a `PolyjoseError` becomes the outcome; anything else fails the vector. */
async function lib<T>(api: PolyjoseApi, call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (e) {
    if (e instanceof api.PolyjoseError) throw new LibraryError(e.code);
    throw e;
  }
}

/** A library call inside a runner check (round trip, decoding): any failure fails the vector. */
async function check<T>(api: PolyjoseApi, what: string, call: () => Promise<T>): Promise<T> {
  try {
    return await lib(api, call);
  } catch (e) {
    if (e instanceof LibraryError) throw new HarnessError(`${what} (${e.code})`);
    throw e;
  }
}

/** A `*_b64u` input's octets. A non-canonical value is a broken vector, never an outcome. */
function decode(api: PolyjoseApi, value: unknown, name: string): Promise<Uint8Array> {
  return check(api, `\`${name}\` is not canonical base64url; the runner must decode it`, () => api.base64urlDecode(String(value)));
}

function encode(api: PolyjoseApi, bytes: Uint8Array): Promise<string> {
  return check(api, "base64url encoding of an output failed", () => api.base64urlEncode(bytes));
}

const str = (v: unknown): string => v as string;
const strs = (v: unknown): string[] => [...(v as string[])];

async function execute(api: PolyjoseApi, vector: { operation: string; input: Out; expect: Out }, text: Text): Promise<Outcome> {
  const out: Out = {};
  const handler = Object.hasOwn(OPERATIONS, vector.operation) ? OPERATIONS[vector.operation] : undefined;
  if (handler === undefined) {
    throw new HarnessError(`operation \`${vector.operation}\` is not implemented by the JS runner; a vector is never skipped`);
  }
  try {
    await handler(api, vector.input, vector.expect, text, out);
  } catch (e) {
    if (e instanceof LibraryError) return { ok: false, error: e.code };
    throw e;
  }
  return { ok: true, out };
}

type Handler = (api: PolyjoseApi, input: Out, expect: Out, text: Text, out: Out) => Promise<void>;

/**
 * One handler per schema operation, each mirroring the Rust runner's function of the same name
 * (`run_jws_sign`, `run_jwe_decrypt`, ...). The facade call that ADR 0030 §4 maps it to is named
 * in each comment; conformance/README.md "Binding runners" lists the same mapping (T02).
 */
const OPERATIONS: Readonly<Record<string, Handler>> = {
  // b64url.encode → base64urlEncode(hex-decoded bytes_hex); RFC 4648 §5.
  "b64url.encode": async (api, input, _expect, _text, out) => {
    out["b64u"] = await lib(api, () => api.base64urlEncode(hexDecode(str(input["bytes_hex"]))));
  },
  // b64url.decode → base64urlDecode(b64u), hex-encoded; RFC 4648 §5.
  "b64url.decode": async (api, input, _expect, _text, out) => {
    out["bytes_hex"] = hexEncode(await lib(api, () => api.base64urlDecode(str(input["b64u"]))));
  },
  // jwk.thumbprint → jwkThumbprint + jwkThumbprintUri (RFC 7638 §3, RFC 9278 §3); hash "sha-256" → "SHA-256".
  "jwk.thumbprint": async (api, input, _expect, text, out) => {
    const hash = HASHES[str(input["hash"])];
    if (hash === undefined) throw new HarnessError(`hash \`${str(input["hash"])}\` has no facade name`);
    const jwk = text.at("input", "jwk");
    out["thumbprint"] = await lib(api, () => api.jwkThumbprint(jwk, hash as "SHA-256"));
    out["thumbprint_uri"] = await lib(api, () => api.jwkThumbprintUri(jwk, hash as "SHA-256"));
  },

  // jws.sign → jwsSignCompact / jwsSignFlattened / jwsSignGeneral (RFC 7515 §5.1, §7).
  "jws.sign": async (api, input, expect, text, out) => {
    const serialization = str(input["serialization"]);
    const payload = await decode(api, input["payload_b64u"], "payload_b64u");
    const detached = input["detached"] === true;
    const signers = (input["signers"] as Out[]).map((s, i) => {
      const signer: { key: string; protectedB64u?: string; unprotectedHeader?: string } = { key: text.at("input", "signers", i, "key") };
      if (typeof s["protected_b64u"] === "string") signer.protectedB64u = s["protected_b64u"];
      const header = text.opt("input", "signers", i, "header");
      if (header !== undefined) signer.unprotectedHeader = header; // RFC 7515 §7.2.1; ADR 0045 §1
      return signer;
    });
    const first = signers[0] as (typeof signers)[number];
    let signed: string;
    if (serialization === "compact") {
      const opts: { protectedB64u?: string; detached?: boolean } = {};
      if (first.protectedB64u !== undefined) opts.protectedB64u = first.protectedB64u;
      if (detached) opts.detached = true;
      signed = await lib(api, () => api.jwsSignCompact(payload, first.key, opts));
    } else if (serialization === "flattened") {
      signed = await lib(api, () => api.jwsSignFlattened(payload, first, detached));
    } else {
      signed = await lib(api, () => api.jwsSignGeneral(payload, signers, detached));
    }
    const jws: unknown = serialization === "compact" ? signed : parseOutput(signed, "the signed JSON JWS");
    const verifyWith = isObject(expect["verify_with"]) ? expect["verify_with"] : undefined;
    if (verifyWith === undefined) {
      out["jws"] = jws;
      return;
    }
    // Round trip (Rust `check_round_trip`): shape, verify with verify_with, same payload.
    const shapeOk =
      serialization === "compact"
        ? signed.split(".").length === 3
        : serialization === "flattened"
          ? isObject(jws) && Object.hasOwn(jws, "signature") && !Object.hasOwn(jws, "signatures")
          : isObject(jws) && Array.isArray(jws["signatures"]) && jws["signatures"].length === signers.length;
    if (!shapeOk) throw new HarnessError(`round trip: the output is not a ${serialization} JWS with ${signers.length} signature(s)`);
    const key = text.at("expect", "verify_with", "key");
    const opts: { allowedAlgs: string[]; detachedPayload?: Uint8Array } = { allowedAlgs: strs(verifyWith["allowed_algs"]) };
    if (detached) opts.detachedPayload = payload;
    const verified = await check(api, "round trip: the signed JWS does not verify with verify_with", () =>
      serialization === "compact" ? api.jwsVerifyCompact(signed, key, opts) : api.jwsVerifyJson(signed, key, opts),
    );
    if (!bytesEqual(verified.payload, payload)) throw new HarnessError("round trip: the verified payload is not the signed one");
    out["verify_with"] = verifyWith;
  },

  // jws.verify → jwsVerifyCompact (string) / jwsVerifyJson (object, as its text); RFC 7515 §5.2.
  "jws.verify": async (api, input, _expect, text, out) => {
    const key = text.at("input", "key");
    const opts: { allowedAlgs: string[]; detachedPayload?: Uint8Array; maxInputLen?: number; maxSignatures?: number } = {
      allowedAlgs: strs(input["allowed_algs"]),
    };
    if (Object.hasOwn(input, "detached_payload_b64u")) opts.detachedPayload = await decode(api, input["detached_payload_b64u"], "detached_payload_b64u");
    if (typeof input["max_input_len"] === "number") opts.maxInputLen = input["max_input_len"];
    if (typeof input["max_signatures"] === "number") opts.maxSignatures = input["max_signatures"];
    const jws = input["jws"];
    const verified = await lib(api, () =>
      typeof jws === "string" ? api.jwsVerifyCompact(jws, key, opts) : api.jwsVerifyJson(text.at("input", "jws"), key, opts),
    );
    out["payload_b64u"] = await encode(api, verified.payload);
    out["alg"] = verified.alg;
    out["signature_index"] = verified.signatureIndex;
  },

  // keys.import_pem → jwkFromPem (ADR 0018 §3).
  "keys.import_pem": async (api, input, _expect, _text, out) => {
    out["jwk"] = imported(await lib(api, () => api.jwkFromPem(str(input["pem"]))));
  },
  // keys.import_der → jwkFromDer(decoded der_b64u, format).
  "keys.import_der": async (api, input, _expect, _text, out) => {
    const der = await decode(api, input["der_b64u"], "der_b64u");
    out["jwk"] = imported(await lib(api, () => api.jwkFromDer(der, str(input["format"]) as "spki")));
  },
  // keys.export_pem → jwkToPem(jwk, format); the JWK import inside is the first step.
  "keys.export_pem": async (api, input, _expect, text, out) => {
    out["pem"] = await lib(api, () => api.jwkToPem(text.at("input", "jwk"), str(input["format"]) as "spki"));
  },
  // keys.export_der → jwkToDer(jwk, format), base64url.
  "keys.export_der": async (api, input, _expect, text, out) => {
    out["der_b64u"] = await encode(api, await lib(api, () => api.jwkToDer(text.at("input", "jwk"), str(input["format"]) as "spki")));
  },
  // keys.generate_for → jwkGenerateForAlg(alg) (ADR 0018 §5); the surface resolves the RFC 7518 §7.1 name.
  "keys.generate_for": async (api, input, _expect, _text, out) => {
    const jwk = await lib(api, () => api.jwkGenerateForAlg(str(input["alg"])));
    out["shape"] = await generatedShape(api, jwk);
  },

  // jwe.encrypt → jweEncryptCompact / jweEncryptJson(form) (RFC 7516 §5.1, §7).
  "jwe.encrypt": async (api, input, expect, text, out) => {
    if (Object.hasOwn(input, "rng_b64u") || Object.hasOwn(input, "protected_b64u")) {
      throw new HarnessError("a reproducible encryption (rng_b64u, protected_b64u) is not in the binding API (ADR 0005)");
    }
    const serialization = str(input["serialization"]);
    const plaintext = await decode(api, input["plaintext_b64u"], "plaintext_b64u");
    const recipientsIn = input["recipients"] as Out[];
    const recipients = [];
    for (const [i, r] of recipientsIn.entries()) {
      const recipient: { alg: string; key: string; header?: string; apu?: Uint8Array; apv?: Uint8Array; p2c?: number; p2sLen?: number } = {
        alg: str(r["alg"]),
        key: text.at("input", "recipients", i, "key"),
      };
      const header = text.opt("input", "recipients", i, "header");
      if (header !== undefined) recipient.header = header;
      if (Object.hasOwn(r, "apu_b64u")) recipient.apu = await decode(api, r["apu_b64u"], "apu_b64u");
      if (Object.hasOwn(r, "apv_b64u")) recipient.apv = await decode(api, r["apv_b64u"], "apv_b64u");
      if (typeof r["p2c"] === "number") recipient.p2c = r["p2c"];
      if (typeof r["p2s_len"] === "number") recipient.p2sLen = r["p2s_len"];
      recipients.push(recipient);
    }
    const opts: { enc: string; recipients: typeof recipients; protectedHeader?: string; sharedUnprotectedHeader?: string; aad?: Uint8Array; compress?: boolean } = {
      enc: str(input["enc"]),
      recipients,
    };
    const protectedHeader = text.opt("input", "protected");
    if (protectedHeader !== undefined) opts.protectedHeader = protectedHeader;
    const shared = text.opt("input", "unprotected");
    if (shared !== undefined) opts.sharedUnprotectedHeader = shared;
    if (Object.hasOwn(input, "aad_b64u")) opts.aad = await decode(api, input["aad_b64u"], "aad_b64u");
    if (input["compress"] === true) opts.compress = true;
    const encrypted = await lib(api, () =>
      serialization === "compact" ? api.jweEncryptCompact(plaintext, opts) : api.jweEncryptJson(plaintext, opts, serialization as "general"),
    );
    const jwe: unknown = serialization === "compact" ? encrypted : parseOutput(encrypted, "the encrypted JSON JWE");
    const decryptWith = isObject(expect["decrypt_with"]) ? expect["decrypt_with"] : undefined;
    if (decryptWith === undefined) {
      out["jwe"] = jwe;
      return;
    }
    // Round trip (Rust `check_jwe_round_trip`): shape, decrypt with decrypt_with, same plaintext.
    const shapeOk =
      serialization === "compact"
        ? encrypted.split(".").length === 5
        : serialization === "flattened"
          ? isObject(jwe) && Object.hasOwn(jwe, "ciphertext") && !Object.hasOwn(jwe, "recipients")
          : isObject(jwe) && Array.isArray(jwe["recipients"]) && jwe["recipients"].length === recipients.length;
    if (!shapeOk) throw new HarnessError(`round trip: the output is not a ${serialization} JWE with ${recipients.length} recipient(s)`);
    const key = text.at("expect", "decrypt_with", "key");
    const policy = { allowedAlgs: strs(decryptWith["allowed_algs"]), allowedEnc: strs(decryptWith["allowed_enc"]) };
    const decrypted = await check(api, "round trip: the encrypted JWE does not decrypt with decrypt_with", () =>
      serialization === "compact" ? api.jweDecryptCompact(encrypted, key, policy) : api.jweDecryptJson(encrypted, key, policy),
    );
    if (!bytesEqual(decrypted.plaintext, plaintext)) throw new HarnessError("round trip: the decrypted plaintext is not the encrypted one");
    out["decrypt_with"] = decryptWith;
  },

  // jwe.decrypt → jweDecryptCompact (string) / jweDecryptJson (object, as its text); RFC 7516 §5.2.
  "jwe.decrypt": async (api, input, _expect, text, out) => {
    const key = text.at("input", "key");
    const policy = jweDecryptOptions(input);
    const jwe = input["jwe"];
    const decrypted = await lib(api, () =>
      typeof jwe === "string" ? api.jweDecryptCompact(jwe, key, policy) : api.jweDecryptJson(text.at("input", "jwe"), key, policy),
    );
    out["plaintext_b64u"] = await encode(api, decrypted.plaintext);
    out["recipient"] = decrypted.recipientIndex;
  },

  // jwt.validate → jwtVerify / jwtVerifyWithJwks, or jwtDecryptNested(WithJwks) with `decrypt` (RFC 7519 §7.2).
  "jwt.validate": async (api, input, _expect, text, out) => {
    const verified = await jwtValidate(api, input, ["input"], str(input["token"]), text);
    out["claims"] = verified.claims;
    out["alg"] = verified.alg;
    // ADR 0029 §4: present exactly when a key set verified; 0 is an index, not "absent".
    if (verified.keyIndex !== undefined) out["key_index"] = verified.keyIndex;
  },

  // jwt.issue → jwtSign, then jwtEncryptNested with `encrypt` (RFC 7519 §7.1; ADR 0027 §7-§8).
  "jwt.issue": async (api, input, expect, text, out) => {
    // Exactly the calls of the README "Binding runners" table, in order, and none of the runner's
    // own (no jwkParse pre-check, B02): jwtSign (which imports `key`, then parses `claims`), then
    // jwtEncryptNested with `encrypt` (which imports `encrypt.key`).
    const key = text.at("input", "key");
    const claims = text.at("input", "claims");
    const encrypt = isObject(input["encrypt"]) ? input["encrypt"] : undefined;
    const encryptKey = encrypt === undefined ? undefined : text.at("input", "encrypt", "key");
    const alg = str(input["alg"]);
    const opts: { alg: string; typ?: string; omitTyp?: boolean } = { alg };
    // `typ`: absent → the core default JWT; null → omitted (RFC 7519 §5.1); a string → set.
    if (Object.hasOwn(input, "typ")) {
      if (input["typ"] === null) opts.omitTyp = true;
      else opts.typ = str(input["typ"]);
    }
    let token = await lib(api, () => api.jwtSign(claims, key, opts));
    let parts = 3;
    if (encrypt !== undefined && encryptKey !== undefined) {
      const signed = token;
      token = await lib(api, () =>
        api.jwtEncryptNested(signed, { enc: str(encrypt["enc"]), recipients: [{ alg: str(encrypt["alg"]), key: encryptKey }] }),
      );
      parts = 5;
    }
    if (token.split(".").length !== parts) throw new HarnessError(`the issued token is not ${parts} compact parts`);
    if (isObject(input["validate"])) {
      // Round trip (Rust `check_jwt_issue_round_trip`): validates, with the issued alg and claims.
      let verified;
      try {
        verified = await jwtValidate(api, input["validate"], ["input", "validate"], token, text);
      } catch (e) {
        if (e instanceof LibraryError) throw new HarnessError(`round trip: the issued token does not validate with \`validate\` (${e.code})`);
        throw e;
      }
      if (verified.alg !== alg) throw new HarnessError(`round trip: validated with alg ${verified.alg}, issued with ${alg}`);
      if (!jsonEqual(verified.claims, input["claims"])) {
        throw new HarnessError(`round trip: validated claims ${JSON.stringify(verified.claims)} are not the issued ${claims}`);
      }
    }
    if (expect["ok"] === true && Object.hasOwn(expect, "token")) out["token"] = token;
  },
};

function parseOutput(text: string, what: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new HarnessError(`${what} does not parse as JSON`);
  }
}

/** A PEM/DER import result; an `oct` key fails the vector whatever it expects (RFC 8725 §2.1). */
function imported(jwk: JsonObject): JsonObject {
  if (jwk["kty"] === "oct") throw new HarnessError("a PEM or DER import returned an oct key (RFC 8725 §2.1)");
  return jwk;
}

/** Rust `generated_shape`: private, exactly the RFC members, imports back unchanged; then the shape. */
async function generatedShape(api: PolyjoseApi, jwk: JsonObject): Promise<Out> {
  const kty = typeof jwk["kty"] === "string" ? jwk["kty"] : "";
  const isPrivate = kty === "oct" || Object.hasOwn(jwk, "d");
  if (!isPrivate) throw new HarnessError("generate_for returned a public key");
  const names = Object.keys(jwk).sort();
  const expected = GENERATED_MEMBERS[kty];
  if (expected === undefined || !jsonEqual(names, [...expected])) {
    throw new HarnessError(`generate_for returned a JWK with members ${JSON.stringify(names)}`);
  }
  const again = await check(api, "the generated JWK does not import", () => api.jwkParse(JSON.stringify(jwk)));
  if (!jsonEqual(again, jwk)) throw new HarnessError("the generated JWK imports as a different key");
  const shape: Out = {};
  for (const name of ["kty", "crv", "alg"]) if (Object.hasOwn(jwk, name)) shape[name] = jwk[name];
  if (typeof jwk["k"] === "string") shape["k_octets"] = (await decode(api, jwk["k"], "the generated k")).length;
  return shape;
}

/** The decrypt options of `jwe.decrypt` and of a nested JWT's `decrypt` (Rust `jwe_policy`). */
function jweDecryptOptions(object: Out): JweDecryptOptions {
  const opts: {
    allowedAlgs: string[];
    allowedEnc: string[];
    understoodCrit?: string[];
    maxInputLen?: number;
    maxRecipients?: number;
    maxPbes2Count?: number;
    maxDecompressedLen?: number;
  } = { allowedAlgs: strs(object["allowed_algs"]), allowedEnc: strs(object["allowed_enc"]) };
  if (Object.hasOwn(object, "understood_crit")) opts.understoodCrit = strs(object["understood_crit"]);
  for (const [member, field] of [
    ["max_input_len", "maxInputLen"],
    ["max_recipients", "maxRecipients"],
    ["max_pbes2_count", "maxPbes2Count"],
    ["max_decompressed_len", "maxDecompressedLen"],
  ] as const) {
    const n = object[member];
    if (typeof n === "number") opts[field] = n;
  }
  return opts;
}

/**
 * The JWT verify options from `allowed_algs`, `now` and `policy` (Rust `jwt_policy`), member by
 * member. An absent member, or a boolean `false`, calls nothing (the library default stays).
 */
function jwtVerifyOptions(object: Out): JwtVerifyOptions {
  const policy = isObject(object["policy"]) ? object["policy"] : {};
  const opts: {
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
  } = { allowedAlgs: strs(object["allowed_algs"]), now: object["now"] as number };
  const typ = isObject(policy["typ"]) ? policy["typ"] : undefined;
  if (policy["profile"] !== undefined && typ?.["mode"] === "default") {
    throw new HarnessError(
      '`policy/typ/mode` "default" contradicts `policy/profile` "access_token", which requires typ at+jwt (RFC 9068 §4)',
    );
  }
  if (policy["issuer"] !== undefined) opts.issuers = typeof policy["issuer"] === "string" ? [policy["issuer"]] : strs(policy["issuer"]);
  if (policy["audience"] !== undefined) opts.audiences = strs(policy["audience"]);
  if (typeof policy["subject"] === "string") opts.subject = policy["subject"];
  if (typeof policy["leeway"] === "number") opts.leeway = policy["leeway"];
  if (typeof policy["max_age"] === "number") opts.maxAge = policy["max_age"];
  if (policy["require"] !== undefined) opts.requiredClaims = strs(policy["require"]);
  if (policy["allow_missing_exp"] === true) opts.allowMissingExp = true;
  if (policy["ignore_audience"] === true) opts.ignoreAudience = true;
  if (typ?.["mode"] === "exact") opts.typ = str(typ["value"]);
  if (typ?.["mode"] === "any") opts.anyTyp = true;
  if (typeof policy["profile"] === "string") opts.profile = policy["profile"];
  if (typeof policy["max_key_candidates"] === "number") opts.maxKeyCandidates = policy["max_key_candidates"];
  return opts;
}

/**
 * Validates `token` with a `jwt.validate` input or a `jwt.issue` `validate` object at `base`
 * (Rust `jwt_validation` + `jwt_verify`): the four facade forms are chosen by `decrypt` and by
 * `key` vs `jwks` (ADR 0030 §4). A nested JWT's result is its inner JWT.
 */
async function jwtValidate(
  api: PolyjoseApi,
  object: Out,
  base: (string | number)[],
  token: string,
  text: Text,
): Promise<{ claims: JsonObject; alg: string; keyIndex?: number }> {
  const options = jwtVerifyOptions(object);
  const decrypt = isObject(object["decrypt"]) ? object["decrypt"] : undefined;
  const jwks = text.opt(...base, "jwks");
  const keys = jwks ?? text.at(...base, "key");
  if (decrypt !== undefined) {
    const decryptKey = text.at(...base, "decrypt", "key");
    const decryptOptions = jweDecryptOptions(decrypt);
    const nested = await lib(api, () =>
      jwks === undefined
        ? api.jwtDecryptNested(token, decryptKey, decryptOptions, keys, options)
        : api.jwtDecryptNestedWithJwks(token, decryptKey, decryptOptions, keys, options),
    );
    return nested.inner;
  }
  return lib(api, () => (jwks === undefined ? api.jwtVerify(token, keys, options) : api.jwtVerifyWithJwks(token, keys, options)));
}
