// jwt-oracle: turns a JWT vector spec into conformance vectors with
// node:crypto (OpenSSL-backed), an implementation independent of polyjose.
// A generator only: CI never runs it, and its output is committed.
//
//   node conformance/tools/jwt-oracle/gen.mjs <spec.json> <out.json>
//
// Requires Node >= 24 and only node:crypto, node:fs and node:path (no npm
// dependencies). Keys are named from keys.json next to this file. The spec
// format is documented in README.md.

import { createHmac, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const major = Number(process.versions.node.split(".")[0]);
if (major < 24) {
  throw new Error(`Node >= 24 is required, this is ${process.version}`);
}

/** Named in every generated vector's `source`. */
export const ORACLE_SOURCE =
  `conformance/tools/jwt-oracle (node:crypto, Node ${process.version}, ` +
  `OpenSSL ${process.versions.openssl})`;

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const unb64u = (text, what) => {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error(`${what} is not base64url text`);
  }
  const bytes = Buffer.from(text, "base64url");
  if (b64u(bytes) !== text) throw new Error(`${what} is not canonical base64url`);
  return bytes;
};
const utf8 = (text) => Buffer.from(text, "utf8");
const ascii = (text) => Buffer.from(text, "ascii");
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function fail(message) {
  throw new Error(message);
}

function onlyMembers(obj, allowed, what) {
  for (const name of Object.keys(obj)) {
    if (!allowed.includes(name)) fail(`${what}: unknown member "${name}" (allowed: ${allowed.join(", ")})`);
  }
}

function exactlyOne(obj, names, what) {
  const present = names.filter((n) => obj[n] !== undefined);
  if (present.length !== 1) fail(`${what}: give exactly one of ${names.join(", ")}`);
  return present[0];
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/** Loads keys.json: a map from key name to JWK. */
export function loadKeys(file = join(import.meta.dirname, "keys.json")) {
  const doc = JSON.parse(readFileSync(file, "utf8"));
  const keys = new Map();
  for (const [name, entry] of Object.entries(doc.keys)) keys.set(name, entry.jwk);
  return keys;
}

function namedKey(keys, name) {
  const jwk = keys.get(name);
  if (jwk === undefined) fail(`unknown key "${name}" (not in keys.json)`);
  return structuredClone(jwk);
}

// Private members per key type: RFC 7518 §6.2.2 (EC), §6.3.2 (RSA), RFC 8037 §2 (OKP).
const PRIVATE_MEMBERS = { EC: ["d"], OKP: ["d"], RSA: ["d", "p", "q", "dp", "dq", "qi", "oth"] };

function publicPart(jwk, name) {
  const priv = PRIVATE_MEMBERS[jwk.kty];
  if (priv === undefined) fail(`$public: "${name}" is a ${jwk.kty} key, which has no public part; use $key`);
  const out = {};
  for (const [m, v] of Object.entries(jwk)) if (!priv.includes(m)) out[m] = v;
  return out;
}

function octFrom(jwk, name, encoding) {
  if (jwk.kty !== "RSA" && jwk.kty !== "EC" && jwk.kty !== "OKP") {
    fail(`$oct_from: "${name}" is not an asymmetric key`);
  }
  const key = createPublicKey({ key: publicPart(jwk, name), format: "jwk" });
  switch (encoding) {
    case "spki-pem":
      return utf8(key.export({ type: "spki", format: "pem" }));
    case "spki-der":
      return key.export({ type: "spki", format: "der" });
    case "jwk-n":
      if (jwk.kty !== "RSA") fail(`$oct_from: jwk-n needs an RSA key, "${name}" is ${jwk.kty}`);
      return unb64u(jwk.n, `${name}.n`);
    default:
      return fail(`$oct_from: unknown encoding "${encoding}" (spki-pem, spki-der, jwk-n)`);
  }
}

function applyWith(jwk, overrides, what) {
  if (overrides === undefined) return jwk;
  if (!isObject(overrides)) fail(`${what}: "with" must be an object`);
  for (const [m, v] of Object.entries(overrides)) {
    if (v === null) delete jwk[m];
    else jwk[m] = v;
  }
  return jwk;
}

/**
 * Replaces key references anywhere in a spec value:
 * `{"$key": name}` (the JWK as in keys.json, private members included),
 * `{"$public": name}` (its public part) and
 * `{"$oct_from": name, "encoding": e}` (an oct JWK whose octets are that
 * key's SPKI PEM, SPKI DER or RSA modulus, for RFC 8725 §2.1 confusion
 * vectors). Each takes an optional `with` object merged over the result;
 * a `null` value there deletes the member.
 */
function resolveRefs(value, keys) {
  if (Array.isArray(value)) return value.map((v) => resolveRefs(v, keys));
  if (!isObject(value)) return value;
  if ("$key" in value) {
    onlyMembers(value, ["$key", "with"], "$key reference");
    return applyWith(namedKey(keys, value.$key), value.with, "$key");
  }
  if ("$public" in value) {
    onlyMembers(value, ["$public", "with"], "$public reference");
    return applyWith(publicPart(namedKey(keys, value.$public), value.$public), value.with, "$public");
  }
  if ("$oct_from" in value) {
    onlyMembers(value, ["$oct_from", "encoding", "with"], "$oct_from reference");
    const bytes = octFrom(namedKey(keys, value.$oct_from), value.$oct_from, value.encoding);
    return applyWith({ kty: "oct", k: b64u(bytes) }, value.with, "$oct_from");
  }
  const out = {};
  for (const [m, v] of Object.entries(value)) out[m] = resolveRefs(v, keys);
  return out;
}

/** A `key` member: a keys.json name, or an inline JWK (references already resolved). */
function signingKey(key, keys, what) {
  if (typeof key === "string") return namedKey(keys, key);
  if (isObject(key)) return key;
  return fail(`${what}: "key" must be a keys.json name or a JWK object`);
}

// ---------------------------------------------------------------------------
// JWS (RFC 7515)
// ---------------------------------------------------------------------------

// RFC 7518 §3.1, RFC 8037 §3.1, RFC 9864 §2.2. RS*/PS* are absent on purpose:
// no RSA private key is ever used for signing (ADR 0021).
const SIGNERS = {
  HS256: { kty: "oct", hash: "sha256", bytes: 32 },
  HS384: { kty: "oct", hash: "sha384", bytes: 48 },
  HS512: { kty: "oct", hash: "sha512", bytes: 64 },
  ES256: { kty: "EC", crv: "P-256", hash: "sha256", bytes: 64 },
  ES384: { kty: "EC", crv: "P-384", hash: "sha384", bytes: 96 },
  ES512: { kty: "EC", crv: "P-521", hash: "sha512", bytes: 132 },
  EdDSA: { kty: "OKP", crv: "Ed25519", hash: null, bytes: 64 },
  Ed25519: { kty: "OKP", crv: "Ed25519", hash: null, bytes: 64 },
};

/** Signs `input` with `jwk` under `alg`, and checks the result with an independent verify. */
function jwsSign(alg, jwk, input) {
  if (/^(RS|PS)\d+$/.test(alg) || jwk.kty === "RSA") {
    fail(`${alg}: RSA signing is not supported; RS*/PS* vectors use RFC-published tokens only (ADR 0021)`);
  }
  const s = SIGNERS[alg];
  if (s === undefined) fail(`unsupported signing alg "${alg}"`);
  if (jwk.kty !== s.kty || (s.crv !== undefined && jwk.crv !== s.crv)) {
    fail(`${alg} needs a ${s.kty}${s.crv ? ` ${s.crv}` : ""} key, got ${jwk.kty}${jwk.crv ? ` ${jwk.crv}` : ""}`);
  }
  let sig;
  if (s.kty === "oct") {
    // RFC 7518 §3.2: HMAC with a key at least as long as the hash output.
    const k = unb64u(jwk.k, "oct key k");
    if (k.length < s.bytes) fail(`${alg} needs a key of at least ${s.bytes} octets (RFC 7518 §3.2), got ${k.length}`);
    sig = createHmac(s.hash, k).update(input).digest();
    return sig;
  }
  if (jwk.d === undefined) fail(`${alg}: the signing key has no private member d`);
  const priv = createPrivateKey({ key: jwk, format: "jwk" });
  // RFC 7518 §3.4: the ECDSA signature is R || S, each the coordinate size (ieee-p1363).
  const opts = s.kty === "EC" ? { key: priv, dsaEncoding: "ieee-p1363" } : priv;
  sig = sign(s.hash, input, opts);
  if (sig.length !== s.bytes) fail(`${alg}: signature is ${sig.length} octets, expected ${s.bytes}`);
  const pubKey = createPublicKey(priv);
  const vopts = s.kty === "EC" ? { key: pubKey, dsaEncoding: "ieee-p1363" } : pubKey;
  if (!verify(s.hash, input, vopts, sig)) fail(`${alg}: node:crypto does not verify its own signature`);
  return sig;
}

/** The encoded protected header from one of header / header_text / header_b64u. */
function encodeHeader(spec, what) {
  const which = exactlyOne(spec, ["header", "header_text", "header_b64u"], what);
  if (which === "header") {
    if (!isObject(spec.header)) fail(`${what}: header must be an object`);
    return b64u(utf8(JSON.stringify(spec.header)));
  }
  if (which === "header_text") return b64u(utf8(spec.header_text));
  return spec.header_b64u; // verbatim, even when it is not canonical
}

/** The payload octets from one of payload (UTF-8 text) / payload_b64u / payload_json. */
function payloadBytes(spec, what) {
  const which = exactlyOne(spec, ["payload", "payload_b64u", "payload_json"], what);
  if (which === "payload") return utf8(spec.payload);
  if (which === "payload_b64u") return unb64u(spec.payload_b64u, `${what}.payload_b64u`);
  return utf8(JSON.stringify(spec.payload_json));
}

const JWS_MEMBERS = [
  "header",
  "header_text",
  "header_b64u",
  "payload",
  "payload_b64u",
  "payload_json",
  "key",
  "alg",
  "corrupt_signature",
  "signature_b64u",
  "replace_after_signing",
  "serialization",
  "unprotected",
];
const REPLACE_MEMBERS = ["header", "header_text", "header_b64u", "payload", "payload_b64u", "payload_json"];

function decodedHeader(protectedB64) {
  try {
    return JSON.parse(Buffer.from(protectedB64, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

/**
 * The JWS Payload as written in the serialization: BASE64URL(payload)
 * (RFC 7515 §7.1), or with `"b64": false` the octets themselves (RFC 7797
 * §3), which in the compact form may not contain '.' (RFC 7797 §5.2).
 */
function payloadPart(payload, b64, serialization, what) {
  if (b64) return b64u(payload);
  const text = payload.toString("utf8");
  if (!utf8(text).equals(payload)) fail(`${what}: a b64:false payload must be UTF-8 text here`);
  if (serialization === "compact" && text.includes(".")) {
    fail(`${what}: a b64:false compact payload must not contain '.' (RFC 7797 §5.2)`);
  }
  return text;
}

/**
 * Builds a JWS from raw header and payload octets.
 *
 * - Compact (RFC 7515 §7.1): BASE64URL(protected) '.' payload '.'
 *   BASE64URL(signature), signed over the ASCII of the first two parts
 *   (§5.1), or over BASE64URL(protected) '.' payload octets when the header
 *   says `"b64": false` (RFC 7797 §3).
 * - Flattened (RFC 7515 §7.2.2): the same three values as `protected`,
 *   `payload` and `signature`, plus the spec's `unprotected` object as the
 *   unprotected `header` member. It is the compact JWS rewrapped: the
 *   unprotected header is not signed, so the signature stays valid (the
 *   ADR 0049 §2 vector).
 *
 * Negative entries: `alg: "none"` gives an empty signature (RFC 7519 §6.1);
 * `signature_b64u` writes a given signature instead of signing;
 * `corrupt_signature` flips the low bit of the last signature octet;
 * `replace_after_signing` swaps the header and/or payload after signing.
 */
function buildJws(spec, keys) {
  const what = "jws";
  if (!isObject(spec)) fail(`${what} must be an object`);
  onlyMembers(spec, JWS_MEMBERS, what);
  const serialization = spec.serialization ?? "compact";
  if (serialization !== "compact" && serialization !== "flattened") {
    fail(`${what}: serialization must be "compact" or "flattened"`);
  }
  if (spec.unprotected !== undefined) {
    if (serialization !== "flattened") fail(`${what}: "unprotected" needs serialization "flattened"`);
    if (!isObject(spec.unprotected)) fail(`${what}: "unprotected" must be an object`);
  }
  let protectedB64 = encodeHeader(spec, what);
  const header = decodedHeader(protectedB64);
  const b64 = !(isObject(header) && header.b64 === false);
  let payload = payloadBytes(spec, what);
  const alg = spec.alg ?? (isObject(header) ? header.alg : undefined);

  let sig;
  if (spec.signature_b64u !== undefined) {
    if (spec.key !== undefined || spec.corrupt_signature) {
      fail(`${what}: signature_b64u takes no key and no corrupt_signature`);
    }
    sig = spec.signature_b64u; // verbatim
  } else if (alg === "none") {
    // RFC 7519 §6.1: an Unsecured JWT has an empty signature.
    if (spec.key !== undefined) fail(`${what}: alg none takes no key`);
    if (spec.corrupt_signature) fail(`${what}: alg none has no signature to corrupt`);
    sig = "";
  } else {
    if (typeof alg !== "string") fail(`${what}: no alg in the header; give "alg" to name the signing algorithm`);
    if (spec.key === undefined) fail(`${what}: "key" is required`);
    const part = payloadPart(payload, b64, serialization, what);
    const input = b64 ? ascii(`${protectedB64}.${part}`) : Buffer.concat([ascii(`${protectedB64}.`), payload]);
    const raw = jwsSign(alg, signingKey(spec.key, keys, what), input);
    if (spec.corrupt_signature === true) raw[raw.length - 1] ^= 0x01;
    else if (spec.corrupt_signature !== undefined && spec.corrupt_signature !== false) {
      fail(`${what}: corrupt_signature must be a boolean`);
    }
    sig = b64u(raw);
  }

  if (spec.replace_after_signing !== undefined) {
    const r = spec.replace_after_signing;
    const rw = `${what}.replace_after_signing`;
    if (!isObject(r)) fail(`${rw} must be an object`);
    onlyMembers(r, REPLACE_MEMBERS, rw);
    if (["header", "header_text", "header_b64u"].some((m) => r[m] !== undefined)) protectedB64 = encodeHeader(r, rw);
    if (["payload", "payload_b64u", "payload_json"].some((m) => r[m] !== undefined)) payload = payloadBytes(r, rw);
  }

  const part = payloadPart(payload, b64, serialization, what);
  if (serialization === "compact") return { token: `${protectedB64}.${part}.${sig}`, json: null };
  const json = { payload: part, protected: protectedB64 };
  if (spec.unprotected !== undefined) json.header = spec.unprotected;
  json.signature = sig;
  return { token: JSON.stringify(json), json };
}

// ---------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------

const DIRECTIVES = ["jws"];
const REQUIRED = ["description", "operation", "input", "expect"];
const ORDER = ["source", "description", "operation", "input", "expect", "features"];

/** Replaces the strings "$token" and "$token_json" anywhere in `value`. */
function placeToken(value, built, used) {
  if (value === "$token" || value === "$token_json") {
    if (built === null) fail(`"${value}" is used, but the entry builds no token (no jws)`);
    used.count += 1;
    if (value === "$token") return built.token;
    if (built.json === null) fail('"$token_json" needs a JSON serialization');
    return structuredClone(built.json);
  }
  if (Array.isArray(value)) return value.map((v) => placeToken(v, built, used));
  if (!isObject(value)) return value;
  const out = {};
  for (const [m, v] of Object.entries(value)) out[m] = placeToken(v, built, used);
  return out;
}

function buildVector(entry, keys) {
  if (!isObject(entry)) fail("a spec entry must be an object");
  for (const m of REQUIRED) if (entry[m] === undefined) fail(`missing "${m}"`);
  const resolved = resolveRefs(entry, keys);
  const built = resolved.jws === undefined ? null : buildJws(resolved.jws, keys);
  const vector = {};
  vector.source = typeof entry.source === "string" ? `${entry.source}; ${ORACLE_SOURCE}` : ORACLE_SOURCE;
  for (const m of ORDER.slice(1)) if (resolved[m] !== undefined) vector[m] = resolved[m];
  for (const [m, v] of Object.entries(resolved)) {
    if (!ORDER.includes(m) && !DIRECTIVES.includes(m)) vector[m] = v;
  }
  const used = { count: 0 };
  const placed = placeToken(vector, built, used);
  if (built !== null && used.count === 0) fail('the entry builds a token, but no "$token" uses it');
  return placed;
}

/**
 * Generates vectors from a spec, keeping its shape: an array of entries gives
 * an array of vectors, `{ "vectors": [...] , ...}` gives the same object with
 * its other members kept, and a single entry gives a single vector.
 */
export function generate(spec, keys = loadKeys()) {
  const one = (entry, index) => {
    try {
      return buildVector(entry, keys);
    } catch (err) {
      const label = isObject(entry) && typeof entry.description === "string" ? ` ("${entry.description}")` : "";
      throw new Error(`spec entry ${index}${label}: ${err.message}`, { cause: err });
    }
  };
  if (Array.isArray(spec)) return spec.map(one);
  if (isObject(spec) && Array.isArray(spec.vectors)) {
    return { ...spec, vectors: spec.vectors.map(one) };
  }
  return one(spec, 0);
}

/** Reads `specPath`, generates every vector, then writes `outPath` (nothing is written on error). */
export function run(specPath, outPath, keys = loadKeys()) {
  const spec = JSON.parse(readFileSync(specPath, "utf8"));
  const out = generate(spec, keys);
  writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);
  return out;
}

const isMain = (() => {
  try {
    return process.argv[1] !== undefined && realpathSync(resolve(process.argv[1])) === realpathSync(import.meta.filename);
  } catch {
    return false;
  }
})();

if (isMain) {
  const args = process.argv.slice(2);
  if (args.length !== 2) {
    process.stderr.write("usage: node gen.mjs <spec.json> <out.json>\n");
    process.exit(2);
  }
  const out = run(args[0], args[1]);
  const count = Array.isArray(out) ? out.length : Array.isArray(out.vectors) ? out.vectors.length : 1;
  process.stdout.write(`wrote ${count} vector(s) to ${args[1]}\n`);
}
