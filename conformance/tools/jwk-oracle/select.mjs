// Generates the `jwks.select` vectors under conformance/vectors/jwks-select/
// (feature 0015 T04, ADR 0054 §1-§5) from a hand-written spec. A generator
// only: CI never runs it, and its output is committed.
//
//   node conformance/tools/jwk-oracle/select.mjs <specs/select.json> <out-dir>
//
// Requires Node >= 24 and nothing else (no npm dependencies, no polyjose).
//
// The expected outcome of every vector is the spec author's, derived by
// hand from the ADR 0054 text and written into the spec with the rule that
// decides it. This script never decides an outcome: it resolves key
// references into the committed fixtures, checks the spec and the fixtures,
// and writes one file per spec entry (ADR 0045). For a positive entry it
// checks that the expected `jwk` is one of the input members. Every check
// runs before the first file is written; a failed check writes nothing.

import { createECDH, createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const major = Number(process.versions.node.split(".")[0]);
if (major < 24) {
  throw new Error(`Node >= 24 is required, this is ${process.version}`);
}
if (process.argv.length !== 4) {
  throw new Error("usage: node select.mjs <specs/select.json> <out-dir>");
}
const specPath = resolve(process.argv[2]);
const outDir = resolve(process.argv[3]);

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../../..");

function check(condition, message) {
  if (!condition) {
    throw new Error(`self-check failed: ${message}`);
  }
}

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const fromB64u = (text) => Buffer.from(text, "base64url");
const toBig = (bytes) => BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);

// ---------------------------------------------------------------------------
// The fixtures: committed keys only, each checked before use.
// ---------------------------------------------------------------------------

/** conformance/tools/jwt-oracle/keys.json: the shared JWT test keys. */
const JWT_KEYS = readJson(join(REPO, "conformance/tools/jwt-oracle/keys.json")).keys;

/**
 * The 1024-bit RSA public key of the JWE RSA-bound fixtures, which every
 * JWK Set import skips (modulus under 2048 bits, ADR 0021, ADR 0041 §2).
 */
const RSA1024 = readJson(join(REPO, "crates/polyjose/tests/data/jwe/rsa-bound/rsa1024.jwk.json"));
check(fromB64u(RSA1024.n).length === 128 && RSA1024.d === undefined, "rsa1024.jwk.json is a 1024-bit public key");

// RFC 7517 Appendix A, as printed (line breaks inside values removed; the
// same transcription as crates/polyjose/tests/jwk_rfc7517.rs).
const RFC7517_RSA_N =
  "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

const RFC7517_A1 = {
  keys: [
    {
      kty: "EC",
      crv: "P-256",
      x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      use: "enc",
      kid: "1",
    },
    { kty: "RSA", n: RFC7517_RSA_N, e: "AQAB", alg: "RS256", kid: "2011-04-29" },
  ],
};

const RFC7517_A2 = {
  keys: [
    {
      kty: "EC",
      crv: "P-256",
      x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      d: "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
      use: "enc",
      kid: "1",
    },
    {
      kty: "RSA",
      n: RFC7517_RSA_N,
      e: "AQAB",
      d: "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
      p: "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
      q: "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
      dp: "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
      dq: "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
      qi: "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
      alg: "RS256",
      kid: "2011-04-29",
    },
  ],
};

const RFC7517_A3 = {
  keys: [
    { kty: "oct", alg: "A128KW", k: "GawgguFyGrWKav7AX4VKUg" },
    {
      kty: "oct",
      k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
      kid: "HMAC key used in JWS spec Appendix A.1 example",
    },
  ],
};

/** Whole JWK Sets, referred to as `{ "$set": "<name>" }`. */
const SETS = { "rfc7517-a1": RFC7517_A1, "rfc7517-a2": RFC7517_A2, "rfc7517-a3": RFC7517_A3 };

// RFC 7517 A.2's EC private key is A.1's public key: d * G = (x, y).
{
  const [a1, a2] = [RFC7517_A1.keys[0], RFC7517_A2.keys[0]];
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(fromB64u(a2.d));
  const point = ecdh.getPublicKey(null, "uncompressed");
  check(b64u(point.subarray(1, 33)) === a1.x && b64u(point.subarray(33)) === a1.y, "RFC 7517 A.2 EC d matches A.1 x, y");
}
// RFC 7517 A.2's RSA private key belongs to A.1's public key: p * q = n.
{
  const rsa = RFC7517_A2.keys[1];
  check(toBig(fromB64u(rsa.p)) * toBig(fromB64u(rsa.q)) === toBig(fromB64u(rsa.n)), "RFC 7517 A.2 RSA p * q = n");
  check(rsa.n === RFC7517_A1.keys[1].n, "RFC 7517 A.1 and A.2 share the RSA modulus");
}
// RFC 7517 A.3's HMAC key is the RFC 7515 A.1 key (jwt-oracle "oct-64").
check(RFC7517_A3.keys[1].k === JWT_KEYS["oct-64"].jwk.k, "RFC 7517 A.3 HMAC key = RFC 7515 A.1.1 key");

/**
 * Bob's X25519 key of RFC 8037 A.6 (RFC 7748 §6.1), public part with the
 * `kid` RFC 8037 A.6 gives it. Checked against Bob's RFC 7748 §6.1
 * private key: X25519(d, 9) = x.
 */
const X25519_BOB = { kty: "OKP", crv: "X25519", kid: "Bob", x: "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08" };
{
  const d = b64u(Buffer.from("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", "hex"));
  const priv = createPrivateKey({ key: { kty: "OKP", crv: "X25519", d, x: X25519_BOB.x }, format: "jwk" });
  check(createPublicKey(priv).export({ format: "jwk" }).x === X25519_BOB.x, "RFC 7748 §6.1 Bob's d gives RFC 8037 A.6 x");
}

/**
 * The fixed secp256k1 key of conformance/tools/jws-oracle/gen.mjs (its
 * ES256K vectors): d = SHA-256 of a label, (x, y) = d * G, rebuilt here the
 * same way and checked against the public key those vectors carry.
 */
const SECP256K1 = (() => {
  const d = createHash("sha256").update("polyjose jws-oracle ES256K key v1").digest();
  const ecdh = createECDH("secp256k1");
  ecdh.setPrivateKey(d);
  const point = ecdh.getPublicKey(null, "uncompressed");
  return { kty: "EC", crv: "secp256k1", x: b64u(point.subarray(1, 33)), y: b64u(point.subarray(33)), d: b64u(d) };
})();
check(
  SECP256K1.x === "iaRF75M3-cfFwiUEHlB9FebMTJKDr8YEDBIwnOuNsWU" &&
    SECP256K1.y === "OxAm4OdyD33a-vsL6NKW26bLSore_lOgDN2AGbLhn1g",
  "the jws-oracle secp256k1 key",
);

/**
 * Every named key: the jwt-oracle keys plus the ones above. Referred to as
 * `{ "$key": "<name>" }` (as stored, private members included) or
 * `{ "$public": "<name>" }`, the conventions of jwt-oracle/README.md.
 */
const KEYS = new Map(Object.entries(JWT_KEYS).map(([name, entry]) => [name, entry.jwk]));
for (const [name, jwk] of [
  ["rsa1024", RSA1024],
  ["x25519-bob", X25519_BOB],
  ["secp256k1", SECP256K1],
]) {
  check(!KEYS.has(name), `key name ${name} is taken in jwt-oracle/keys.json`);
  KEYS.set(name, jwk);
}

// ---------------------------------------------------------------------------
// Spec resolution.
// ---------------------------------------------------------------------------

/** RFC 7518 §6.3.2 RSA private members; EC and OKP have `d` only (§6.2.2, RFC 8037 §2). */
const RSA_PRIVATE = ["d", "p", "q", "dp", "dq", "qi", "oth"];

/** The public part of a key, as jwt-oracle's `$public`. An `oct` key has none. */
function publicPart(jwk, where) {
  check(jwk.kty !== "oct", `${where}: an oct key has no public part; use $key`);
  const drop = jwk.kty === "RSA" ? RSA_PRIVATE : ["d"];
  return Object.fromEntries(Object.entries(jwk).filter(([name]) => !drop.includes(name)));
}

/**
 * One member of `jwks.keys`: a `$key`/`$public` reference (with an optional
 * `with` merged over it, a `null` deleting a member), or a literal object
 * passed through unchanged. Returns the member and whether it is a fixture
 * key (a literal may be junk under test, so it can never be an expected key).
 */
function resolveMember(spec, where) {
  check(spec !== null && typeof spec === "object" && !Array.isArray(spec), `${where}: not an object`);
  const ref = spec.$key ?? spec.$public;
  if (ref === undefined) {
    check(!Object.keys(spec).some((n) => n.startsWith("$")), `${where}: unknown $ reference`);
    return { jwk: spec, fixture: false };
  }
  check(Object.keys(spec).every((n) => ["$key", "$public", "with"].includes(n)), `${where}: unknown member`);
  check(!("$key" in spec && "$public" in spec), `${where}: both $key and $public`);
  const stored = KEYS.get(ref);
  check(stored !== undefined, `${where}: no key named ${ref}`);
  const base = "$public" in spec ? publicPart(stored, where) : { ...stored };
  const merged = { ...base, ...(spec.with ?? {}) };
  for (const [name, value] of Object.entries(merged)) {
    if (value === null) {
      delete merged[name];
    }
  }
  return { jwk: merged, fixture: true };
}

/** `jwks`: a `$set` reference, or `{ "keys": [members] }`, or any other object as is (malformed sets). */
function resolveJwks(spec, where) {
  if (typeof spec.$set === "string") {
    check(Object.keys(spec).length === 1, `${where}: $set takes no other member`);
    const set = SETS[spec.$set];
    check(set !== undefined, `${where}: no set named ${spec.$set}`);
    return { jwks: structuredClone(set), fixture: set.keys.map(() => true) };
  }
  if (!Array.isArray(spec.keys)) {
    // A set whose `keys` is missing or not an array (InvalidKey vectors).
    check(!JSON.stringify(spec).includes('"$'), `${where}: references in a malformed set`);
    return { jwks: spec, fixture: [] };
  }
  const resolved = spec.keys.map((member, i) => resolveMember(member, `${where}.keys[${i}]`));
  return { jwks: { ...spec, keys: resolved.map((r) => r.jwk) }, fixture: resolved.map((r) => r.fixture) };
}

/** The stable error codes a jwks.select vector may expect (ADR 0054 §4, §5). */
const ERRORS = ["NoMatchingKey", "MultipleMatchingKeys", "UnsupportedAlgorithm", "InvalidKey"];

/** File-name prefix per outcome, so the directory reads by outcome. */
const PREFIX = {
  ok: "select-",
  NoMatchingKey: "no-match-",
  MultipleMatchingKeys: "multiple-",
  UnsupportedAlgorithm: "unsupported-",
  InvalidKey: "invalid-key-",
};

const ENTRY_MEMBERS = ["id", "source", "description", "rule", "jwks", "selector", "expect"];

function build(entry, index) {
  const where = `vectors[${index}] (${entry?.id ?? "no id"})`;
  check(
    Object.keys(entry).length === ENTRY_MEMBERS.length && ENTRY_MEMBERS.every((n) => n in entry),
    `${where}: members must be exactly ${ENTRY_MEMBERS.join(", ")}`,
  );
  for (const name of ["id", "source", "description", "rule"]) {
    check(typeof entry[name] === "string" && /\S/.test(entry[name]), `${where}: ${name} is not text`);
  }
  check(/^[a-z0-9]+(-[a-z0-9]+)*$/.test(entry.id), `${where}: id must be lowercase words joined by -`);
  check(entry.source.includes("ADR 0054 §"), `${where}: source must cite the ADR 0054 rule`);
  check(/RFC \d+/.test(entry.source), `${where}: source must cite an RFC section`);

  const selector = entry.selector;
  check(selector !== null && typeof selector === "object" && !Array.isArray(selector), `${where}: selector`);
  for (const [name, value] of Object.entries(selector)) {
    check(["kid", "alg", "key_use"].includes(name), `${where}: selector member ${name}`);
    check(typeof value === "string", `${where}: selector.${name} is not a string`);
  }

  const { jwks, fixture } = resolveJwks(entry.jwks, `${where}.jwks`);
  const expect = entry.expect;
  let outcome;
  if ("member" in expect) {
    // A positive: the spec names the expected member by its position in
    // `keys` (skipped entries included); the vector carries that member.
    check(Object.keys(expect).length === 1 && Number.isInteger(expect.member), `${where}: expect`);
    check(expect.member >= 0 && expect.member < jwks.keys.length, `${where}: expect.member out of range`);
    check(fixture[expect.member], `${where}: the expected member must be a fixture key, not a literal`);
    const jwk = jwks.keys[expect.member];
    check(
      jwks.keys.some((member) => isDeepStrictEqual(member, jwk)),
      `${where}: the expected jwk is one of the input members`,
    );
    outcome = { ok: true, jwk: structuredClone(jwk) };
  } else {
    check(Object.keys(expect).length === 1 && ERRORS.includes(expect.error), `${where}: expect.error`);
    outcome = { ok: false, error: expect.error };
  }
  const prefix = PREFIX[outcome.ok ? "ok" : outcome.error];
  check(
    entry.id.startsWith(prefix) || entry.id.startsWith("precedence-"),
    `${where}: id must start with ${prefix} (or precedence-)`,
  );

  return {
    file: `${entry.id}.json`,
    vector: {
      source: entry.source,
      description:
        `${entry.description}; ${entry.rule}; ` +
        "outcome hand-derived from the ADR 0054 text (conformance/tools/jwk-oracle/specs/select.json), never computed by polyjose",
      operation: "jwks.select",
      input: { jwks, selector },
      expect: outcome,
    },
  };
}

// ---------------------------------------------------------------------------
// Build everything, then write.
// ---------------------------------------------------------------------------

const spec = readJson(specPath);
check(Array.isArray(spec.vectors) && spec.vectors.length > 0, "the spec has no vectors");

const files = new Map();
spec.vectors.forEach((entry, index) => {
  const { file, vector } = build(entry, index);
  check(!files.has(file), `duplicate id ${file}`);
  files.set(file, `${JSON.stringify(vector, null, 2)}\n`);
});

mkdirSync(outDir, { recursive: true });
for (const [name, text] of files) {
  writeFileSync(join(outDir, name), text);
}
console.log(`wrote ${files.size} files to ${outDir}`);
