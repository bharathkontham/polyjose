// Generates the SHA-384, SHA-512 and hash-name `jwk.thumbprint` vectors
// under conformance/vectors/jwk-thumbprint/ (feature 0015 T03, ADR 0054 §8)
// with node:crypto (OpenSSL-backed), an implementation independent of
// polyjose. A generator only: CI never runs it, and its output is committed.
//
//   node conformance/tools/jwk-oracle/thumbprints.mjs <out-dir>
//
// Requires Node >= 24 and nothing else (no npm dependencies, no polyjose).
// It writes exactly the files listed in README.md next to this file into
// <out-dir>, and nothing else. Every self-check runs before the first file
// is written; a failed check writes nothing.

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";

const major = Number(process.versions.node.split(".")[0]);
if (major < 24) {
  throw new Error(`Node >= 24 is required, this is ${process.version}`);
}
if (process.argv.length !== 3) {
  throw new Error("usage: node thumbprints.mjs <out-dir>");
}
const outDir = resolve(process.argv[2]);

const ORACLE =
  `node:crypto (Node ${process.version}, OpenSSL ${process.versions.openssl}), ` +
  "conformance/tools/jwk-oracle/thumbprints.mjs";

function check(condition, message) {
  if (!condition) {
    throw new Error(`self-check failed: ${message}`);
  }
}

// ---------------------------------------------------------------------------
// RFC 7638 §3: the hash input.
// ---------------------------------------------------------------------------

/**
 * The required members per `kty`, already in lexicographic order of their
 * Unicode code points (RFC 7638 §3.3): RFC 7638 §3.2 for "EC", "RSA" and
 * "oct", RFC 8037 §2 for "OKP". Every other member (alg, kid, use, d, ...)
 * is left out, private members included (RFC 7638 §3.2.1).
 */
const REQUIRED_MEMBERS = {
  EC: ["crv", "kty", "x", "y"],
  RSA: ["e", "kty", "n"],
  oct: ["k", "kty"],
  OKP: ["crv", "kty", "x"],
};

/**
 * The RFC 7638 §3.3 hash input, built by hand: the required members only,
 * in lexicographic order, no whitespace, each name and string value as a
 * JSON string. RFC 7638 §3.3 leaves thumbprints of members that need
 * escaping undefined, so such a value is refused rather than escaped.
 */
function canonicalInput(jwk) {
  const members = REQUIRED_MEMBERS[jwk.kty];
  check(members !== undefined, `no RFC 7638 member list for kty ${jwk.kty}`);
  const parts = members.map((name) => {
    const value = jwk[name];
    check(typeof value === "string", `${jwk.kty} member ${name} is not a string`);
    check(!/["\\\u0000-\u001f]/.test(value), `${name} needs escaping (RFC 7638 §3.3)`);
    return `${JSON.stringify(name)}:${JSON.stringify(value)}`;
  });
  return `{${parts.join(",")}}`;
}

/** The node:crypto digest name for each IANA Hash Name String (RFC 9278 §4). */
const NODE_DIGEST = { "sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512" };

/** BASE64URL(H(UTF8(hash input))), RFC 7638 §3 and §3.4. */
function thumbprint(jwk, ianaName) {
  return createHash(NODE_DIGEST[ianaName])
    .update(canonicalInput(jwk), "utf8")
    .digest("base64url");
}

/** RFC 9278 §3: the prefix, the IANA Hash Name String (§4), the thumbprint. */
function thumbprintUri(jwk, ianaName) {
  return `urn:ietf:params:oauth:jwk-thumbprint:${ianaName}:${thumbprint(jwk, ianaName)}`;
}

// ---------------------------------------------------------------------------
// The six keys, each exactly as in its committed SHA-256 vector.
// ---------------------------------------------------------------------------

const RSA_N =
  "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

const KEYS = [
  {
    slug: "rfc7638-3-1-rsa",
    origin: "the RFC 7638 §3.1 key",
    what: 'the RFC 7638 §3.1 RSA key: only "e", "kty" and "n" are hashed, so "alg" and "kid" do not change it',
    jwk: { kty: "RSA", n: RSA_N, e: "AQAB", alg: "RS256", kid: "2011-04-29" },
  },
  {
    slug: "rfc8037-a3-ed25519-public",
    origin: "the RFC 8037 Appendix A.2 key",
    what: "the RFC 8037 A.2 Ed25519 public key",
    jwk: { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
  },
  {
    slug: "rfc8037-a3-ed25519-private",
    origin: "the RFC 8037 Appendix A.1 key",
    what: 'the RFC 8037 A.1 Ed25519 private key: "d" is not hashed (RFC 7638 §3.2.1), so it equals the public key\'s',
    jwk: {
      kty: "OKP",
      crv: "Ed25519",
      d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
      x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    },
  },
  {
    slug: "rfc7517-a1-p256-public",
    origin: "the RFC 7517 Appendix A.1 key",
    what: "the RFC 7517 A.1 P-256 public key",
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      use: "enc",
      kid: "1",
    },
  },
  {
    slug: "rfc7517-a3-oct-a128kw",
    origin: "the RFC 7517 Appendix A.3 key",
    what: 'the RFC 7517 A.3 AES key: only "k" and "kty" are hashed',
    jwk: { kty: "oct", alg: "A128KW", k: "GawgguFyGrWKav7AX4VKUg" },
  },
  {
    slug: "rfc8037-a6-x25519-public",
    origin: "the RFC 8037 Appendix A.6 key",
    what: "Bob's X25519 public key from RFC 8037 A.6 (RFC 7748 §6.1)",
    jwk: { kty: "OKP", crv: "X25519", kid: "Bob", x: "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08" },
  },
];
const RSA_KEY = KEYS[0].jwk;

// ---------------------------------------------------------------------------
// Self-checks against the values the RFCs print, before anything is built.
// ---------------------------------------------------------------------------

// RFC 7638 §3.1 prints the hash input of its key and its SHA-256 thumbprint.
check(
  canonicalInput(RSA_KEY) === `{"e":"AQAB","kty":"RSA","n":"${RSA_N}"}`,
  "the RFC 7638 §3.1 hash input",
);
check(
  thumbprint(RSA_KEY, "sha-256") === "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "the RFC 7638 §3.1 thumbprint",
);
// RFC 9278 §6 prints the URI of that thumbprint.
check(
  thumbprintUri(RSA_KEY, "sha-256") ===
    "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "the RFC 9278 §6 URI",
);
// RFC 8037 A.3 prints the thumbprint of the A.2 public key, which the A.1
// private key shares (RFC 7638 §3.2.1).
for (const index of [1, 2]) {
  check(
    thumbprint(KEYS[index].jwk, "sha-256") === "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
    `the RFC 8037 A.3 thumbprint of ${KEYS[index].slug}`,
  );
}
// Output lengths: 32, 48 and 64 octets as unpadded base64url.
for (const { jwk } of KEYS) {
  check(thumbprint(jwk, "sha-384").length === 64, "a SHA-384 thumbprint is 64 characters");
  check(thumbprint(jwk, "sha-512").length === 86, "a SHA-512 thumbprint is 86 characters");
}

// ---------------------------------------------------------------------------
// The vectors.
// ---------------------------------------------------------------------------

const files = new Map();

function add(name, vector) {
  check(!files.has(name), `duplicate file ${name}`);
  files.set(name, `${JSON.stringify(vector, null, 2)}\n`);
}

function ok(jwk, ianaName) {
  return { ok: true, thumbprint: thumbprint(jwk, ianaName), thumbprint_uri: thumbprintUri(jwk, ianaName) };
}

function derivation(ianaName) {
  return `no RFC prints it: ${ianaName.toUpperCase()} over the hand-built RFC 7638 §3.3 hash input with ${ORACLE}`;
}

// SHA-384 and SHA-512 over every key (RFC 7638 §3.4: the hash is the
// application's choice; RFC 9278 §4: the URI names it).
for (const ianaName of ["sha-384", "sha-512"]) {
  const prefix = ianaName.replace("-", "");
  for (const key of KEYS) {
    add(`${prefix}-${key.slug}.json`, {
      source: `RFC 7638 §3.4 over ${key.origin}`,
      description:
        `${ianaName.toUpperCase()} JWK Thumbprint of ${key.what}; ${derivation(ianaName)}; ` +
        `the URI carries the IANA name ${ianaName} (RFC 9278 §3, §4)`,
      operation: "jwk.thumbprint",
      input: { jwk: key.jwk, hash: ianaName },
      expect: ok(key.jwk, ianaName),
    });
  }
}

// No hash: the core default, SHA-256 (RFC 9278 §5, ADR 0054 §8).
add("hash-default-rfc7638-3-1-rsa.json", {
  source: "RFC 7638 §3.1, RFC 9278 §6",
  description:
    'Without "hash" the thumbprint uses the core default, SHA-256, the mandatory-to-implement hash (RFC 9278 §5, ADR 0054 §8): the RFC 7638 §3.1 value and the RFC 9278 §6 URI',
  operation: "jwk.thumbprint",
  input: { jwk: RSA_KEY },
  expect: ok(RSA_KEY, "sha-256"),
});

// The other accepted spellings (ADR 0054 §8.2): each gives its IANA-name
// vector, and the URI always carries the IANA name (RFC 9278 §4).
const ALIASES = [
  { name: "SHA-256", file: "upper-sha-256", iana: "sha-256", from: "ADR 0030 §4" },
  { name: "SHA-384", file: "upper-sha-384", iana: "sha-384", from: "ADR 0030 §4" },
  { name: "SHA-512", file: "upper-sha-512", iana: "sha-512", from: "ADR 0030 §4" },
  { name: "sha256", file: "sha256", iana: "sha-256", from: "panva/jose" },
  { name: "sha384", file: "sha384", iana: "sha-384", from: "panva/jose" },
  { name: "sha512", file: "sha512", iana: "sha-512", from: "panva/jose" },
];
for (const alias of ALIASES) {
  const twin =
    alias.iana === "sha-256" ? "rfc7638-3-1-rsa.json" : `${alias.iana.replace("-", "")}-rfc7638-3-1-rsa.json`;
  const how =
    alias.iana === "sha-256"
      ? "the value RFC 7638 §3.1 prints and the RFC 9278 §6 URI"
      : derivation(alias.iana);
  add(`hash-alias-${alias.file}-rfc7638-3-1-rsa.json`, {
    source: alias.iana === "sha-256" ? "RFC 7638 §3.1, RFC 9278 §6" : "RFC 7638 §3.4 over the RFC 7638 §3.1 key",
    description:
      `The ${alias.from} spelling "${alias.name}" (ADR 0054 §8.2) gives the same result as ${twin}, ` +
      `with the IANA name ${alias.iana} in the URI whatever the spelling (RFC 9278 §4); ${how}`,
    operation: "jwk.thumbprint",
    input: { jwk: RSA_KEY, hash: alias.name },
    expect: ok(RSA_KEY, alias.iana),
  });
}

// Every other name is refused (ADR 0054 §8.2), whatever the key.
const REJECTS = [
  { name: "SHA-1", file: "upper-sha-1", why: "SHA-1 is never used (ADR 0022)" },
  { name: "sha-1", file: "sha-1", why: "SHA-1 is never used (ADR 0022), even under its IANA Hash Name String" },
  {
    name: "sha-256-128",
    file: "sha-256-128",
    why: "a registered truncated SHA-256 is not one of the nine accepted names",
  },
  { name: "sha3-256", file: "sha3-256", why: "a SHA-3 hash is not one of the nine accepted names" },
  {
    name: "Sha-256",
    file: "mixed-case-sha-256",
    why: "names match exactly and case-sensitively, so a case variant of an accepted name is refused",
  },
  { name: "", file: "empty", why: "an empty name is not the default (only an absent hash is)" },
];
for (const reject of REJECTS) {
  add(`hash-reject-${reject.file}.json`, {
    source: "polyjose",
    description:
      `The hash name ${JSON.stringify(reject.name)} is refused with UnsupportedAlgorithm (ADR 0054 §8.2, RFC 9278 §4): ` +
      `${reject.why}; the key is the valid RFC 7638 §3.1 key`,
    operation: "jwk.thumbprint",
    input: { jwk: RSA_KEY, hash: reject.name },
    expect: { ok: false, error: "UnsupportedAlgorithm" },
  });
}

check(files.size === 25, `expected 25 files, built ${files.size}`);

mkdirSync(outDir, { recursive: true });
for (const [name, text] of files) {
  writeFileSync(join(outDir, name), text);
}
console.log(`wrote ${files.size} files to ${outDir}`);
