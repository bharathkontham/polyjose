// Generates the conformance vectors under conformance/vectors/jws-oracle/
// with node:crypto (OpenSSL-backed), an implementation independent of
// polyjose. A generator only: CI never runs it, and its output is committed.
//
//   node conformance/tools/jws-oracle/gen.mjs [output-dir]
//
// Requires Node >= 24 and nothing else (no npm dependencies). The output
// directory defaults to ../../vectors/jws-oracle relative to this file.
// See README.md next to this file for what it generates and why.

import {
  createECDH,
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const major = Number(process.versions.node.split(".")[0]);
if (major < 24) {
  throw new Error(`Node >= 24 is required, this is ${process.version}`);
}

const here = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(process.argv[2] ?? join(here, "..", "..", "vectors", "jws-oracle"));

const SOURCE =
  `node:crypto (Node ${process.version}, OpenSSL ${process.versions.openssl}), ` +
  "conformance/tools/jws-oracle/gen.mjs";

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const utf8 = (text) => Buffer.from(text, "utf8");

/** RFC 7515 §5.1: ASCII(BASE64URL(UTF8(protected)) || '.' || BASE64URL(payload)). */
function signingInput(protectedB64u, payloadB64u) {
  return Buffer.from(`${protectedB64u}.${payloadB64u}`, "ascii");
}

function check(condition, message) {
  if (!condition) {
    throw new Error(`self-check failed: ${message}`);
  }
}

// ---------------------------------------------------------------------------
// Ed25519: the RFC 8037 A.1 key. EdDSA signing is deterministic (RFC 8032
// §5.1.6), so these entries are reproduced byte for byte on every run.
// ---------------------------------------------------------------------------

const ED25519_PRIVATE = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
};
const ED25519_PUBLIC = { kty: "OKP", crv: "Ed25519", x: ED25519_PRIVATE.x };
const ED25519_PAYLOAD = b64u(utf8("Example of Ed25519 signing"));

const edKey = createPrivateKey({ key: ED25519_PRIVATE, format: "jwk" });
check(
  createPublicKey(edKey).export({ format: "jwk" }).x === ED25519_PUBLIC.x,
  "the RFC 8037 A.1 d does not derive its x",
);

// The oracle must first reproduce RFC 8037 A.4 exactly.
{
  const protectedB64u = b64u(utf8('{"alg":"EdDSA"}'));
  const sig = sign(null, signingInput(protectedB64u, ED25519_PAYLOAD), edKey);
  check(
    `${protectedB64u}.${ED25519_PAYLOAD}.${b64u(sig)}` ===
      "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc." +
        "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
    "node:crypto does not reproduce the RFC 8037 A.4 JWS",
  );
}

// The same key and payload under the fully-specified alg "Ed25519" (RFC 9864 §2.2).
const ED25519_PROTECTED = b64u(utf8('{"alg":"Ed25519"}'));
const ED25519_JWS = (() => {
  const input = signingInput(ED25519_PROTECTED, ED25519_PAYLOAD);
  const sig = sign(null, input, edKey);
  check(sig.length === 64, "an Ed25519 signature is 64 octets (RFC 8032 §5.1.6)");
  check(verify(null, input, createPublicKey(edKey), sig), "the Ed25519 JWS does not verify");
  return `${ED25519_PROTECTED}.${ED25519_PAYLOAD}.${b64u(sig)}`;
})();

// ---------------------------------------------------------------------------
// ES256K (RFC 8812 §3.2): ECDSA over secp256k1 with SHA-256, R || S as 64
// octets. The key is fixed (d = SHA-256 of a label, so every run uses the
// same key), but OpenSSL's ECDSA is randomized, so the two token entries
// change on every run; only the round-trip entry is reproduced exactly.
// ---------------------------------------------------------------------------

// The order of the secp256k1 base point (SEC 2 v2 §2.4.1).
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const toBig = (bytes) => BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);
const toBytes32 = (n) => Buffer.from(n.toString(16).padStart(64, "0"), "hex");

const es256kD = createHash("sha256").update("polyjose jws-oracle ES256K key v1").digest();
check(toBig(es256kD) > 0n && toBig(es256kD) < N, "the ES256K d is not in [1, n-1]");
const es256kPoint = (() => {
  const ecdh = createECDH("secp256k1");
  ecdh.setPrivateKey(es256kD);
  return ecdh.getPublicKey(null, "uncompressed"); // 0x04 || X || Y
})();
check(es256kPoint.length === 65 && es256kPoint[0] === 4, "not an uncompressed point");

const ES256K_PUBLIC = {
  kty: "EC",
  crv: "secp256k1",
  x: b64u(es256kPoint.subarray(1, 33)),
  y: b64u(es256kPoint.subarray(33, 65)),
};
const ES256K_PRIVATE = { ...ES256K_PUBLIC, d: b64u(es256kD) };

const kKey = createPrivateKey({ key: ES256K_PRIVATE, format: "jwk" });
const kPub = createPublicKey({ key: ES256K_PUBLIC, format: "jwk" });
{
  const derived = createPublicKey(kKey).export({ format: "jwk" });
  check(
    derived.x === ES256K_PUBLIC.x && derived.y === ES256K_PUBLIC.y,
    "the ES256K d does not derive its (x, y)",
  );
}

const ES256K_PROTECTED = b64u(utf8('{"alg":"ES256K"}'));
const ES256K_PAYLOAD = b64u(utf8("Example of ES256K signing"));
const es256kInput = signingInput(ES256K_PROTECTED, ES256K_PAYLOAD);
const p1363 = { dsaEncoding: "ieee-p1363" };

// OpenSSL emits either S form. Sign until the oracle itself gives a low-S
// signature (S <= n/2), so the low-S entry is the oracle's own output.
const [lowR, lowS] = (() => {
  for (let attempt = 0; attempt < 64; attempt += 1) {
    const sig = sign("sha256", es256kInput, { key: kKey, ...p1363 });
    check(sig.length === 64, "an ES256K signature is 64 octets (RFC 8812 §3.2)");
    const s = toBig(sig.subarray(32));
    if (s <= N >> 1n) {
      return [sig.subarray(0, 32), s];
    }
  }
  throw new Error("no low-S signature in 64 attempts");
})();

// The high-S twin: the same R with S replaced by n - S. This is only how
// the vector is built (BigInt subtraction), not a cryptographic primitive.
const highS = N - lowS;
check(highS > N >> 1n && highS < N, "n - S is not the high form");
const lowSig = Buffer.concat([lowR, toBytes32(lowS)]);
const highSig = Buffer.concat([lowR, toBytes32(highS)]);
check(verify("sha256", es256kInput, { key: kPub, ...p1363 }, lowSig), "low-S does not verify");
// OpenSSL accepts both S forms, as ADR 0026 §5 requires of polyjose.
check(verify("sha256", es256kInput, { key: kPub, ...p1363 }, highSig), "high-S does not verify");

const ES256K_LOW_JWS = `${ES256K_PROTECTED}.${ES256K_PAYLOAD}.${b64u(lowSig)}`;
const ES256K_HIGH_JWS = `${ES256K_PROTECTED}.${ES256K_PAYLOAD}.${b64u(highSig)}`;

// ---------------------------------------------------------------------------
// The vectors, one per file (conformance/README.md).
// ---------------------------------------------------------------------------

function vector(description, operation, input, expect) {
  return { source: SOURCE, description, operation, input, expect };
}

function verified(payloadB64u, alg) {
  return { ok: true, payload_b64u: payloadB64u, alg, signature_index: 0 };
}

const vectors = {
  "ed25519-compact-sign.json": vector(
    'Ed25519 (RFC 9864 §2.2) compact sign with the RFC 8037 A.1 private key over header {"alg":"Ed25519"} and the RFC 8037 A.4 payload; EdDSA is deterministic, so the expected JWS is node:crypto\'s exact output (the generator first checks that node:crypto reproduces RFC 8037 A.4)',
    "jws.sign",
    {
      serialization: "compact",
      payload_b64u: ED25519_PAYLOAD,
      detached: false,
      signers: [{ protected_b64u: ED25519_PROTECTED, key: ED25519_PRIVATE }],
    },
    { ok: true, jws: ED25519_JWS },
  ),
  "ed25519-compact-verify.json": vector(
    'Ed25519 (RFC 9864 §2.2) compact verify of the node:crypto JWS over header {"alg":"Ed25519"} with the RFC 8037 A.2 public key and allow-list ["Ed25519"]',
    "jws.verify",
    { jws: ED25519_JWS, key: ED25519_PUBLIC, allowed_algs: ["Ed25519"] },
    verified(ED25519_PAYLOAD, "Ed25519"),
  ),
  "es256k-compact-sign-roundtrip.json": vector(
    "ES256K (RFC 8812 §3.2) compact sign with the generator's fixed secp256k1 key (d = SHA-256 of a label, x and y derived by node:crypto), then verify with its public key: ECDSA is randomized, so the output is checked by round trip, not bytes",
    "jws.sign",
    {
      serialization: "compact",
      payload_b64u: ES256K_PAYLOAD,
      detached: false,
      signers: [{ protected_b64u: ES256K_PROTECTED, key: ES256K_PRIVATE }],
    },
    { ok: true, verify_with: { key: ES256K_PUBLIC, allowed_algs: ["ES256K"] } },
  ),
  "es256k-compact-verify-low-s.json": vector(
    "ES256K (RFC 8812 §3.2) compact verify of a node:crypto signature whose S is in the low form (S <= n/2), with the generator's fixed secp256k1 public key",
    "jws.verify",
    { jws: ES256K_LOW_JWS, key: ES256K_PUBLIC, allowed_algs: ["ES256K"] },
    verified(ES256K_PAYLOAD, "ES256K"),
  ),
  "es256k-compact-verify-high-s.json": vector(
    "ES256K compact verify of the high-S twin of es256k-compact-verify-low-s.json (same R, S replaced by n - S, which node:crypto also verifies): polyjose normalizes S before verifying, so it is valid (ADR 0026 §5; RFC 8812 §3.2 is silent on the S form)",
    "jws.verify",
    { jws: ES256K_HIGH_JWS, key: ES256K_PUBLIC, allowed_algs: ["ES256K"] },
    verified(ES256K_PAYLOAD, "ES256K"),
  ),
};

mkdirSync(outDir, { recursive: true });
for (const [name, value] of Object.entries(vectors)) {
  writeFileSync(join(outDir, name), `${JSON.stringify(value, null, 2)}\n`);
  console.log(`wrote ${join(outDir, name)}`);
}
