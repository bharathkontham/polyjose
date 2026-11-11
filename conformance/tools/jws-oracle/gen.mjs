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
  constants,
  createECDH,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
// RS384, RS512 (RFC 7518 §3.3) and PS512 (§3.5): no RFC prints a JWS for
// them. The keys are read from committed RFC vectors, never generated: the
// RFC 7515 A.2 key pair signs and verifies, the RFC 7520 §3.4 RSA public key
// is the wrong key, and the RFC 7515 A.3 P-256 public key is the key of
// another family. RSASSA-PKCS1-v1_5 is deterministic (RFC 8017 §8.2.1), so
// the RS* entries are reproduced byte for byte; RSASSA-PSS is salted, so the
// two PS512 token entries change on every run.
// ---------------------------------------------------------------------------

const vectorsRoot = join(here, "..", "..", "vectors");
const committed = (rel) => JSON.parse(readFileSync(join(vectorsRoot, rel), "utf8"));

const A2_SIGN = committed("jws-rfc7515/a2-rs256-compact-sign.json");
const RSA_PRIVATE = A2_SIGN.input.signers[0].key;
const RSA_PUBLIC = { kty: "RSA", n: RSA_PRIVATE.n, e: RSA_PRIVATE.e };
const RSA_OTHER_PUBLIC = committed("third_party/rfc7520/jws/4-1-rs256-compact-verify.json").input.key;
const P256_PUBLIC = committed("jws-rfc7515/a3-es256-compact-verify.json").input.key;
check(RSA_OTHER_PUBLIC.kty === "RSA" && RSA_OTHER_PUBLIC.n !== RSA_PUBLIC.n, "the RFC 7520 key is not another RSA key");
check(P256_PUBLIC.kty === "EC" && P256_PUBLIC.crv === "P-256" && !("d" in P256_PUBLIC), "not a P-256 public key");

const rsaKey = createPrivateKey({ key: RSA_PRIVATE, format: "jwk" });
const rsaPub = createPublicKey({ key: RSA_PUBLIC, format: "jwk" });
const rsaOtherPub = createPublicKey({ key: { kty: "RSA", n: RSA_OTHER_PUBLIC.n, e: RSA_OTHER_PUBLIC.e }, format: "jwk" });

// The oracle must first reproduce RFC 7515 A.2 exactly.
{
  const signer = A2_SIGN.input.signers[0];
  const sig = sign("sha256", signingInput(signer.protected_b64u, A2_SIGN.input.payload_b64u), rsaKey);
  check(
    `${signer.protected_b64u}.${A2_SIGN.input.payload_b64u}.${b64u(sig)}` === A2_SIGN.expect.jws,
    "node:crypto does not reproduce the RFC 7515 A.2 JWS",
  );
}

/** The same octets with the lowest bit of the last one flipped: still canonical base64url of the same length. */
function tampered(sig) {
  const out = Buffer.from(sig);
  out[out.length - 1] ^= 1;
  return out;
}

/** The RS<bits> entries: an exact signature, and what must refuse it or a relative of it. */
function rsEntries(bits, otherBits) {
  const alg = `RS${bits}`;
  const other = `RS${otherBits}`;
  const hash = `sha${bits}`;
  const protectedB64u = b64u(utf8(`{"alg":"${alg}"}`));
  const payload = b64u(utf8(`Example of ${alg} signing`));
  const input = signingInput(protectedB64u, payload);
  const sig = sign(hash, input, rsaKey);
  check(sig.length === 256, "an RSA-2048 signature is 256 octets (RFC 8017 §8.2.1)");
  check(verify(hash, input, rsaPub, sig), `the ${alg} JWS does not verify`);
  check(!verify(hash, input, rsaPub, tampered(sig)), `the tampered ${alg} signature verifies`);
  check(!verify(hash, input, rsaOtherPub, sig), `the ${alg} JWS verifies with another key`);
  const jws = `${protectedB64u}.${payload}.${b64u(sig)}`;
  // A valid SHA-<bits> signature over a signing input whose header names the other RS* alg.
  const otherProtected = b64u(utf8(`{"alg":"${other}"}`));
  const otherInput = signingInput(otherProtected, payload);
  const crossSig = sign(hash, otherInput, rsaKey);
  check(verify(hash, otherInput, rsaPub, crossSig), "the cross-hash signature is not a valid one under its own hash");
  check(!verify(`sha${otherBits}`, otherInput, rsaPub, crossSig), "the cross-hash signature verifies under the header's hash");
  const name = alg.toLowerCase();
  const key = "the RFC 7515 A.2 RSA";
  return {
    [`${name}-compact-sign.json`]: vector(
      `${alg} (RFC 7518 §3.3) compact sign with ${key} private key over header {"alg":"${alg}"}; RSASSA-PKCS1-v1_5 is deterministic (RFC 8017 §8.2.1), so the expected JWS is node:crypto's exact output (the generator first checks that node:crypto reproduces RFC 7515 A.2)`,
      "jws.sign",
      { serialization: "compact", payload_b64u: payload, detached: false, signers: [{ protected_b64u: protectedB64u, key: RSA_PRIVATE }] },
      { ok: true, jws },
    ),
    [`${name}-compact-verify.json`]: vector(
      `${alg} (RFC 7518 §3.3) compact verify of the node:crypto JWS with ${key} public key and allow-list ["${alg}"]`,
      "jws.verify",
      { jws, key: RSA_PUBLIC, allowed_algs: [alg] },
      verified(payload, alg),
    ),
    [`${name}-compact-verify-tampered-signature.json`]: vector(
      `The node:crypto ${alg} JWS with the lowest bit of its last signature octet flipped (still 256 canonical octets) fails RSASSA-PKCS1-v1_5 verification (RFC 7515 §5.2 step 8; RFC 8017 §8.2.2); node:crypto refuses it too`,
      "jws.verify",
      { jws: `${protectedB64u}.${payload}.${b64u(tampered(sig))}`, key: RSA_PUBLIC, allowed_algs: [alg] },
      { ok: false, error: "InvalidSignature" },
    ),
    [`${name}-compact-verify-wrong-key.json`]: vector(
      `The node:crypto ${alg} JWS, signed with the RFC 7515 A.2 key, verified with another RSA public key (RFC 7520 §3.4): the signature does not verify (RFC 7515 §5.2 step 8); node:crypto refuses it too`,
      "jws.verify",
      { jws, key: RSA_OTHER_PUBLIC, allowed_algs: [alg] },
      { ok: false, error: "InvalidSignature" },
    ),
    [`${name}-compact-verify-alg-not-allowed.json`]: vector(
      `The node:crypto ${alg} JWS, verified with its own public key but an allow-list of only ${other}, is refused: the header alg alone is never trusted (RFC 8725 §3.1; ADR 0026 §2 step 7)`,
      "jws.verify",
      { jws, key: RSA_PUBLIC, allowed_algs: [other] },
      { ok: false, error: "AlgorithmNotAllowed" },
    ),
    [`${name}-compact-verify-ec-key.json`]: vector(
      `The node:crypto ${alg} JWS verified with the RFC 7515 A.3 P-256 public key: ${alg} is bound to RSA keys (RFC 7518 §3.3; RFC 8725 §3.1; ADR 0026 §2 step 8)`,
      "jws.verify",
      { jws, key: P256_PUBLIC, allowed_algs: [alg] },
      { ok: false, error: "KeyAlgorithmMismatch" },
    ),
    [`${other.toLowerCase()}-compact-verify-sha${bits}-signature.json`]: vector(
      `A compact JWS whose header says ${other} but whose signature is RSASSA-PKCS1-v1_5 with SHA-${bits} over that signing input, by ${key} private key: the header alg fixes the hash (RFC 7518 §3.3), so it does not verify as ${other} (RFC 7515 §5.2 step 8); node:crypto verifies it with SHA-${bits} and refuses it with SHA-${otherBits}`,
      "jws.verify",
      { jws: `${otherProtected}.${payload}.${b64u(crossSig)}`, key: RSA_PUBLIC, allowed_algs: [other] },
      { ok: false, error: "InvalidSignature" },
    ),
  };
}

// PS512: RSASSA-PSS with SHA-512, MGF1 with SHA-512 and a 64-octet salt (RFC 7518 §3.5).
const PS512_PROTECTED = b64u(utf8('{"alg":"PS512"}'));
const PS512_PAYLOAD = b64u(utf8("Example of PS512 signing"));
const pss = { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 };
const ps512Input = signingInput(PS512_PROTECTED, PS512_PAYLOAD);
const ps512Sig = sign("sha512", ps512Input, { key: rsaKey, ...pss });
check(ps512Sig.length === 256, "an RSA-2048 signature is 256 octets (RFC 8017 §8.1.1)");
check(verify("sha512", ps512Input, { key: rsaPub, ...pss }, ps512Sig), "the PS512 JWS does not verify");
check(!verify("sha512", ps512Input, { key: rsaPub, ...pss }, tampered(ps512Sig)), "the tampered PS512 signature verifies");

// ---------------------------------------------------------------------------
// HS512 (RFC 7518 §3.2): HMAC is deterministic, so every entry is reproduced
// byte for byte. The key is fixed: SHA-512 of a label, 64 octets, the hash
// output size §3.2 requires as a minimum. It is a test key, used nowhere else.
// ---------------------------------------------------------------------------

// The oracle must first reproduce RFC 7515 A.1 exactly.
{
  const a1 = committed("jws-rfc7515/a1-hs256-compact-sign.json");
  const signer = a1.input.signers[0];
  const mac = createHmac("sha256", Buffer.from(signer.key.k, "base64url"))
    .update(signingInput(signer.protected_b64u, a1.input.payload_b64u))
    .digest();
  check(
    `${signer.protected_b64u}.${a1.input.payload_b64u}.${b64u(mac)}` === a1.expect.jws,
    "node:crypto does not reproduce the RFC 7515 A.1 JWS",
  );
}

const hs512K = createHash("sha512").update("polyjose jws-oracle HS512 key v1").digest();
const HS512_KEY = { kty: "oct", k: b64u(hs512K) };
const HS512_PROTECTED = b64u(utf8('{"alg":"HS512"}'));
const HS512_PAYLOAD = b64u(utf8("Example of HS512 signing"));
const hs512Mac = createHmac("sha512", hs512K).update(signingInput(HS512_PROTECTED, HS512_PAYLOAD)).digest();
check(hs512Mac.length === 64, "an HS512 MAC is 64 octets (RFC 7518 §3.2)");
const HS512_JWS = `${HS512_PROTECTED}.${HS512_PAYLOAD}.${b64u(hs512Mac)}`;

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
  ...rsEntries(384, 512),
  ...rsEntries(512, 384),
  "ps512-compact-sign-roundtrip.json": vector(
    "PS512 (RFC 7518 §3.5) compact sign with the RFC 7515 A.2 RSA private key, then verify with its public key: RSASSA-PSS is salted, so the output is checked by round trip, not bytes",
    "jws.sign",
    {
      serialization: "compact",
      payload_b64u: PS512_PAYLOAD,
      detached: false,
      signers: [{ protected_b64u: PS512_PROTECTED, key: RSA_PRIVATE }],
    },
    { ok: true, verify_with: { key: RSA_PUBLIC, allowed_algs: ["PS512"] } },
  ),
  "ps512-compact-verify.json": vector(
    "PS512 (RFC 7518 §3.5) compact verify of a node:crypto RSASSA-PSS signature (SHA-512, MGF1 with SHA-512, 64-octet salt) by the RFC 7515 A.2 RSA key, with its public key",
    "jws.verify",
    { jws: `${PS512_PROTECTED}.${PS512_PAYLOAD}.${b64u(ps512Sig)}`, key: RSA_PUBLIC, allowed_algs: ["PS512"] },
    verified(PS512_PAYLOAD, "PS512"),
  ),
  "ps512-compact-verify-tampered-signature.json": vector(
    "The PS512 JWS of ps512-compact-verify.json with the lowest bit of its last signature octet flipped (still 256 canonical octets) fails RSASSA-PSS verification (RFC 7515 §5.2 step 8; RFC 8017 §8.1.2); node:crypto refuses it too",
    "jws.verify",
    { jws: `${PS512_PROTECTED}.${PS512_PAYLOAD}.${b64u(tampered(ps512Sig))}`, key: RSA_PUBLIC, allowed_algs: ["PS512"] },
    { ok: false, error: "InvalidSignature" },
  ),
  "hs512-compact-sign.json": vector(
    'HS512 (RFC 7518 §3.2) compact sign with the generator\'s fixed 64-octet key (SHA-512 of a label) over header {"alg":"HS512"}; HMAC is deterministic, so the expected JWS is node:crypto\'s exact output (the generator first checks that node:crypto reproduces RFC 7515 A.1)',
    "jws.sign",
    {
      serialization: "compact",
      payload_b64u: HS512_PAYLOAD,
      detached: false,
      signers: [{ protected_b64u: HS512_PROTECTED, key: HS512_KEY }],
    },
    { ok: true, jws: HS512_JWS },
  ),
  "hs512-compact-verify.json": vector(
    'HS512 (RFC 7518 §3.2) compact verify of the node:crypto JWS with the generator\'s fixed 64-octet key and allow-list ["HS512"]',
    "jws.verify",
    { jws: HS512_JWS, key: HS512_KEY, allowed_algs: ["HS512"] },
    verified(HS512_PAYLOAD, "HS512"),
  ),
  "hs512-compact-verify-tampered-signature.json": vector(
    "The node:crypto HS512 JWS with the lowest bit of its last MAC octet flipped (still 64 canonical octets) fails the MAC check (RFC 7515 §5.2 step 8)",
    "jws.verify",
    { jws: `${HS512_PROTECTED}.${HS512_PAYLOAD}.${b64u(tampered(hs512Mac))}`, key: HS512_KEY, allowed_algs: ["HS512"] },
    { ok: false, error: "InvalidSignature" },
  ),
};

mkdirSync(outDir, { recursive: true });
for (const [name, value] of Object.entries(vectors)) {
  writeFileSync(join(outDir, name), `${JSON.stringify(value, null, 2)}\n`);
  console.log(`wrote ${join(outDir, name)}`);
}
