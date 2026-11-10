#!/usr/bin/env node
// Independent oracle for the RSA-OAEP-256 conformance vectors (feature 0003 T11).
//
// The exact encrypt vectors must not depend on polyjose's own decryption (ADR 0067 added it), so
// this script checks every committed
// `conformance/vectors/jwe/rsa-oaep-256/*.json` vector of operation `jwe.encrypt` that expects an
// exact compact JWE, with Node's built-in crypto only (no npm packages), against the vector's
// test-only private key (`keys/rsa-<bits>.private.jwk`, data only, matched by the modulus `n`):
//
//  1. `rng_b64u` splits exactly into the documented draw order (crates/polyjose/src/jwe/random.rs):
//     the CEK (RFC 7516 §5.1 step 2), the 32-octet OAEP seed (RFC 8017 §7.1.1 step 2.d), then
//     the content IV (§5.1 step 9). No octet is left over.
//  2. The JWE Encrypted Key decrypts with `crypto.privateDecrypt` (OAEP, `oaepHash: 'sha256'`,
//     MGF1-SHA-256, empty label: RFC 7518 §4.3) to that CEK, and is k octets (RFC 8017 §7.1.1).
//  3. Raw RSADP (`RSA_NO_PADDING`) gives the encoded message EM. Unmasking it (RFC 8017 §7.1.2
//     step 3) yields exactly the injected seed, lHash = SHA-256(""), a zero PS, 0x01 and the CEK.
//  4. The oracle encodes EME-OAEP itself from the seed and CEK (RFC 8017 §7.1.1 step 2) and
//     applies raw RSAEP with the public key: the result equals the committed encrypted key, so
//     the expected value never depended on polyjose.
//  5. The IV segment is the injected IV; the content decrypts with Node's AES-GCM or
//     AES-CBC + HMAC-SHA-2 (RFC 7518 §5.2, §5.3) over AAD = ASCII(encoded protected header)
//     (RFC 7516 §5.1 step 14) to `plaintext_b64u`, and encrypting again gives the same
//     ciphertext and tag. The protected header is {"alg":"RSA-OAEP-256","enc":<enc>}.
//
// Usage: node conformance/tools/rsa-oaep-oracle.mjs [vector-dir]
// Exits 0 when at least MIN_VECTORS vectors were checked and all PASS, 1 otherwise.

import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DIR = path.join(HERE, '..', 'vectors', 'jwe', 'rsa-oaep-256');
/** The task's floor: 2048, 3072 and 4096 bits × A128GCM and A256CBC-HS512. */
const MIN_VECTORS = 6;
const H_LEN = 32; // SHA-256

/** RFC 7518 §5.1: CEK and IV lengths per `enc`. */
export const ENC = {
  A128GCM: { cek: 16, iv: 12, gcm: 'aes-128-gcm' },
  A192GCM: { cek: 24, iv: 12, gcm: 'aes-192-gcm' },
  A256GCM: { cek: 32, iv: 12, gcm: 'aes-256-gcm' },
  'A128CBC-HS256': { cek: 32, iv: 16, cbc: 'aes-128-cbc', hash: 'sha256' },
  'A192CBC-HS384': { cek: 48, iv: 16, cbc: 'aes-192-cbc', hash: 'sha384' },
  'A256CBC-HS512': { cek: 64, iv: 16, cbc: 'aes-256-cbc', hash: 'sha512' },
};

/** Strict base64url (RFC 7515 §2): no padding, URL alphabet, canonical. */
export function b64u(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error(`not base64url: ${JSON.stringify(text)}`);
  }
  const bytes = Buffer.from(text, 'base64url');
  if (bytes.toString('base64url') !== text) throw new Error(`non-canonical base64url: ${text}`);
  return bytes;
}

const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

/** MGF1 with SHA-256 (RFC 8017 Appendix B.2.1). */
export function mgf1(seed, len) {
  const out = [];
  for (let counter = 0; out.length * H_LEN < len; counter++) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter);
    out.push(sha256(Buffer.concat([seed, c])));
  }
  return Buffer.concat(out).subarray(0, len);
}

const xor = (a, b) => Buffer.from(a.map((byte, i) => byte ^ b[i]));

/** EME-OAEP encoding with SHA-256, MGF1-SHA-256 and the empty label (RFC 8017 §7.1.1 step 2). */
export function oaepEncode(message, seed, k) {
  if (seed.length !== H_LEN) throw new Error('the OAEP seed must be hLen octets');
  if (message.length > k - 2 * H_LEN - 2) throw new Error('message too long');
  const lHash = sha256(Buffer.alloc(0));
  const ps = Buffer.alloc(k - message.length - 2 * H_LEN - 2);
  const db = Buffer.concat([lHash, ps, Buffer.from([1]), message]);
  const maskedDb = xor(db, mgf1(seed, k - H_LEN - 1));
  const maskedSeed = xor(seed, mgf1(maskedDb, H_LEN));
  return Buffer.concat([Buffer.from([0]), maskedSeed, maskedDb]);
}

/** EME-OAEP decoding (RFC 8017 §7.1.2 step 3), returning the seed and the message. */
export function oaepDecode(em, k) {
  if (em.length !== k || em[0] !== 0) throw new Error('EM must be k octets with a leading 0x00');
  const maskedSeed = em.subarray(1, 1 + H_LEN);
  const maskedDb = em.subarray(1 + H_LEN);
  const seed = xor(maskedSeed, mgf1(maskedDb, H_LEN));
  const db = xor(maskedDb, mgf1(seed, k - H_LEN - 1));
  if (!db.subarray(0, H_LEN).equals(sha256(Buffer.alloc(0)))) throw new Error("lHash is not SHA-256('')");
  let i = H_LEN;
  while (i < db.length && db[i] === 0) i++;
  if (db[i] !== 1) throw new Error('no 0x01 after PS');
  return { seed, message: db.subarray(i + 1) };
}

/** Raw RSAEP / RSADP (RFC 8017 §5.1.1, §5.1.2), padding left to the caller. */
export const rsaep = (publicKey, em) =>
  crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_NO_PADDING }, em);
const rsadp = (privateKey, c) =>
  crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_NO_PADDING }, c);

/** Content encryption (RFC 7518 §5.2.2.1, §5.3): `{ ciphertext, tag }`. */
export function contentEncrypt(enc, cek, iv, aad, plaintext) {
  const spec = ENC[enc];
  if (spec.gcm) {
    const cipher = crypto.createCipheriv(spec.gcm, cek, iv, { authTagLength: 16 });
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { ciphertext, tag: cipher.getAuthTag() };
  }
  const half = cek.length / 2;
  const [macKey, encKey] = [cek.subarray(0, half), cek.subarray(half)];
  const cipher = crypto.createCipheriv(spec.cbc, encKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const al = Buffer.alloc(8);
  al.writeBigUInt64BE(BigInt(aad.length) * 8n);
  const mac = crypto.createHmac(spec.hash, macKey).update(Buffer.concat([aad, iv, ciphertext, al])).digest();
  return { ciphertext, tag: mac.subarray(0, half) };
}

/** Content decryption (RFC 7518 §5.2.2.2, §5.3), checking the tag first for CBC-HMAC. */
function contentDecrypt(enc, cek, iv, aad, ciphertext, tag) {
  const spec = ENC[enc];
  if (spec.gcm) {
    const decipher = crypto.createDecipheriv(spec.gcm, cek, iv, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }
  const half = cek.length / 2;
  const [macKey, encKey] = [cek.subarray(0, half), cek.subarray(half)];
  const al = Buffer.alloc(8);
  al.writeBigUInt64BE(BigInt(aad.length) * 8n);
  const mac = crypto.createHmac(spec.hash, macKey).update(Buffer.concat([aad, iv, ciphertext, al])).digest();
  if (tag.length !== half || !crypto.timingSafeEqual(mac.subarray(0, half), tag)) throw new Error('tag mismatch');
  const decipher = crypto.createDecipheriv(spec.cbc, encKey, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** The test-only private keys in `<dir>/keys/*.private.jwk`, by their modulus `n`. */
export function loadKeys(dir) {
  const keys = new Map();
  const keyDir = path.join(dir, 'keys');
  for (const name of fs.readdirSync(keyDir).sort()) {
    if (!name.endsWith('.private.jwk')) continue;
    const jwk = JSON.parse(fs.readFileSync(path.join(keyDir, name), 'utf8'));
    const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
    const publicKey = crypto.createPublicKey(privateKey);
    keys.set(jwk.n, { name, privateKey, publicKey, k: b64u(jwk.n).length, e: jwk.e });
  }
  return keys;
}

const assert = (cond, what) => {
  if (!cond) throw new Error(what);
};

/** Checks one vector (steps 1–5 above); throws on the first failure. */
export function checkVector(vector, keys) {
  const { input, expect } = vector;
  assert(vector.operation === 'jwe.encrypt', 'operation is jwe.encrypt');
  assert((vector.features ?? []).includes('fixed-rng'), 'features lists fixed-rng');
  assert(/interop: true/.test(vector.description), 'description marks it interop: true');
  assert(input.serialization === 'compact', 'serialization is compact');
  assert(input.recipients.length === 1, 'one recipient');
  const [recipient] = input.recipients;
  assert(recipient.alg === 'RSA-OAEP-256', 'alg is RSA-OAEP-256');
  const pub = recipient.key;
  assert(pub.kty === 'RSA' && pub.d === undefined, 'the recipient key is an RSA public JWK');
  const key = keys.get(pub.n);
  assert(key !== undefined, 'a test private key matches the recipient n');
  assert(key.e === pub.e, 'the recipient e matches the test key');
  const spec = ENC[input.enc];
  assert(spec !== undefined, `known enc ${input.enc}`);

  // 1. The draw order: CEK, OAEP seed, IV, and nothing left over.
  const rng = b64u(input.rng_b64u);
  assert(rng.length === spec.cek + H_LEN + spec.iv, 'rng_b64u is exactly CEK + seed + IV');
  const cek = rng.subarray(0, spec.cek);
  const seed = rng.subarray(spec.cek, spec.cek + H_LEN);
  const iv = rng.subarray(spec.cek + H_LEN);

  assert(expect.ok === true && typeof expect.jwe === 'string', 'expects an exact compact JWE');
  const parts = expect.jwe.split('.');
  assert(parts.length === 5, 'five compact segments');
  const [protectedB64, ekB64, ivB64, ctB64, tagB64] = parts;
  const header = JSON.parse(b64u(protectedB64).toString('utf8'));
  assert(
    JSON.stringify(header) === JSON.stringify({ alg: 'RSA-OAEP-256', enc: input.enc }),
    'protected header is {"alg":"RSA-OAEP-256","enc":<enc>}',
  );
  const encryptedKey = b64u(ekB64);

  // 2. Node's own RSA-OAEP-256 decryption gives the CEK.
  assert(encryptedKey.length === key.k, 'the encrypted key is k octets (RFC 8017 §7.1.1)');
  const oaepCek = crypto.privateDecrypt(
    { key: key.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    encryptedKey,
  );
  assert(oaepCek.equals(cek), 'privateDecrypt(oaepHash sha256) gives the injected CEK');

  // 3. The seed inside EM is the injected one.
  const decoded = oaepDecode(rsadp(key.privateKey, encryptedKey), key.k);
  assert(decoded.seed.equals(seed), 'the OAEP seed in EM is the injected seed');
  assert(decoded.message.equals(cek), 'the OAEP message in EM is the CEK');

  // 4. The oracle's own encoding reproduces the encrypted key exactly.
  const reencrypted = rsaep(key.publicKey, oaepEncode(cek, seed, key.k));
  assert(reencrypted.equals(encryptedKey), "the oracle's own OAEP encoding reproduces the encrypted key");

  // 5. The content layer.
  assert(b64u(ivB64).equals(iv), 'the IV segment is the injected IV');
  const aad = Buffer.from(protectedB64, 'ascii');
  const plaintext = b64u(input.plaintext_b64u);
  const recovered = contentDecrypt(input.enc, cek, iv, aad, b64u(ctB64), b64u(tagB64));
  assert(recovered.equals(plaintext), 'the content decrypts to plaintext_b64u');
  const again = contentEncrypt(input.enc, cek, iv, aad, plaintext);
  assert(again.ciphertext.toString('base64url') === ctB64, 'the ciphertext is reproduced');
  assert(again.tag.toString('base64url') === tagB64, 'the tag is reproduced');
}

/** True for the vectors this oracle checks: exact RSA-OAEP-256 encryptions. */
export const isOracleVector = (v) =>
  v.operation === 'jwe.encrypt' &&
  v.expect?.ok === true &&
  typeof v.expect.jwe === 'string' &&
  v.input?.recipients?.some((r) => r.alg === 'RSA-OAEP-256');

function main() {
  const dir = path.resolve(process.argv[2] ?? DEFAULT_DIR);
  console.log(`rsa-oaep-oracle: Node ${process.version}, OpenSSL ${process.versions.openssl}, ${dir}`);
  const keys = loadKeys(dir);
  let checked = 0;
  let failed = 0;
  for (const name of fs.readdirSync(dir).sort()) {
    if (!name.endsWith('.json')) continue;
    const vector = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
    if (!isOracleVector(vector)) continue;
    checked++;
    try {
      checkVector(vector, keys);
      console.log(`PASS ${name}`);
    } catch (err) {
      failed++;
      console.log(`FAIL ${name}: ${err.message}`);
    }
  }
  if (checked < MIN_VECTORS) {
    console.log(`FAIL: ${checked} RSA-OAEP-256 vectors found, at least ${MIN_VECTORS} expected`);
    return 1;
  }
  console.log(`rsa-oaep-oracle: ${checked - failed}/${checked} vectors PASS`);
  return failed === 0 ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = main();
}
