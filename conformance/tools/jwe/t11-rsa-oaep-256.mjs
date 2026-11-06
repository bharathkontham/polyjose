// Builds the six T11 RSA-OAEP-256 `*-reproduced.json` vectors from the oracle's own
// EME-OAEP encoding and Node's raw RSA, independently of polyjose.
// Usage: node conformance/tools/jwe/t11-rsa-oaep-256.mjs <repo-root>
// Writes into <repo-root>/conformance/vectors/jwe/rsa-oaep-256/ (it needs keys/ there).
import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
const WT = process.argv[2];
const oracle = await import(path.join(WT, 'conformance/tools/rsa-oaep-oracle.mjs'));
const dir = path.join(WT, 'conformance/vectors/jwe/rsa-oaep-256');
const keys = oracle.loadKeys(dir);
const byBits = new Map([...keys.entries()].map(([n, k]) => [k.k * 8, { n, ...k }]));
// Deterministic "random" bytes: SHA-256 in counter mode over a label (any fixed bytes would do).
function stream(label, len) {
  const out = [];
  for (let i = 0; out.length * 32 < len; i++) out.push(crypto.createHash('sha256').update(`${label}/${i}`).digest());
  return Buffer.concat(out).subarray(0, len);
}
const node = `Node ${process.version} built-in crypto (OpenSSL ${process.versions.openssl})`;
for (const bits of [2048, 3072, 4096]) {
  for (const enc of ['A128GCM', 'A256CBC-HS512']) {
    const key = byBits.get(bits);
    const spec = oracle.ENC[enc];
    const name = `${bits}-${enc.toLowerCase()}`;
    const rng = stream(`polyjose 0003 T11 rsa-oaep-256 ${name}`, spec.cek + 32 + spec.iv);
    const cek = rng.subarray(0, spec.cek);
    const seed = rng.subarray(spec.cek, spec.cek + 32);
    const iv = rng.subarray(spec.cek + 32);
    const plaintext = Buffer.from(`RSA-OAEP-256 with ${enc} to a ${bits}-bit key: the CEK, the OAEP seed and the IV are drawn in that order.`);
    const protectedB64 = Buffer.from(JSON.stringify({ alg: 'RSA-OAEP-256', enc })).toString('base64url');
    const ek = oracle.rsaep(key.publicKey, oracle.oaepEncode(cek, seed, key.k));
    const { ciphertext, tag } = oracle.contentEncrypt(enc, cek, iv, Buffer.from(protectedB64, 'ascii'), plaintext);
    const jwe = [protectedB64, ek, iv, ciphertext, tag].map((p) => (typeof p === 'string' ? p : p.toString('base64url'))).join('.');
    const vector = {
      source: `${node}, conformance/tools/rsa-oaep-oracle.mjs`,
      description: `RFC 7518 §4.3 RSA-OAEP-256 + ${enc} to the ${bits}-bit test key: with rng_b64u as the drawn bytes (the ${spec.cek}-octet CEK, which is the expected CEK, then the 32-octet OAEP seed, then the ${spec.iv}-octet IV) polyjose reproduces the compact JWE exactly; the expected JWE was computed independently of polyjose by the oracle's EME-OAEP encoding (RFC 8017 §7.1.1) with Node's raw RSA and AES, and the oracle checks it with crypto.privateDecrypt (oaepHash sha256) against the test-only private key keys/rsa-${bits}.private.jwk (data only, never read by Rust); interop: true (feature 0010)`,
      operation: 'jwe.encrypt',
      input: {
        serialization: 'compact',
        enc,
        plaintext_b64u: plaintext.toString('base64url'),
        recipients: [{ alg: 'RSA-OAEP-256', key: { kty: 'RSA', n: key.n, e: key.e } }],
        rng_b64u: rng.toString('base64url'),
      },
      expect: { ok: true, jwe },
      features: ['fixed-rng'],
    };
    fs.writeFileSync(path.join(dir, `${name}-reproduced.json`), JSON.stringify(vector, null, 2) + '\n');
    console.log(name, ek.length);
  }
}
