#!/usr/bin/env node
// Generates conformance/vectors/binding-surface/ (feature 0013 T11): the vectors that pin the
// core's defaults and security decisions on every platform (ADR 0034 §6), so a binding that
// re-states a default, or offers an extra code path, fails them first. One vector per file
// (ADR 0045 §4); each `source` names the ADR it pins.
//
// Usage: node conformance/vectors/binding-surface/generate.mjs <repo-root> [<out-dir>]
//   <out-dir> defaults to <repo-root>/conformance/vectors/binding-surface. Only the files this
//   script names are written, so it can be run into an empty directory and diffed.
//
// Where the values come from, never from polyjose:
// - the allow-list, limit and RSA pins reuse inputs of committed vectors (RFC 7515 App. A.1-A.3,
//   RFC 7516 App. A.3, the jws-negative/ and jwe/rsa-oaep-256/ files), read from <repo-root>;
// - the PBES2 tokens are built here with node:crypto (OpenSSL) from SHA-256-derived bytes, so a
//   rerun gives identical files, and each is opened with node:crypto before it is written;
// - the JWT key-set pins reuse the RFC 7519 §3.1 token and the RFC 7515 A.1 and A.3 keys.
// Node built-ins only, no npm packages.

import { createCipheriv, createDecipheriv, createHash, pbkdf2Sync } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';

const [ROOT, OUT_ARG] = process.argv.slice(2);
if (!ROOT) {
  console.error('usage: node generate.mjs <repo-root> [<out-dir>]');
  process.exit(2);
}
const VECTORS = join(ROOT, 'conformance', 'vectors');
const OUT = OUT_ARG ?? join(VECTORS, 'binding-surface');
const NODE = `Node.js ${process.versions.node} node:crypto (OpenSSL ${process.versions.openssl})`;

const read = (path) => JSON.parse(readFileSync(join(VECTORS, path), 'utf8'));
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const utf8 = (s) => Buffer.from(s, 'utf8');
/** SHA-256 in counter mode over a label: any fixed bytes would do, these are reproducible. */
function derive(label, len) {
  const out = [];
  for (let i = 0; out.length * 32 < len; i++) {
    out.push(createHash('sha256').update(`polyjose 0013 T11 ${label} ${i}`).digest());
  }
  return Buffer.concat(out).subarray(0, len);
}

const written = [];
mkdirSync(OUT, { recursive: true });
function write(name, source, description, operation, input, expect) {
  writeFileSync(join(OUT, `${name}.json`), `${JSON.stringify({ source, description, operation, input, expect }, null, 2)}\n`);
  written.push(name);
}
const fails = (error) => ({ ok: false, error });

// ---- Allow-lists (ADR 0007, RFC 8725 §3.1) ----------------------------------------------------
const A1 = read('jws-rfc7515/a1-hs256-compact-verify.json');
const A1_JWS = A1.input.jws;
const A1_KEY = A1.input.key;
for (const [name, algs, what] of [
  ['jws-verify-allowed-algs-empty', [], 'an empty allow-list'],
  ['jws-verify-allowed-algs-none-only', ['none'], 'the allow-list ["none"]'],
]) {
  write(
    name,
    'ADR 0007; ADR 0034 §6',
    `ADR 0007, RFC 8725 §3.1: the RFC 7515 App. A.1 HS256 JWS with its own key and ${what} is AlgorithmNotAllowed, before the signature is looked at; no binding may substitute a default list`,
    'jws.verify',
    { jws: A1_JWS, key: A1_KEY, allowed_algs: algs },
    fails('AlgorithmNotAllowed'),
  );
}
const JWE_A3 = read('jwe/compact/rfc7516-a3-a128kw-a128cbc-hs256-decrypt.json');
for (const [name, algs, encs, what] of [
  ['jwe-decrypt-allowed-algs-empty', [], ['A128CBC-HS256'], 'an empty allowed_algs'],
  ['jwe-decrypt-allowed-algs-none-only', ['none'], ['A128CBC-HS256'], 'allowed_algs ["none"]'],
  ['jwe-decrypt-allowed-enc-empty', ['A128KW'], [], 'an empty allowed_enc'],
]) {
  write(
    name,
    'ADR 0007; ADR 0034 §6',
    `ADR 0007, RFC 8725 §3.1: the RFC 7516 App. A.3 A128KW + A128CBC-HS256 JWE with its own key and ${what} is AlgorithmNotAllowed, before any cryptography; no binding may substitute a default list`,
    'jwe.decrypt',
    { jwe: JWE_A3.input.jwe, key: JWE_A3.input.key, allowed_algs: algs, allowed_enc: encs },
    fails('AlgorithmNotAllowed'),
  );
}

// ---- PBES2 bound and per-token budget (ADR 0023, ADR 0050 §2) ----------------------------------
const PBES2 = 'PBES2-HS256+A128KW';
const ENC = 'A128GCM';
const PASSWORD = utf8('binding surface password');
const PASSWORD_KEY = { kty: 'oct', k: b64u(PASSWORD) };
const PLAINTEXT = utf8('Defaults come from the core.');
const DEFAULT_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
/** RFC 7518 §4.8.1.1: PBKDF2-HMAC-SHA-256, salt = UTF8(alg) || 0x00 || p2s, a 16-octet KEK. */
const kek = (password, p2s, p2c) => pbkdf2Sync(password, Buffer.concat([utf8(PBES2), Buffer.from([0]), p2s]), p2c, 16, 'sha256');
/** RFC 7518 §4.4 / RFC 3394 §2.2.1: AES Key Wrap with the default IV. */
function wrap(key, cek) {
  const c = createCipheriv('id-aes128-wrap', key, DEFAULT_IV);
  return Buffer.concat([c.update(cek), c.final()]);
}
/** RFC 3394 §2.2.2-§2.2.3: AES Key Unwrap; null when the integrity check fails. */
function unwrap(key, wrapped) {
  try {
    const d = createDecipheriv('id-aes128-wrap', key, DEFAULT_IV);
    return Buffer.concat([d.update(wrapped), d.final()]);
  } catch {
    return null;
  }
}
/** RFC 7516 §5.1 steps 13-16: AES-128-GCM with AAD = ASCII(BASE64URL(protected)). */
function seal(cek, iv, protectedB64) {
  const c = createCipheriv('aes-128-gcm', cek, iv, { authTagLength: 16 });
  c.setAAD(Buffer.from(protectedB64, 'ascii'));
  const ciphertext = Buffer.concat([c.update(PLAINTEXT), c.final()]);
  return { ciphertext, tag: c.getAuthTag() };
}
function open(cek, iv, protectedB64, ciphertext, tag) {
  const d = createDecipheriv('aes-128-gcm', cek, iv, { authTagLength: 16 });
  d.setAAD(Buffer.from(protectedB64, 'ascii'));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ciphertext), d.final()]);
}

/** A compact PBES2-HS256+A128KW + A128GCM JWE with this p2c, checked to open. */
function compactPbes2(p2c) {
  const p2s = derive(`compact p2s ${p2c}`, 16);
  const cek = derive(`compact cek ${p2c}`, 16);
  const iv = derive(`compact iv ${p2c}`, 12);
  const protectedB64 = b64u(utf8(JSON.stringify({ alg: PBES2, enc: ENC, p2s: b64u(p2s), p2c })));
  const encryptedKey = wrap(kek(PASSWORD, p2s, p2c), cek);
  const { ciphertext, tag } = seal(cek, iv, protectedB64);
  const unwrapped = unwrap(kek(PASSWORD, p2s, p2c), encryptedKey);
  if (unwrapped === null || !unwrapped.equals(cek)) throw new Error(`p2c ${p2c}: the key does not unwrap`);
  if (!open(cek, iv, protectedB64, ciphertext, tag).equals(PLAINTEXT)) throw new Error(`p2c ${p2c}: does not open`);
  return [protectedB64, b64u(encryptedKey), b64u(iv), b64u(ciphertext), b64u(tag)].join('.');
}
const pbes2Input = (jwe, bound) => {
  const input = { jwe, key: PASSWORD_KEY, allowed_algs: [PBES2], allowed_enc: [ENC] };
  if (bound !== undefined) input.max_pbes2_count = bound;
  return input;
};
const decrypted = (recipient) => ({ ok: true, plaintext_b64u: b64u(PLAINTEXT), recipient });
const P10000 = compactPbes2(10000);
const P10001 = compactPbes2(10001);
const compactToken = (p2c) => `a compact PBES2-HS256+A128KW + A128GCM JWE with p2c ${p2c} (built with ${NODE} from SHA-256-derived bytes)`;
write(
  'pbes2-p2c-10000-default-decrypts',
  'ADR 0023; ADR 0034 §6',
  `ADR 0023, RFC 7518 §8.8: ${compactToken(10000)} decrypts under the default max_pbes2_count of 10,000, which is inclusive`,
  'jwe.decrypt',
  pbes2Input(P10000),
  decrypted(0),
);
write(
  'pbes2-p2c-10001-default-fails',
  'ADR 0023; ADR 0034 §6',
  `ADR 0023, RFC 7518 §8.8 (CVE-2022-36083): ${compactToken(10001)} is DecryptionFailed under the default max_pbes2_count of 10,000, before any PBKDF2 work; no binding may raise the default`,
  'jwe.decrypt',
  pbes2Input(P10001),
  fails('DecryptionFailed'),
);
write(
  'pbes2-p2c-10001-bound-20000-decrypts',
  'ADR 0023; ADR 0034 §6',
  `ADR 0023: ${compactToken(10001)} decrypts once the caller raises max_pbes2_count to 20,000 explicitly`,
  'jwe.decrypt',
  pbes2Input(P10001, 20000),
  decrypted(0),
);

// Two kid-less recipients of p2c 6000: a decoy first, then the password. The per-token budget
// (ADR 0050 §2) is the sum over the candidates tried: 6000 + 6000 = 12,000 > 10,000.
const P2C_EACH = 6000;
const cek = derive('general cek', 16);
const iv = derive('general iv', 12);
const recipients = [utf8('binding surface decoy'), PASSWORD].map((password, i) => {
  const p2s = derive(`general p2s ${i}`, 16);
  return { header: { alg: PBES2, p2s: b64u(p2s), p2c: P2C_EACH }, encrypted_key: b64u(wrap(kek(password, p2s, P2C_EACH), cek)) };
});
const generalProtected = b64u(utf8(JSON.stringify({ enc: ENC })));
const sealed = seal(cek, iv, generalProtected);
const GENERAL = { protected: generalProtected, recipients, iv: b64u(iv), ciphertext: b64u(sealed.ciphertext), tag: b64u(sealed.tag) };
recipients.forEach((r, i) => {
  const opened = unwrap(kek(PASSWORD, Buffer.from(r.header.p2s, 'base64url'), P2C_EACH), Buffer.from(r.encrypted_key, 'base64url'));
  if ((opened !== null) !== (i === 1)) throw new Error(`general recipient ${i} unwraps wrongly under the password`);
});
if (!open(cek, iv, generalProtected, sealed.ciphertext, sealed.tag).equals(PLAINTEXT)) throw new Error('general: does not open');
const generalToken = `a general JWE (RFC 7516 §7.2.1) with two kid-less PBES2-HS256+A128KW + A128GCM recipients of p2c 6000, a decoy password first and this password second (built with ${NODE} from SHA-256-derived bytes)`;
write(
  'pbes2-two-recipients-over-default-budget',
  'ADR 0050 §2; ADR 0034 §6',
  `ADR 0050 §2 (amends ADR 0023), RFC 7518 §8.8: max_pbes2_count bounds the sum of p2c over every PBES2 candidate tried in one decrypt call. For ${generalToken}, the first candidate uses 6,000 of the default 10,000 and the second would need 6,000 more, so it is never tried: DecryptionFailed`,
  'jwe.decrypt',
  pbes2Input(GENERAL),
  fails('DecryptionFailed'),
);
write(
  'pbes2-two-recipients-budget-raised',
  'ADR 0050 §2; ADR 0034 §6',
  `ADR 0050 §2: ${generalToken} decrypts as recipient 1 once max_pbes2_count is raised to 12,000, the sum of p2c over both candidates`,
  'jwe.decrypt',
  pbes2Input(GENERAL, 2 * P2C_EACH),
  decrypted(1),
);

// ---- JWS limits (ADR 0026 §7) -----------------------------------------------------------------
const SEVENTEEN = read('jws-negative/general-17-signatures.json');
write(
  'jws-verify-17-signatures-default',
  'ADR 0026 §7; ADR 0034 §6',
  'ADR 0026 §7: the general JWS of jws-negative/general-17-signatures.json (17 copies of one valid HS256 signature over "Payload", RFC 7515 A.1 key) is InvalidFormat under the default max_signatures of 16, given no limit; no binding may raise the default',
  'jws.verify',
  SEVENTEEN.input,
  fails('InvalidFormat'),
);
write(
  'jws-verify-max-input-len-small',
  'ADR 0026 §7; ADR 0034 §6',
  `ADR 0026 §2 step 1, §7: the valid RFC 7515 App. A.1 compact JWS (${A1_JWS.length} octets) with an explicit max_input_len of 64 is InvalidFormat, checked before anything else; a binding passes the caller's limit through`,
  'jws.verify',
  { jws: A1_JWS, key: A1_KEY, allowed_algs: ['HS256'], max_input_len: 64 },
  fails('InvalidFormat'),
);

// ---- RSA public-key only (ADR 0021), no RSA-OAEP (ADR 0022) ------------------------------------
const A2_SIGN = read('jws-rfc7515/a2-rs256-sign-private-key-unsupported.json');
write(
  'jws-sign-rsa-private-jwk',
  'ADR 0021; ADR 0034 §6',
  'ADR 0021: signing the RFC 7515 App. A.2 payload with its RSA private JWK fails at JWK import with UnsupportedAlgorithm: RSA private keys are not supported on any platform',
  'jws.sign',
  A2_SIGN.input,
  fails('UnsupportedAlgorithm'),
);
const a2Signer = A2_SIGN.input.signers[0];
write(
  'jws-sign-rs256-public-key',
  'ADR 0021; ADR 0034 §6',
  'ADR 0021: RS256 signing with the RFC 7515 App. A.2 RSA public key (n and e of its JWK) and the A.2 protected header is UnsupportedAlgorithm: polyjose never signs with RSA',
  'jws.sign',
  { ...A2_SIGN.input, signers: [{ protected_b64u: a2Signer.protected_b64u, key: { kty: 'RSA', n: a2Signer.key.n, e: a2Signer.key.e } }] },
  fails('UnsupportedAlgorithm'),
);
const OAEP_DECRYPT = read('jwe/rsa-oaep-256/decrypt-own-output-unsupported.json');
write(
  'jwe-decrypt-rsa-oaep-256',
  'ADR 0021; ADR 0034 §6',
  'ADR 0021: the RSA-OAEP-256 + A128GCM JWE of jwe/rsa-oaep-256/decrypt-own-output-unsupported.json, with RSA-OAEP-256 allowed and the RSA public key, does not decrypt: UnsupportedAlgorithm (no RSA decryption on any platform)',
  'jwe.decrypt',
  OAEP_DECRYPT.input,
  fails('UnsupportedAlgorithm'),
);
const OAEP_ENCRYPT = read('jwe/rsa-oaep-256/encrypt-rsa-oaep-sha1-unsupported.json');
write(
  'jwe-encrypt-rsa-oaep',
  'ADR 0022; ADR 0034 §6',
  'ADR 0022: encrypting with RSA-OAEP (SHA-1 OAEP, RFC 7518 §4.3) to the RSA public key of jwe/rsa-oaep-256/encrypt-rsa-oaep-sha1-unsupported.json is UnsupportedAlgorithm, even though RSA-OAEP-256 accepts that key',
  'jwe.encrypt',
  OAEP_ENCRYPT.input,
  fails('UnsupportedAlgorithm'),
);
// ---- JWK Set selection (ADR 0029) --------------------------------------------------------------
const JWT = read('jwt/rfc7519/3-1-hs256-before-exp.json');
const A3_KEY = read('jws-rfc7515/a3-es256-compact-verify.json').input.key;
const DECOY = { kty: 'oct', k: b64u(derive('jwks decoy', 32)) };
write(
  'jwt-jwks-kidless-second-key',
  'ADR 0029 §2-§4; ADR 0034 §6',
  'ADR 0029 §2-§4: the RFC 7519 §3.1 HS256 JWT (no kid) against a JWK Set of two kid-less oct keys, a SHA-256-derived decoy first and the RFC 7515 A.1 key second: both are candidates, tried in set order, and the second verifies, so key_index is 1',
  'jwt.validate',
  { ...JWT.input, key: undefined, jwks: { keys: [DECOY, JWT.input.key] } },
  { ...JWT.expect, key_index: 1 },
);
write(
  'jwt-jwks-no-candidate',
  'ADR 0029 §2-§4; ADR 0034 §6',
  'ADR 0029 §2-§4: the RFC 7519 §3.1 HS256 JWT against a JWK Set holding only the RFC 7515 A.3 P-256 public key: no member can verify HS256, so there is no candidate: NoMatchingKey',
  'jwt.validate',
  { ...JWT.input, key: undefined, jwks: { keys: [A3_KEY] } },
  fails('NoMatchingKey'),
);

console.log(`wrote ${written.length} vectors into ${OUT}`);
