#!/usr/bin/env node
// Generates the per-token PBES2 budget vectors of conformance/vectors/jwe/pbes2/ (feature 0003
// F07, ADR 0050 §2, amending ADR 0023).
//
// DecryptPolicy::max_pbes2_count bounds the SUM of p2c over every PBES2 candidate tried in one
// decrypt call, not each recipient on its own (RFC 7518 §8.8). The token here is a general JWE
// JSON Serialization (RFC 7516 §7.2.1) with 16 PBES2-HS256+A128KW recipients, each with p2c 1000
// and no kid, so every one is a candidate for a kid-less password key. The CEK is wrapped for 15
// decoy passwords and, last (recipient 15), for the decrypting password. Under the default budget
// of 10,000 only the first 10 recipients are tried (DecryptionFailed); a budget of 16,000 reaches
// the 16th, and 15,999 falls one iteration short of it.
//
// Usage: node conformance/tools/jwe/f07-pbes2-budget.mjs <out-dir>
// Writes each vector it names into <out-dir> (and only those), so it can be run into an empty
// directory and diffed. The token is built here with node:crypto (OpenSSL), independently of
// polyjose, from SHA-256-derived bytes, so a rerun gives identical files. Before writing, it is
// opened with node:crypto: recipient 15 opens under the password, and no decoy's encrypted key
// unwraps under it. Node built-ins only, no npm packages.

import { createCipheriv, createDecipheriv, createHash, pbkdf2Sync } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';

const [OUT] = process.argv.slice(2);
if (!OUT) {
  console.error('usage: node f07-pbes2-budget.mjs <out-dir>');
  process.exit(2);
}

// ---- encodings and deterministic bytes -------------------------------------------------------
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const utf8 = (s) => Buffer.from(s, 'utf8');
/** SHA-256 in counter mode over a label: any fixed bytes would do, these are reproducible. */
function derive(label, len) {
  const out = [];
  for (let i = 0; out.length * 32 < len; i++) {
    out.push(createHash('sha256').update(`polyjose 0003 F07 ${label} ${i}`).digest());
  }
  return Buffer.concat(out).subarray(0, len);
}

// ---- primitives (RFC 7518), all from node:crypto ---------------------------------------------
const ALG = 'PBES2-HS256+A128KW';
const ENC = 'A128GCM';
const P2C = 1000;
const RECIPIENTS = 16;
/** RFC 7518 §4.8.1.1: PBKDF2-HMAC-SHA-256 over the password, salt = UTF8(alg) || 0x00 || p2s. */
function kek(password, p2s) {
  const salt = Buffer.concat([utf8(ALG), Buffer.from([0]), p2s]);
  return pbkdf2Sync(password, salt, P2C, 16, 'sha256');
}
const DEFAULT_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
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

// ---- the token -------------------------------------------------------------------------------
const PASSWORD = utf8('correct horse, budgeted');
const KEY = { kty: 'oct', k: b64u(PASSWORD) };
const CEK = derive('cek', 16);
const IV = derive('iv', 12);
const PLAINTEXT = utf8('Sixteen recipients, one budget.');
const CORRECT = RECIPIENTS - 1;

const recipients = [];
for (let i = 0; i < RECIPIENTS; i++) {
  const password = i === CORRECT ? PASSWORD : utf8(`decoy password ${i}`);
  const p2s = derive(`p2s ${i}`, 16);
  recipients.push({
    header: { alg: ALG, p2s: b64u(p2s), p2c: P2C },
    encrypted_key: b64u(wrap(kek(password, p2s), CEK)),
  });
}
// RFC 7516 §5.1 steps 13-15: AAD = ASCII(BASE64URL(UTF8(JWE Protected Header))), no aad member.
const protectedB64 = b64u(utf8(JSON.stringify({ enc: ENC })));
const cipher = createCipheriv('aes-128-gcm', CEK, IV, { authTagLength: 16 });
cipher.setAAD(Buffer.from(protectedB64, 'ascii'));
const ciphertext = Buffer.concat([cipher.update(PLAINTEXT), cipher.final()]);
const JWE = {
  protected: protectedB64,
  recipients,
  iv: b64u(IV),
  ciphertext: b64u(ciphertext),
  tag: b64u(cipher.getAuthTag()),
};

// ---- self-check with node:crypto --------------------------------------------------------------
for (let i = 0; i < RECIPIENTS; i++) {
  const r = recipients[i];
  const opened = unwrap(kek(PASSWORD, Buffer.from(r.header.p2s, 'base64url')), Buffer.from(r.encrypted_key, 'base64url'));
  if ((opened !== null) !== (i === CORRECT)) throw new Error(`recipient ${i} unwraps wrongly under the password`);
  if (i === CORRECT && !opened.equals(CEK)) throw new Error('recipient 15 does not unwrap to the CEK');
}
const decipher = createDecipheriv('aes-128-gcm', CEK, IV, { authTagLength: 16 });
decipher.setAAD(Buffer.from(protectedB64, 'ascii'));
decipher.setAuthTag(Buffer.from(JWE.tag, 'base64url'));
const back = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
if (!back.equals(PLAINTEXT)) throw new Error('the token does not open');

// ---- vectors ----------------------------------------------------------------------------------
mkdirSync(OUT, { recursive: true });
function write(name, vector) {
  writeFileSync(join(OUT, `${name}.json`), `${JSON.stringify(vector, null, 2)}\n`);
}
const SOURCE = 'ADR 0050 §2';
const TOKEN =
  'a general JWE (RFC 7516 §7.2.1) with 16 kid-less PBES2-HS256+A128KW + A128GCM recipients of p2c 1000, ' +
  'the 16th for this password and the others for decoys (built with node:crypto, F07)';
function decryptVector(name, budget, description, expect) {
  const input = { jwe: JWE, key: KEY, allowed_algs: [ALG], allowed_enc: [ENC] };
  if (budget !== undefined) input.max_pbes2_count = budget;
  write(name, { source: SOURCE, description, operation: 'jwe.decrypt', input, expect });
}
decryptVector(
  'budget-16-recipients-over-default',
  undefined,
  `ADR 0050 §2 (amends ADR 0023), RFC 7518 §8.8: max_pbes2_count bounds the sum of p2c over every PBES2 ` +
    `candidate tried in one decrypt call. For ${TOKEN}, the default budget of 10,000 covers only the first 10 ` +
    `recipients; the 11th to 16th fail without any PBKDF2 work, so the result is DecryptionFailed`,
  { ok: false, error: 'DecryptionFailed' },
);
decryptVector(
  'budget-16-recipients-raised',
  RECIPIENTS * P2C,
  `ADR 0050 §2: ${TOKEN} decrypts as recipient 15 once max_pbes2_count is raised to 16,000, ` +
    `the sum of p2c over the 16 candidates tried`,
  { ok: true, plaintext_b64u: b64u(PLAINTEXT), recipient: CORRECT },
);
decryptVector(
  'budget-16-recipients-one-short',
  RECIPIENTS * P2C - 1,
  `ADR 0050 §2: ${TOKEN} is DecryptionFailed with max_pbes2_count 15,999: after 15 candidates only 999 ` +
    `iterations are left, fewer than the 16th recipient's p2c of 1000`,
  { ok: false, error: 'DecryptionFailed' },
);
