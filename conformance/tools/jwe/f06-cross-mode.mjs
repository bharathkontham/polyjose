#!/usr/bin/env node
// Generates conformance/vectors/jwe/negative-cross-mode/ (feature 0003 F06, ADR 0050 §1):
// cross-mode key confusion between A*GCMKW and the direct modes, and the rule that closes it.
//
// A*GCMKW wraps the CEK with AES-GCM under an empty AAD (RFC 7518 §4.7.1). A JSON JWE with no
// protected header and no aad has the content AAD "" too (RFC 7516 §5.1 step 14), so a GCMKW
// recipient's (iv, encrypted_key, tag) is a valid dir + A*GCM ciphertext under the same key. The
// rule: dir (RFC 7518 §4.5) and ECDH-ES (§4.6, direct) need alg AND enc in the JWE Protected
// Header, else InvalidHeader before any cryptography.
//
// Usage: node conformance/tools/jwe/f06-cross-mode.mjs <out-dir>
// Writes each vector it names into <out-dir> (and only those), so it can be run into an empty
// directory and diffed. Every token is built here with node:crypto (OpenSSL), independently of
// polyjose, from SHA-256-derived bytes, so a rerun gives identical files; the one exception is the
// security audit's forged token, copied verbatim and checked here to open under the empty AAD.
// Every token expected to decrypt, and every forgery, is opened with node:crypto before writing.
// Node built-ins only, no npm packages.

import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  pbkdf2Sync,
} from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';

const [OUT] = process.argv.slice(2);
if (!OUT) {
  console.error('usage: node f06-cross-mode.mjs <out-dir>');
  process.exit(2);
}

// ---- encodings and deterministic bytes -------------------------------------------------------
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const unb64u = (s) => {
  const b = Buffer.from(s, 'base64url');
  if (b64u(b) !== s) throw new Error(`non-canonical base64url: ${s}`);
  return b;
};
const utf8 = (s) => Buffer.from(s, 'utf8');
/** SHA-256 in counter mode over a label: any fixed bytes would do, these are reproducible. */
function derive(label, len) {
  const out = [];
  for (let i = 0; out.length * 32 < len; i++) {
    out.push(createHash('sha256').update(`polyjose 0003 F06 ${label} ${i}`).digest());
  }
  return Buffer.concat(out).subarray(0, len);
}
const ORACLE = `Node.js ${process.versions.node} node:crypto (OpenSSL ${process.versions.openssl})`;

// ---- primitives (RFC 7518), all from node:crypto ---------------------------------------------
/** RFC 7518 §5.3 AES GCM, and §4.7.1 GCM key wrapping (empty AAD): [ciphertext, tag]. */
function gcmSeal(key, iv, aad, pt) {
  const c = createCipheriv(`aes-${key.length * 8}-gcm`, key, iv, { authTagLength: 16 });
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  return [ct, c.getAuthTag()];
}
/** AES-GCM open; null if the tag does not verify. */
function gcmOpen(key, iv, aad, ct, tag) {
  try {
    const d = createDecipheriv(`aes-${key.length * 8}-gcm`, key, iv, { authTagLength: 16 });
    d.setAAD(aad);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]);
  } catch {
    return null;
  }
}
/** RFC 7518 §4.4 / RFC 3394: AES Key Wrap with the default IV. */
function aesKw(kek, cek) {
  const c = createCipheriv(`id-aes${kek.length * 8}-wrap`, kek, Buffer.from('A6A6A6A6A6A6A6A6', 'hex'));
  return Buffer.concat([c.update(cek), c.final()]);
}
const be32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const lp = (b) => Buffer.concat([be32(b.length), b]);
/** RFC 7518 §4.6.2: Concat KDF (NIST SP 800-56A §5.8.1) with SHA-256, empty apu/apv. */
function concatKdf(z, algId, bits) {
  const other = Buffer.concat([lp(Buffer.from(algId, 'ascii')), lp(Buffer.alloc(0)), lp(Buffer.alloc(0)), be32(bits)]);
  let out = Buffer.alloc(0);
  for (let i = 1; out.length < bits / 8; i++) {
    out = Buffer.concat([out, createHash('sha256').update(Buffer.concat([be32(i), z, other])).digest()]);
  }
  return out.subarray(0, bits / 8);
}
/** RFC 7518 §4.8.1: PBES2-HS256+A128KW key derivation (salt = alg || 0x00 || p2s). */
function pbes2Kek(password, p2s, p2c) {
  const salt = Buffer.concat([utf8('PBES2-HS256+A128KW'), Buffer.from([0]), p2s]);
  return pbkdf2Sync(password, salt, p2c, 16, 'sha256');
}

// ---- keys --------------------------------------------------------------------------------------
/** The audit's key: 16 octets 00..0f, no alg (RFC 7517 §4.4 makes alg optional). */
const K128 = Buffer.from([...Array(16).keys()]);
const KEY128 = { kty: 'oct', k: b64u(K128) };
if (KEY128.k !== 'AAECAwQFBgcICQoLDA0ODw') throw new Error('audit key');
const K256 = derive('a256 key', 32);
const KEY256 = { kty: 'oct', k: b64u(K256) };
const PASSWORD = utf8('password-for-f06');
const PASSWORD_KEY = { kty: 'oct', k: b64u(PASSWORD) };

/** A P-256 key pair from a fixed private scalar. */
function p256(label) {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(derive(label, 32));
  const pub = ecdh.getPublicKey(null, 'uncompressed');
  return {
    ecdh,
    jwk: { kty: 'EC', crv: 'P-256', x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33)), d: b64u(ecdh.getPrivateKey()) },
  };
}
/** An X25519 key from fixed private bytes (RFC 8037 §2, RFC 7748 §5; PKCS#8 wrapper). */
function x25519(label) {
  const d = derive(label, 32);
  const priv = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), d]),
    format: 'der',
    type: 'pkcs8',
  });
  const { x } = createPublicKey(priv).export({ format: 'jwk' });
  return { priv, jwk: { kty: 'OKP', crv: 'X25519', x, d: b64u(d) } };
}
const P256_RECIPIENT = p256('p256 recipient');
const X25519_RECIPIENT = x25519('x25519 recipient');

/** ECDH-ES agreement (RFC 7518 §4.6.2): [epk, Z] for the recipient's public key. */
function agree(recipient, label) {
  if (recipient.jwk.kty === 'EC') {
    const eph = p256(label);
    const peer = Buffer.concat([Buffer.from([4]), unb64u(recipient.jwk.x), unb64u(recipient.jwk.y)]);
    const { x, y } = eph.jwk;
    return [{ kty: 'EC', crv: 'P-256', x, y }, eph.ecdh.computeSecret(peer)];
  }
  const eph = x25519(label);
  const peer = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: recipient.jwk.x }, format: 'jwk' });
  return [{ kty: 'OKP', crv: 'X25519', x: eph.jwk.x }, diffieHellman({ privateKey: eph.priv, publicKey: peer })];
}
/** The recipient's side of the agreement, to cross-check: Z from its private key and the epk. */
function agreeBack(recipient, epk) {
  if (recipient.jwk.kty === 'EC') {
    return recipient.ecdh.computeSecret(Buffer.concat([Buffer.from([4]), unb64u(epk.x), unb64u(epk.y)]));
  }
  const peer = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: epk.x }, format: 'jwk' });
  return diffieHellman({ privateKey: recipient.priv, publicKey: peer });
}

// ---- token builders ----------------------------------------------------------------------------
const encode = (header) => b64u(utf8(JSON.stringify(header)));
const PT = utf8('cross-mode confusion must never decrypt');

/** Content encryption (RFC 7516 §5.1 steps 14-15) over `protectedB64` and no aad. */
function content(cek, label, protectedB64, pt = PT) {
  const iv = derive(`${label} content iv`, 12);
  const [ct, tag] = gcmSeal(cek, iv, Buffer.from(protectedB64, 'ascii'), pt);
  return { iv: b64u(iv), ciphertext: b64u(ct), tag: b64u(tag) };
}
/** A JSON JWE, `protected` omitted when empty (RFC 7516 §7.2.1), members in RFC order. */
function jsonJwe({ protectedB64 = '', unprotected, header, recipients, encryptedKey, body }) {
  const j = {};
  if (protectedB64) j.protected = protectedB64;
  if (unprotected) j.unprotected = unprotected;
  if (header) j.header = header;
  if (encryptedKey) j.encrypted_key = encryptedKey;
  if (recipients) j.recipients = recipients;
  return { ...j, ...body };
}
/** A victim's A*GCMKW key wrap of a fresh CEK under `kek`: { cek, iv, encryptedKey, tag }. */
function gcmKwWrap(kek, label) {
  const cek = derive(`${label} cek`, kek.length);
  const iv = derive(`${label} wrap iv`, 12);
  const [ek, tag] = gcmSeal(kek, iv, Buffer.alloc(0), cek);
  return { cek, iv: b64u(iv), encryptedKey: b64u(ek), tag: b64u(tag) };
}
/** The forgery: the wrap's triple relabelled as dir content; checked to open to the CEK. */
function forge(kek, wrap) {
  const opened = gcmOpen(kek, unb64u(wrap.iv), Buffer.alloc(0), unb64u(wrap.encryptedKey), unb64u(wrap.tag));
  if (!opened || !opened.equals(wrap.cek)) throw new Error('the relabelled wrap does not open to the CEK');
  return { iv: wrap.iv, ciphertext: wrap.encryptedKey, tag: wrap.tag };
}

// ---- output ------------------------------------------------------------------------------------
const files = [];
function write(name, v) {
  const ordered = { source: 'ADR 0050 §1', description: v.description, operation: 'jwe.decrypt', input: v.input, expect: v.expect };
  mkdirSync(OUT, { recursive: true });
  if (files.includes(name)) throw new Error(`written twice: ${name}`);
  writeFileSync(join(OUT, `${name}.json`), JSON.stringify(ordered, null, 2) + '\n');
  files.push(name);
}
const ok = (pt = PT) => ({ ok: true, plaintext_b64u: b64u(pt), recipient: 0 });
const fails = (error) => ({ ok: false, error });
const decrypt = (jwe, key, algs, encs) => ({ jwe, key, allowed_algs: algs, allowed_enc: encs });
const AUDIT_ALGS = ['A128GCMKW', 'dir'];

// =============================================================================================
// Negatives: the forgery in every placement, the reverse relabel, direct modes unprotected
// =============================================================================================

// The audit's token, verbatim (ADR 0050 Context 1): a victim's A128GCMKW triple as flattened dir.
const AUDIT = {
  unprotected: { alg: 'dir', enc: 'A128GCM' },
  iv: 'O7z64SOn4nzSXqYX',
  ciphertext: 'MnP1M2KMxJATaL2fiHopzA',
  tag: '1iuYCU-NaRWTNmU0AQpqYg',
};
{
  const cek = gcmOpen(K128, unb64u(AUDIT.iv), Buffer.alloc(0), unb64u(AUDIT.ciphertext), unb64u(AUDIT.tag));
  if (!cek || cek.length !== 16) throw new Error('the audit token is not a live forgery');
}
write('audit-forged-gcmkw-as-dir', {
  description: `Security audit B1: an A128GCMKW recipient's iv, encrypted_key and tag relabelled as a flattened dir + A128GCM JWE with alg and enc in the shared unprotected header and no protected header or aad, under the audit's alg-less 16-octet key with [A128GCMKW, dir] allowed. Both AADs are empty, so the triple opens (checked with ${ORACLE}) to the victim's CEK; RFC 7516 §5.2 step 4 with ADR 0050 §1 makes it InvalidHeader before any cryptography`,
  input: decrypt(AUDIT, KEY128, AUDIT_ALGS, ['A128GCM']),
  expect: fails('InvalidHeader'),
});

{
  const wrap = gcmKwWrap(K128, 'per-recipient');
  write('forged-gcmkw-as-dir-per-recipient-header', {
    description: `ADR 0050 §1, RFC 7518 §4.5, §4.7.1: an A128GCMKW key wrap relabelled as a flattened dir JWE with alg and enc in the per-recipient header (RFC 7516 §7.2.2 "header"), alg-less key, [A128GCMKW, dir] allowed; the triple opens to the wrapped CEK under the empty AAD (${ORACLE}): InvalidHeader`,
    input: decrypt(jsonJwe({ header: { alg: 'dir', enc: 'A128GCM' }, body: forge(K128, wrap) }), KEY128, AUDIT_ALGS, ['A128GCM']),
    expect: fails('InvalidHeader'),
  });
}
{
  const wrap = gcmKwWrap(K128, 'general');
  write('forged-gcmkw-as-dir-general', {
    description: `ADR 0050 §1, RFC 7516 §7.2.1: the alg-less-key forgery through the general form: an A128GCMKW key wrap relabelled as a dir JWE with enc in the shared unprotected header and alg in recipients[0].header, no protected header; the triple opens to the wrapped CEK under the empty AAD (${ORACLE}): InvalidHeader`,
    input: decrypt(
      jsonJwe({ unprotected: { enc: 'A128GCM' }, recipients: [{ header: { alg: 'dir' } }], body: forge(K128, wrap) }),
      KEY128,
      AUDIT_ALGS,
      ['A128GCM'],
    ),
    expect: fails('InvalidHeader'),
  });
}
{
  const wrap = gcmKwWrap(K256, 'a256');
  write('forged-a256gcmkw-as-dir-a256gcm', {
    description: `ADR 0050 §1, RFC 7518 §4.7.1: the same relabel for A256GCMKW and A256GCM under an alg-less 32-octet key, [A256GCMKW, dir] allowed; the triple opens to the wrapped CEK under the empty AAD (${ORACLE}): InvalidHeader`,
    input: decrypt(jsonJwe({ unprotected: { alg: 'dir', enc: 'A256GCM' }, body: forge(K256, wrap) }), KEY256, ['A256GCMKW', 'dir'], ['A256GCM']),
    expect: fails('InvalidHeader'),
  });
}

// The reverse relabel: a dir token with no protected header (another producer could write one)
// whose 16-octet plaintext is a plausible CEK, presented as A128GCMKW.
{
  const secret = derive('reverse secret', 16);
  const iv = derive('reverse iv', 12);
  const [ct, tag] = gcmSeal(K128, iv, Buffer.alloc(0), secret);
  const triple = { iv: b64u(iv), ciphertext: b64u(ct), tag: b64u(tag) };
  write('dir-no-protected-header', {
    description: `ADR 0050 §1, RFC 7518 §4.5: an honest dir + A128GCM JWE with alg and enc only in the shared unprotected header and no protected header (content AAD ""), built with ${ORACLE}; it would decrypt, but a direct mode needs alg and enc protected: InvalidHeader`,
    input: decrypt(jsonJwe({ unprotected: { alg: 'dir', enc: 'A128GCM' }, body: triple }), KEY128, AUDIT_ALGS, ['A128GCM']),
    expect: fails('InvalidHeader'),
  });
  // As A128GCMKW the triple is the key wrap and unwraps to `secret`; the content, which an
  // attacker could only copy from the same triple, does not open under it.
  if (gcmOpen(secret, iv, Buffer.alloc(0), ct, tag)) throw new Error('reverse relabel content opens');
  write('reverse-relabel-dir-as-gcmkw', {
    description: `ADR 0050 §1, RFC 7518 §4.7.1, RFC 7516 §11.4: the reverse relabel: the dir-no-protected-header triple presented as an A128GCMKW key wrap (iv and tag in the shared header, its ciphertext as encrypted_key), with the same triple as content. GCMKW with an unprotected alg is not a direct mode, so the header rule does not apply; the key unwraps to the dir plaintext, under which the copied content does not open (checked with ${ORACLE}): the uniform DecryptionFailed, never a plaintext`,
    input: decrypt(
      jsonJwe({ unprotected: { alg: 'A128GCMKW', enc: 'A128GCM', iv: triple.iv, tag: triple.tag }, encryptedKey: triple.ciphertext, body: triple }),
      KEY128,
      AUDIT_ALGS,
      ['A128GCM'],
    ),
    expect: fails('DecryptionFailed'),
  });
}

// dir with only one of alg and enc protected: each a valid ciphertext over its own AAD.
for (const [name, prot, place, what] of [
  ['dir-alg-shared-enc-protected', { enc: 'A128GCM' }, { unprotected: { alg: 'dir' } }, 'enc protected and alg only in the shared unprotected header'],
  ['dir-alg-per-recipient-enc-protected', { enc: 'A128GCM' }, { header: { alg: 'dir' } }, 'enc protected and alg only in the per-recipient header'],
  ['dir-alg-protected-enc-shared', { alg: 'dir' }, { unprotected: { enc: 'A128GCM' } }, 'alg protected and enc only in the shared unprotected header'],
]) {
  const protectedB64 = encode(prot);
  const body = content(K128, name, protectedB64);
  write(name, {
    description: `ADR 0050 §1, RFC 7516 §5.2 step 4, RFC 7518 §4.5: a flattened dir + A128GCM JWE with ${what}, a valid ciphertext over its protected header (built with ${ORACLE}): a direct mode needs both alg and enc protected, so InvalidHeader`,
    input: decrypt(jsonJwe({ protectedB64, ...place, body }), KEY128, AUDIT_ALGS, ['A128GCM']),
    expect: fails('InvalidHeader'),
  });
}

// ECDH-ES (direct) with alg unprotected, P-256 and X25519: valid ciphertexts over {"enc"}.
function ecdhDirect(recipient, label) {
  const [epk, z] = agree(recipient, `${label} ephemeral`);
  if (!agreeBack(recipient, epk).equals(z)) throw new Error(`${label}: agreement`);
  return [epk, concatKdf(z, 'A128GCM', 128)];
}
for (const [name, recipient, curve, placement] of [
  ['ecdh-es-p256-alg-shared', P256_RECIPIENT, 'P-256', 'shared'],
  ['ecdh-es-x25519-alg-per-recipient', X25519_RECIPIENT, 'X25519', 'per-recipient'],
  ['ecdh-es-x25519-general-alg-per-recipient', X25519_RECIPIENT, 'X25519', 'general'],
]) {
  const [epk, cek] = ecdhDirect(recipient, name);
  const protectedB64 = encode({ enc: 'A128GCM' });
  const body = content(cek, name, protectedB64);
  const members = { alg: 'ECDH-ES', epk };
  const place = {
    shared: { unprotected: members },
    'per-recipient': { header: members },
    general: { recipients: [{ header: members }] },
  }[placement];
  const where = {
    shared: 'the shared unprotected header',
    'per-recipient': 'the per-recipient header (flattened)',
    general: 'recipients[0].header (general)',
  }[placement];
  write(name, {
    description: `ADR 0050 §1, RFC 7518 §4.6 (Direct Key Agreement), RFC 8037 §3.2 where X25519: an ECDH-ES + A128GCM JWE on ${curve} with enc protected and alg and epk only in ${where}, a valid ciphertext under the Concat KDF CEK (built with ${ORACLE}): InvalidHeader before the agreement runs`,
    input: decrypt(jsonJwe({ protectedB64, ...place, body }), recipient.jwk, ['ECDH-ES'], ['A128GCM']),
    expect: fails('InvalidHeader'),
  });
}

// =============================================================================================
// Positive controls: protected direct modes, and non-direct modes with an unprotected alg
// =============================================================================================
{
  const header = { alg: 'dir', enc: 'A128GCM' };
  const protectedB64 = encode(header);
  const body = content(K128, 'control dir compact', protectedB64);
  write('control-dir-compact-decrypts', {
    description: `ADR 0050 §1 positive control, RFC 7516 §7.1: a compact dir + A128GCM JWE (alg and enc protected) under the audit key and policy decrypts (built with ${ORACLE})`,
    input: decrypt([protectedB64, '', body.iv, body.ciphertext, body.tag].join('.'), KEY128, AUDIT_ALGS, ['A128GCM']),
    expect: ok(),
  });
}
{
  const protectedB64 = encode({ alg: 'dir', enc: 'A128GCM' });
  const body = content(K128, 'control dir flattened', protectedB64);
  write('control-dir-flattened-protected-decrypts', {
    description: `ADR 0050 §1 positive control, RFC 7516 §7.2.2: a flattened dir + A128GCM JWE with alg and enc protected and a kid in the shared unprotected header decrypts under the audit key and policy (built with ${ORACLE})`,
    input: decrypt(jsonJwe({ protectedB64, unprotected: { kid: 'f06' }, body }), KEY128, AUDIT_ALGS, ['A128GCM']),
    expect: ok(),
  });
}
for (const [name, recipient, curve] of [
  ['control-ecdh-es-p256-compact-decrypts', P256_RECIPIENT, 'P-256'],
  ['control-ecdh-es-x25519-compact-decrypts', X25519_RECIPIENT, 'X25519'],
]) {
  const [epk, cek] = ecdhDirect(recipient, name);
  const protectedB64 = encode({ alg: 'ECDH-ES', enc: 'A128GCM', epk });
  const body = content(cek, name, protectedB64);
  write(name, {
    description: `ADR 0050 §1 positive control, RFC 7518 §4.6: a compact ECDH-ES + A128GCM JWE on ${curve} (alg, enc and epk protected) decrypts (built with ${ORACLE})`,
    input: decrypt([protectedB64, '', body.iv, body.ciphertext, body.tag].join('.'), recipient.jwk, ['ECDH-ES'], ['A128GCM']),
    expect: ok(),
  });
}
{
  // The victim's mode, honestly: A128GCMKW with alg, iv and tag in the shared header and no
  // protected header, under the audit key and policy.
  const wrap = gcmKwWrap(K128, 'control gcmkw');
  const body = content(wrap.cek, 'control gcmkw', '');
  write('control-a128gcmkw-alg-unprotected-decrypts', {
    description: `ADR 0050 §1 positive control, RFC 7516 §7.2.1, RFC 7518 §4.7: an A128GCMKW + A128GCM flattened JWE with no protected header and alg, enc, iv and tag in the shared unprotected header decrypts under the audit key and policy: the rule is for the direct modes only (built with ${ORACLE})`,
    input: decrypt(
      jsonJwe({ unprotected: { alg: 'A128GCMKW', enc: 'A128GCM', iv: wrap.iv, tag: wrap.tag }, encryptedKey: wrap.encryptedKey, body }),
      KEY128,
      AUDIT_ALGS,
      ['A128GCM'],
    ),
    expect: ok(),
  });
}
{
  const cek = derive('control a128kw cek', 16);
  const protectedB64 = encode({ enc: 'A128GCM' });
  const body = content(cek, 'control a128kw', protectedB64);
  write('control-a128kw-alg-per-recipient-decrypts', {
    description: `ADR 0050 §1 positive control, RFC 7516 §7.2.1, RFC 7518 §4.4: a general A128KW + A128GCM JWE with enc protected and alg in recipients[0].header decrypts under the audit key with [A128KW, dir] allowed (built with ${ORACLE})`,
    input: decrypt(
      jsonJwe({ protectedB64, recipients: [{ header: { alg: 'A128KW' }, encrypted_key: b64u(aesKw(K128, cek)) }], body }),
      KEY128,
      ['A128KW', 'dir'],
      ['A128GCM'],
    ),
    expect: ok(),
  });
}
{
  const cek = derive('control pbes2 cek', 16);
  const p2s = derive('control pbes2 p2s', 16);
  const p2c = 1000;
  const protectedB64 = encode({ enc: 'A128GCM' });
  const body = content(cek, 'control pbes2', protectedB64);
  write('control-pbes2-alg-shared-decrypts', {
    description: `ADR 0050 §1 positive control, RFC 7516 §7.2.1, RFC 7518 §4.8: a flattened PBES2-HS256+A128KW + A128GCM JWE (p2c 1000) with enc protected and alg, p2s and p2c in the shared unprotected header decrypts with the password as an oct key, [PBES2-HS256+A128KW, dir] allowed (built with ${ORACLE})`,
    input: decrypt(
      jsonJwe({
        protectedB64,
        unprotected: { alg: 'PBES2-HS256+A128KW', p2s: b64u(p2s), p2c },
        encryptedKey: b64u(aesKw(pbes2Kek(PASSWORD, p2s, p2c), cek)),
        body,
      }),
      PASSWORD_KEY,
      ['PBES2-HS256+A128KW', 'dir'],
      ['A128GCM'],
    ),
    expect: ok(),
  });
}
{
  const name = 'control-ecdh-es-a128kw-alg-per-recipient-decrypts';
  const [epk, z] = agree(P256_RECIPIENT, `${name} ephemeral`);
  if (!agreeBack(P256_RECIPIENT, epk).equals(z)) throw new Error(`${name}: agreement`);
  const kek = concatKdf(z, 'ECDH-ES+A128KW', 128);
  const cek = derive(`${name} cek`, 16);
  const protectedB64 = encode({ enc: 'A128GCM' });
  const body = content(cek, name, protectedB64);
  write(name, {
    description: `ADR 0050 §1 positive control, RFC 7516 §7.2.2, RFC 7518 §4.6: a flattened ECDH-ES+A128KW + A128GCM JWE on P-256 with enc protected and alg and epk in the per-recipient header decrypts, [ECDH-ES+A128KW, ECDH-ES] allowed (built with ${ORACLE})`,
    input: decrypt(
      jsonJwe({ protectedB64, header: { alg: 'ECDH-ES+A128KW', epk }, encryptedKey: b64u(aesKw(kek, cek)), body }),
      P256_RECIPIENT.jwk,
      ['ECDH-ES+A128KW', 'ECDH-ES'],
      ['A128GCM'],
    ),
    expect: ok(),
  });
}

console.log(`wrote ${files.length} vectors to ${OUT}`);
