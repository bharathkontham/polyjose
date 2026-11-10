#!/usr/bin/env node
// Generates the cross-family JWE conformance vectors of feature 0003 T18:
//
//   conformance/vectors/jwe/rfc7520-multi/   RFC 7520 §5.13 (three recipients, three families)
//   conformance/vectors/jwe/negative-crypto/ cross-family negatives (tamper per enc, allow-lists,
//                                            invalid epk per curve, missing and extra recipients)
//   conformance/vectors/jwe/json/            RFC 7520 §5.7 flattened (erratum 4802)
//   conformance/vectors/jwe/zip/             RFC 7520 §5.9 in both JSON forms
//   conformance/vectors/jwe/gcmkw/           A256GCMKW with iv and tag in the per-recipient header
//
// Usage: node conformance/tools/jwe/t18-cross-family.mjs <repo-root> [<out-root>]
// Reads (data only) the vendored ietf-jose cookbook (crates/polyjose/tests/third_party/
// ietf-jose-cookbook/jwe/) and the vendored Wycheproof ECDH webcrypto files; writes each vector it
// names under <out-root>/conformance/vectors/jwe/ (default <out-root> = <repo-root>), and only
// those, so it can be run into an empty directory and diffed. Every RFC value is read from the
// cookbook, never typed in. Every token that is not an RFC output is built here with node:crypto
// (OpenSSL), independently of polyjose, from SHA-256-derived bytes, so a rerun gives identical
// files. Node built-ins only, no npm packages.

import { createCipheriv, createDecipheriv, createECDH, createHash, createHmac } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';

const [root, outRoot = root] = process.argv.slice(2);
if (!root) {
  console.error('usage: node t18-cross-family.mjs <repo-root> [<out-root>]');
  process.exit(2);
}
const COOKBOOK = join(root, 'crates/polyjose/tests/third_party/ietf-jose-cookbook/jwe');
const WYCHEPROOF = join(root, 'crates/polyjose/tests/third_party/wycheproof');
const OUT = join(outRoot, 'conformance/vectors/jwe');

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
    out.push(createHash('sha256').update(`polyjose 0003 T18 ${label} ${i}`).digest());
  }
  return Buffer.concat(out).subarray(0, len);
}
/** `buf` with bit 0 of octet `index` flipped (negative index: from the end). */
function flip(buf, index) {
  const b = Buffer.from(buf);
  const i = index < 0 ? b.length + index : index;
  b[i] ^= 0x01;
  return b;
}
const flipB64u = (s, index) => b64u(flip(unb64u(s), index));
const ORACLE = `Node.js ${process.versions.node} node:crypto (OpenSSL ${process.versions.openssl})`;

// ---- primitives (RFC 7518), all from node:crypto ---------------------------------------------
const CEK_LEN = { A128GCM: 16, A192GCM: 24, A256GCM: 32, 'A128CBC-HS256': 32, 'A192CBC-HS384': 48, 'A256CBC-HS512': 64 };
const IV_LEN = (enc) => (enc.endsWith('GCM') ? 12 : 16);

/** RFC 7518 §5.2.2.1 (AES_CBC_HMAC_SHA2) and §5.3 (AES GCM): [ciphertext, tag]. */
function contentEncrypt(enc, cek, iv, aad, pt) {
  if (enc.endsWith('GCM')) {
    const c = createCipheriv(`aes-${cek.length * 8}-gcm`, cek, iv, { authTagLength: 16 });
    c.setAAD(aad);
    const ct = Buffer.concat([c.update(pt), c.final()]);
    return [ct, c.getAuthTag()];
  }
  const half = cek.length / 2;
  const mac = cek.subarray(0, half);
  const key = cek.subarray(half);
  const c = createCipheriv(`aes-${half * 8}-cbc`, key, iv);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  const al = Buffer.alloc(8);
  al.writeBigUInt64BE(BigInt(aad.length * 8));
  const hash = { 16: 'sha256', 24: 'sha384', 32: 'sha512' }[half];
  const tag = createHmac(hash, mac).update(Buffer.concat([aad, iv, ct, al])).digest().subarray(0, half);
  return [ct, tag];
}

/** RFC 7518 §4.4 / RFC 3394: AES Key Wrap with the default IV. */
function aesKw(kek, cek) {
  const c = createCipheriv(`id-aes${kek.length * 8}-wrap`, kek, Buffer.from('A6A6A6A6A6A6A6A6', 'hex'));
  return Buffer.concat([c.update(cek), c.final()]);
}

/** RFC 7518 §4.7.1: AES GCM key wrapping (96-bit IV, 128-bit tag, empty AAD). */
function gcmKw(kek, iv, cek) {
  const c = createCipheriv(`aes-${kek.length * 8}-gcm`, kek, iv, { authTagLength: 16 });
  const ct = Buffer.concat([c.update(cek), c.final()]);
  return { encryptedKey: ct, tag: c.getAuthTag() };
}

/** RFC 7518 §4.7.1 unwrap, used only to cross-check cookbook values. */
function gcmKwUnwrap(kek, iv, tag, encryptedKey) {
  const d = createDecipheriv(`aes-${kek.length * 8}-gcm`, kek, iv, { authTagLength: 16 });
  d.setAuthTag(tag);
  return Buffer.concat([d.update(encryptedKey), d.final()]);
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

/** A compact JWE (RFC 7516 §7.1) from a protected header object and raw parts. */
function compact(header, encryptedKey, iv, ct, tag) {
  return [b64u(utf8(JSON.stringify(header))), b64u(encryptedKey), b64u(iv), b64u(ct), b64u(tag)].join('.');
}

/** A compact JWE with its protected header replaced by `header` (JSON.stringify order). */
function reprotect(token, header) {
  const parts = token.split('.');
  parts[0] = b64u(utf8(JSON.stringify(header)));
  return parts.join('.');
}
const protectedOf = (token) => JSON.parse(unb64u(token.split('.')[0]).toString('utf8'));

// ---- inputs ----------------------------------------------------------------------------------
const cook = (name) => JSON.parse(readFileSync(join(COOKBOOK, name), 'utf8'));
const c53 = cook('5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json');
const c54 = cook('5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json');
const c55 = cook('5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json');
const c56 = cook('5_6.direct_encryption_using_aes-gcm.json');
const c57 = cook('5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json');
const c59 = cook('5_9.compressed_content.json');
const c513 = cook('5_13.encrypting_to_multiple_recipients.json');

function wycheproof(file, tcId, comment) {
  const doc = JSON.parse(readFileSync(join(WYCHEPROOF, file), 'utf8'));
  for (const g of doc.testGroups) {
    for (const t of g.tests) {
      if (t.tcId === tcId) {
        if (t.comment !== comment || t.result !== 'invalid') throw new Error(`${file} tcId ${tcId}: ${t.comment}`);
        const { kty, crv, x, y } = t.public;
        return { kty, crv, x, y };
      }
    }
  }
  throw new Error(`${file}: no tcId ${tcId}`);
}

// ---- output ----------------------------------------------------------------------------------
const files = [];
function write(dir, name, v) {
  const ordered = { source: v.source, description: v.description, operation: v.operation, input: v.input, expect: v.expect };
  if (v.features) ordered.features = v.features;
  mkdirSync(join(OUT, dir), { recursive: true });
  const rel = `${dir}/${name}.json`;
  if (files.includes(rel)) throw new Error(`written twice: ${rel}`);
  writeFileSync(join(OUT, rel), JSON.stringify(ordered, null, 2) + '\n');
  files.push(rel);
}
const ok = (pt, recipient = 0) => ({ ok: true, plaintext_b64u: b64u(pt), recipient });
const fails = (error) => ({ ok: false, error });
const decrypt = (jwe, key, algs, encs, extra = {}) => ({ jwe, key, allowed_algs: algs, allowed_enc: encs, ...extra });

// =============================================================================================
// RFC 7520 §5.13: general JSON, three recipients (RSA1_5, ECDH-ES+A256KW on P-384, A256GCMKW),
// shared unprotected cty.
// =============================================================================================
const M = 'rfc7520-multi';
const m513 = c513.output.json;
const pt513 = utf8(c513.input.plaintext);
const [rsa513, ec513, aes513] = c513.input.key;
const algs513 = c513.input.alg; // RSA1_5, ECDH-ES+A256KW, A256GCMKW
const enc513 = c513.encrypting_content.protected.enc; // input.enc has the typo "A128CBC-H256"
if (JSON.stringify(algs513) !== '["RSA1_5","ECDH-ES+A256KW","A256GCMKW"]') throw new Error('5.13 algs');
if (m513.recipients.length !== 3 || m513.protected !== c513.encrypting_content.protected_b64u) throw new Error('5.13 shape');
if (enc513 !== 'A128CBC-HS256') throw new Error('5.13 enc');
// Independent cross-checks of the cookbook: recipient #3 unwraps to the CEK, and the content
// decrypts (the tag is recomputed over AAD = ASCII(protected), RFC 7516 §5.1 step 14).
{
  const cek = unb64u(c513.generated.cek);
  const h3 = m513.recipients[2].header;
  const unwrapped = gcmKwUnwrap(unb64u(aes513.k), unb64u(h3.iv), unb64u(h3.tag), unb64u(m513.recipients[2].encrypted_key));
  if (!unwrapped.equals(cek)) throw new Error('5.13 recipient #3 does not unwrap to the CEK');
  const [ct, tag] = contentEncrypt(enc513, cek, unb64u(m513.iv), Buffer.from(m513.protected, 'ascii'), pt513);
  if (b64u(ct) !== m513.ciphertext || b64u(tag) !== m513.tag) throw new Error('5.13 content');
}
const rsa513Public = { kty: rsa513.kty, kid: rsa513.kid, use: rsa513.use, n: rsa513.n, e: rsa513.e };
const ec513Public = { kty: ec513.kty, kid: ec513.kid, use: ec513.use, crv: ec513.crv, x: ec513.x, y: ec513.y };
const with513 = (f) => {
  const j = structuredClone(m513);
  f(j);
  return j;
};

write(M, 'rfc7520-5-13-ec-key-decrypts-recipient-1', {
  source: 'RFC 7520 §5.13',
  description:
    'The RFC 7520 §5.13 general JSON JWE (RSA1_5, ECDH-ES+A256KW on P-384 and A256GCMKW recipients, shared unprotected cty) decrypts with recipient #2\'s P-384 private key to the Figure 72 plaintext as recipient 1: RSA1_5 is unsupported and A256GCMKW does not fit an EC key, so ECDH-ES+A256KW is the only candidate (RFC 7516 §5.2 step 6; plan.md recipient selection; generated from the ietf-jose cookbook)',
  operation: 'jwe.decrypt',
  input: decrypt(m513, ec513, algs513, [enc513]),
  expect: ok(pt513, 1),
});
write(M, 'rfc7520-5-13-aes-key-decrypts-recipient-2', {
  source: 'RFC 7520 §5.13',
  description:
    'The RFC 7520 §5.13 general JSON JWE decrypts with recipient #3\'s A256GCMKW key (iv and tag in its per-recipient header) to the Figure 72 plaintext as recipient 2 (RFC 7516 §5.2 step 6, RFC 7518 §4.7; generated from the ietf-jose cookbook)',
  operation: 'jwe.decrypt',
  input: decrypt(m513, aes513, algs513, [enc513]),
  expect: ok(pt513, 2),
});
write(M, 'rfc7520-5-13-rsa-key-only-unsupported', {
  source: 'RFC 7520 §5.13',
  description:
    'The RFC 7520 §5.13 general JSON JWE with only recipient #1\'s RSA key (its public members): RSA1_5 is not implemented (ADR 0022) and the other two recipients do not fit an RSA key, so there is no candidate and the best error is UnsupportedAlgorithm (plan.md recipient selection; generated from the ietf-jose cookbook)',
  operation: 'jwe.decrypt',
  input: decrypt(m513, rsa513Public, algs513, [enc513]),
  expect: fails('UnsupportedAlgorithm'),
});
write(M, 'rfc7520-5-13-ec-key-alg-not-allowed', {
  source: 'RFC 7520 §5.13',
  description:
    'RFC 8725 §3.1: the RFC 7520 §5.13 JWE with recipient #2\'s P-384 key and only A256GCMKW allowed has no candidate (RSA1_5 unsupported, ECDH-ES+A256KW not allowed, A256GCMKW not an EC algorithm), and AlgorithmNotAllowed ranks first (plan.md recipient selection; generated from the ietf-jose cookbook)',
  operation: 'jwe.decrypt',
  input: decrypt(m513, ec513, ['A256GCMKW'], [enc513]),
  expect: fails('AlgorithmNotAllowed'),
});
write(M, 'rfc7520-5-13-tampered-tag-ec-key', {
  source: 'RFC 7520 §5.13',
  description:
    'RFC 7516 §5.2 step 16, §11.5: the RFC 7520 §5.13 JWE with one bit of the shared Authentication Tag flipped is DecryptionFailed with recipient #2\'s key: its only candidate unwraps the CEK and then fails the tag (generated from the ietf-jose cookbook)',
  operation: 'jwe.decrypt',
  input: decrypt(with513((j) => { j.tag = flipB64u(j.tag, -1); }), ec513, algs513, [enc513]),
  expect: fails('DecryptionFailed'),
});
{
  // Without the RSA1_5 recipient (polyjose does not encrypt to RSA1_5, ADR 0022), the same draws
  // reproduce recipients #2 and #3 and the shared content exactly: the content depends only on
  // the protected header, the CEK, the IV and the plaintext (RFC 7516 §5.1 steps 9-15).
  const k1 = c513.encrypting_key[1];
  const k2 = c513.encrypting_key[2];
  if (JSON.stringify(k1.header.epk) !== JSON.stringify({ kty: k1.epk.kty, crv: k1.epk.crv, x: k1.epk.x, y: k1.epk.y })) throw new Error('5.13 epk');
  if (k2.iv !== m513.recipients[2].header.iv) throw new Error('5.13 iv');
  const rng = Buffer.concat([unb64u(c513.generated.cek), unb64u(k1.epk.d), unb64u(k2.iv), unb64u(c513.generated.iv)]);
  write(M, 'rfc7520-5-13-without-rsa-recipient-encrypt', {
    source: 'RFC 7520 §5.13',
    description:
      'Encrypting to recipients #2 (ECDH-ES+A256KW, P-384) and #3 (A256GCMKW) of RFC 7520 §5.13, with its random values as the drawn bytes (CEK, then the 48-octet ephemeral d, accepted on the first draw, then the 96-bit key-wrap IV, then the content IV), kid in each per-recipient header and its shared unprotected cty, reproduces the RFC 7520 §5.13 general JSON JWE exactly with recipient #1 (RSA1_5, not implemented, ADR 0022) left out: alg and the key management parameters go in each recipient\'s header and enc in the protected header, as in the RFC (RFC 7516 §7.2.1; generated from the ietf-jose cookbook)',
    operation: 'jwe.encrypt',
    input: {
      serialization: 'general',
      enc: enc513,
      plaintext_b64u: b64u(pt513),
      recipients: [
        { alg: algs513[1], key: ec513Public, header: { kid: ec513.kid } },
        { alg: algs513[2], key: aes513, header: { kid: aes513.kid } },
      ],
      protected_b64u: m513.protected,
      unprotected: m513.unprotected,
      rng_b64u: b64u(rng),
    },
    expect: { ok: true, jwe: with513((j) => { j.recipients = j.recipients.slice(1); }) },
    features: ['fixed-rng'],
  });
}

// =============================================================================================
// negative-crypto/: cross-family negatives (see conformance/vectors/jwe/README.md for the cases
// that already live in other directories and are not repeated here).
// =============================================================================================
const N = 'negative-crypto';

// ---- tampered tag, ciphertext and IV for every enc, on dir tokens built here ------------------
// Already elsewhere: A128CBC-HS256 tag/ciphertext/IV (negative-structure/tampered-*.json) and the
// A128GCM tag (negative-structure/dir-tampered-gcm-tag.json).
const ALREADY = new Set(['A128CBC-HS256 tag', 'A128CBC-HS256 ciphertext', 'A128CBC-HS256 iv', 'A128GCM tag']);
for (const enc of ['A128GCM', 'A192GCM', 'A256GCM', 'A192CBC-HS384', 'A256CBC-HS512']) {
  const slug = enc.toLowerCase();
  const cek = derive(`dir ${enc} key`, CEK_LEN[enc]);
  const iv = derive(`dir ${enc} iv`, IV_LEN(enc));
  const pt = utf8(`RFC 7516 §5.2 with dir + ${enc}: any change to the IV, the ciphertext or the tag is DecryptionFailed.`);
  const header = { alg: 'dir', enc };
  const aad = Buffer.from(b64u(utf8(JSON.stringify(header))), 'ascii');
  const [ct, tag] = contentEncrypt(enc, cek, iv, aad, pt);
  const token = compact(header, Buffer.alloc(0), iv, ct, tag);
  const key = { kty: 'oct', k: b64u(cek) };
  const how = enc.endsWith('GCM') ? 'RFC 7518 §5.3' : 'RFC 7518 §5.2.2.2';
  write(N, `dir-${slug}-decrypts`, {
    source: 'polyjose',
    description: `RFC 7516 §5.2, RFC 7518 §4.5 and ${how}: the untampered compact dir + ${enc} JWE the tamper vectors of this enc start from decrypts (built with ${ORACLE}, independently of polyjose)`,
    operation: 'jwe.decrypt',
    input: decrypt(token, key, ['dir'], [enc]),
    expect: ok(pt),
  });
  const parts = token.split('.');
  for (const [what, index, octet] of [['iv', 2, 0], ['ciphertext', 3, 0], ['tag', 4, -1]]) {
    if (ALREADY.has(`${enc} ${what}`)) continue;
    const tampered = [...parts];
    tampered[index] = flipB64u(parts[index], octet);
    const name = { iv: 'IV', ciphertext: 'ciphertext', tag: 'Authentication Tag' }[what];
    write(N, `dir-${slug}-tampered-${what}`, {
      source: 'polyjose',
      description: `RFC 7516 §5.2 step 16, §11.5 and ${how}: the dir + ${enc} JWE of dir-${slug}-decrypts with one bit of its ${name} flipped is DecryptionFailed, the one detail-free error (built with ${ORACLE}, independently of polyjose)`,
      operation: 'jwe.decrypt',
      input: decrypt(tampered.join('.'), key, ['dir'], [enc]),
      expect: fails('DecryptionFailed'),
    });
  }
}

// ---- alg or enc not allowed, per family, on RFC 7520 tokens -----------------------------------
// Already elsewhere: A128KW (negative-structure/alg-not-allowed.json, enc-not-allowed.json).
const pwd53 = { kty: 'oct', k: b64u(utf8(c53.input.pwd)) };
for (const [slug, sec, token, key, alg, allowed, enc] of [
  ['dir', '§5.6', c56.output.compact, c56.input.key, 'dir', 'A128GCMKW', c56.input.enc],
  ['a256gcmkw', '§5.7', c57.output.compact, c57.input.key, 'A256GCMKW', 'A256KW', c57.input.enc],
  ['pbes2-hs512-a256kw', '§5.3', c53.output.compact, pwd53, 'PBES2-HS512+A256KW', 'PBES2-HS256+A128KW', c53.input.enc],
  ['ecdh-es-a128kw', '§5.4', c54.output.compact, c54.input.key, 'ECDH-ES+A128KW', 'ECDH-ES', c54.input.enc],
  ['ecdh-es', '§5.5', c55.output.compact, c55.input.key, 'ECDH-ES', 'ECDH-ES+A128KW', c55.input.enc],
]) {
  if (protectedOf(token).alg !== alg) throw new Error(`${sec} alg`);
  write(N, `alg-not-allowed-${slug}`, {
    source: `RFC 7520 ${sec}`,
    description: `RFC 8725 §3.1, RFC 7516 §5.2 step 6: the RFC 7520 ${sec} compact JWE (${alg}) with only ${allowed} allowed is AlgorithmNotAllowed, before its key is bound (plan.md error order; generated from the ietf-jose cookbook)`,
    operation: 'jwe.decrypt',
    input: decrypt(token, key, [allowed], [enc]),
    expect: fails('AlgorithmNotAllowed'),
  });
}
for (const [slug, sec, token, key, alg, enc, allowedEnc] of [
  ['a128gcm-dir', '§5.6', c56.output.compact, c56.input.key, 'dir', 'A128GCM', 'A256GCM'],
  ['a128cbc-hs256-ecdh-es', '§5.5', c55.output.compact, c55.input.key, 'ECDH-ES', 'A128CBC-HS256', 'A256CBC-HS512'],
]) {
  if (protectedOf(token).enc !== enc) throw new Error(`${sec} enc`);
  write(N, `enc-not-allowed-${slug}`, {
    source: `RFC 7520 ${sec}`,
    description: `RFC 8725 §3.1: the RFC 7520 ${sec} compact JWE (${alg} + ${enc}) with only ${allowedEnc} allowed as enc is AlgorithmNotAllowed (generated from the ietf-jose cookbook)`,
    operation: 'jwe.decrypt',
    input: decrypt(token, key, [alg], [allowedEnc]),
    expect: fails('AlgorithmNotAllowed'),
  });
}

// ---- invalid epk on P-384 and P-521 (P-256 and X25519: ecdh-es/epk-*.json, x25519-epk-*.json) --
function epkVector(name, source, base, key, alg, enc, epk, why) {
  const h = protectedOf(base);
  if (!h.epk || h.alg !== alg) throw new Error(`${name}: base`);
  h.epk = epk;
  write(N, name, {
    source,
    description: why,
    operation: 'jwe.decrypt',
    input: decrypt(reprotect(base, h), key, [alg], [enc]),
    expect: fails('DecryptionFailed'),
  });
}
// P-384: the RFC 7520 §5.4 JWE (ECDH-ES+A128KW + A128GCM) and its recipient key.
{
  const base = c54.output.compact;
  const epk = protectedOf(base).epk;
  const W = 'ecdh_secp384r1_webcrypto_test.json';
  const cases = [
    ['epk-p384-not-on-curve', wycheproof(W, 788, 'public point not on curve'), 'RFC 8725 §3.4, RFC 7518 §4.6.1.1: a P-384 "epk" that is not on the curve (Wycheproof ecdh_secp384r1_webcrypto tcId 788, "public point not on curve")'],
    ['epk-p384-identity', wycheproof(W, 789, 'public point = (0,0)'), 'RFC 8725 §3.4, ADR 0041 §4: a P-384 "epk" of (0, 0), the identity spelled in affine coordinates and off the curve (Wycheproof ecdh_secp384r1_webcrypto tcId 789)'],
    ['epk-p384-coordinates-above-p', wycheproof(W, 782, 'point is not on curve'), 'RFC 7518 §6.2.1.2, SEC 1 §2.3.6: a P-384 "epk" whose x and y are 2^384 - 1, above the field prime (Wycheproof ecdh_secp384r1_webcrypto tcId 782, InvalidCurveAttack)'],
    ['epk-p384-short-x', { kty: 'EC', crv: 'P-384', x: b64u(unb64u(epk.x).subarray(1)), y: epk.y }, 'RFC 7518 §6.2.1.2 ("MUST be the full size of a coordinate"): the RFC 7520 §5.4 "epk" with its x cut to 47 octets'],
  ];
  for (const [name, point, why] of cases) {
    epkVector(name, 'RFC 7520 §5.4', base, c54.input.key, c54.input.alg, c54.input.enc, point,
      `${why} in the RFC 7520 §5.4 JWE is DecryptionFailed with the §5.4 recipient key, before any key agreement result is used (generated from the ietf-jose cookbook)`);
  }
}
// P-521: an ECDH-ES+A256KW + A256GCM JWE built here to the T13 P-521 test key.
{
  const recipient = JSON.parse(readFileSync(join(root, 'conformance/tools/jwe/t13-p521-key.json'), 'utf8'));
  const P = (1n << 521n) - 1n; // the P-521 field prime (FIPS 186-4 D.1.2.5)
  const bigOf = (b) => BigInt(`0x${b.toString('hex')}`);
  const bytesOf = (n, len) => Buffer.from(n.toString(16).padStart(len * 2, '0'), 'hex');
  // An ephemeral key whose x has a zero first octet, so the 65-octet short x below is the same
  // number: only the length is wrong. d < 2^520 < n, so it is a valid scalar.
  let eph;
  for (let i = 0; ; i++) {
    const d = derive(`p521 ephemeral ${i}`, 66);
    d[0] = 0;
    const ecdh = createECDH('secp521r1');
    ecdh.setPrivateKey(d);
    const pub = ecdh.getPublicKey(null, 'uncompressed');
    if (pub[1] === 0) {
      eph = { ecdh, x: pub.subarray(1, 67), y: pub.subarray(67) };
      break;
    }
  }
  const z = eph.ecdh.computeSecret(Buffer.concat([Buffer.from([4]), unb64u(recipient.x), unb64u(recipient.y)]));
  const kek = concatKdf(z, 'ECDH-ES+A256KW', 256);
  const cek = derive('p521 cek', 32);
  const iv = derive('p521 iv', 12);
  const header = { alg: 'ECDH-ES+A256KW', enc: 'A256GCM', epk: { kty: 'EC', crv: 'P-521', x: b64u(eph.x), y: b64u(eph.y) } };
  const pt = utf8('RFC 7518 §4.6 on P-521: the ephemeral public key must be a full-length point on the curve.');
  const [ct, tag] = contentEncrypt('A256GCM', cek, iv, Buffer.from(b64u(utf8(JSON.stringify(header))), 'ascii'), pt);
  const base = compact(header, aesKw(kek, cek), iv, ct, tag);
  const key = { kty: 'EC', crv: 'P-521', x: recipient.x, y: recipient.y, d: recipient.d };
  write(N, 'ecdh-es-a256kw-p521-decrypts', {
    source: 'polyjose',
    description: `RFC 7518 §4.6: the untampered compact ECDH-ES+A256KW + A256GCM JWE to the P-521 test key (conformance/tools/jwe/t13-p521-key.json) that the P-521 "epk" vectors start from decrypts; its epk x has a zero first octet (built with ${ORACLE}, independently of polyjose)`,
    operation: 'jwe.decrypt',
    input: decrypt(base, key, ['ECDH-ES+A256KW'], ['A256GCM']),
    expect: ok(pt),
  });
  const W = 'ecdh_secp521r1_webcrypto_test.json';
  const aliased = bigOf(eph.x) + P;
  if (aliased >= 1n << 528n) throw new Error('aliased x does not fit 66 octets');
  const cases = [
    ['epk-p521-not-on-curve', wycheproof(W, 649, 'public point not on curve'), 'RFC 8725 §3.4, RFC 7518 §4.6.1.1: a P-521 "epk" that is not on the curve (Wycheproof ecdh_secp521r1_webcrypto tcId 649, "public point not on curve")'],
    ['epk-p521-identity', wycheproof(W, 650, 'public point = (0,0)'), 'RFC 8725 §3.4, ADR 0041 §4: a P-521 "epk" of (0, 0), the identity spelled in affine coordinates and off the curve (Wycheproof ecdh_secp521r1_webcrypto tcId 650)'],
    ['epk-p521-x-aliased-by-p', { ...header.epk, x: b64u(bytesOf(aliased, 66)) }, 'RFC 7518 §6.2.1.2, SEC 1 §2.3.6: the "epk" of ecdh-es-a256kw-p521-decrypts with x + p in place of x (66 octets, the same point modulo p, but not a field element below p)'],
    ['epk-p521-short-x', { ...header.epk, x: b64u(eph.x.subarray(1)) }, 'RFC 7518 §6.2.1.2 ("MUST be the full size of a coordinate"): the "epk" of ecdh-es-a256kw-p521-decrypts with its zero first octet dropped, so x is the same number in 65 octets instead of 66'],
  ];
  for (const [name, point, why] of cases) {
    epkVector(name, 'polyjose', base, key, 'ECDH-ES+A256KW', 'A256GCM', point,
      `${why} is DecryptionFailed with the P-521 recipient key (built with ${ORACLE}, independently of polyjose)`);
  }
}

// ---- missing and extra recipients, on RFC 7520 §5.13 ------------------------------------------
// Already elsewhere: recipients [] and over max_recipients (negative-json/recipients-empty.json,
// over-max-recipients.json), flattened with recipients (negative-json/flattened-with-recipients.json).
write(N, 'rfc7520-5-13-recipient-for-key-removed', {
  source: 'RFC 7520 §5.13',
  description:
    'RFC 7516 §5.2 step 6: the RFC 7520 §5.13 JWE with recipient #3 (A256GCMKW) removed leaves no candidate for its AES key (RSA1_5 unsupported, ECDH-ES+A256KW not an oct algorithm); UnsupportedAlgorithm ranks above KeyAlgorithmMismatch (plan.md recipient selection; generated from the ietf-jose cookbook)',
  operation: 'jwe.decrypt',
  input: decrypt(with513((j) => { j.recipients = j.recipients.slice(0, 2); }), aes513, algs513, [enc513]),
  expect: fails('UnsupportedAlgorithm'),
});
write(N, 'rfc7520-5-13-encrypted-key-removed', {
  source: 'RFC 7520 §5.13',
  description:
    'RFC 7516 §5.2 steps 6-10, RFC 7518 §4.7: the RFC 7520 §5.13 JWE with recipient #3\'s encrypted_key member removed (an empty JWE Encrypted Key, RFC 7516 §7.2.1) is DecryptionFailed with its AES key: the GCM key unwrap of nothing fails its tag (generated from the ietf-jose cookbook)',
  operation: 'jwe.decrypt',
  input: decrypt(with513((j) => { delete j.recipients[2].encrypted_key; }), aes513, algs513, [enc513]),
  expect: fails('DecryptionFailed'),
});
write(N, 'rfc7520-5-13-extra-forged-recipient-first', {
  source: 'RFC 7520 §5.13',
  description:
    'RFC 7516 §5.2 step 6 ("an attacker can add recipients"): the RFC 7520 §5.13 JWE with a copy of recipient #3 whose encrypted_key has one bit flipped added in front still decrypts with recipient #3\'s AES key, now as recipient 3: the forged candidate fails its key unwrap and is passed over (plan.md recipient selection; generated from the ietf-jose cookbook)',
  operation: 'jwe.decrypt',
  input: decrypt(
    with513((j) => {
      const forged = structuredClone(j.recipients[2]);
      forged.encrypted_key = flipB64u(forged.encrypted_key, 0);
      j.recipients.unshift(forged);
    }),
    aes513, algs513, [enc513]),
  expect: ok(pt513, 3),
});

// =============================================================================================
// Deferred vectors (T10, T14, T15)
// =============================================================================================

// ---- RFC 7520 §5.7 flattened, with the erratum 4802 tag ---------------------------------------
{
  const flat = c57.output.json_flat;
  const tag = c57.encrypting_content.tag;
  // Erratum 4802: the RFC's printed flattened example (§5.7.5) carries a different protected
  // header and tag; the cookbook's json_flat has the compact form's protected header and tag.
  if (flat.protected !== c57.encrypting_content.protected_b64u || flat.tag !== tag || c57.output.compact.split('.')[4] !== tag) {
    throw new Error('5.7 flattened is not the erratum 4802 form');
  }
  const cek = unb64u(c57.generated.cek);
  const kw = gcmKw(unb64u(c57.input.key.k), unb64u(c57.encrypting_key.iv), cek);
  if (b64u(kw.encryptedKey) !== flat.encrypted_key || b64u(kw.tag) !== c57.encrypting_key.tag) throw new Error('5.7 key wrap');
  const [ct, t] = contentEncrypt(c57.input.enc, cek, unb64u(flat.iv), Buffer.from(flat.protected, 'ascii'), utf8(c57.input.plaintext));
  if (b64u(ct) !== flat.ciphertext || b64u(t) !== tag) throw new Error('5.7 content');
  const src = 'RFC 7520 §5.7, erratum 4802';
  write('json', 'rfc7520-5-7-a256gcmkw-a128cbc-hs256-flattened-decrypt', {
    source: src,
    description: `The RFC 7520 §5.7 flattened JSON JWE (A256GCMKW + A128CBC-HS256, alg, kid, iv and tag in the protected header), as corrected by erratum 4802 (the compact form's protected header and the tag ${tag}), decrypts with the §5.7 key to the Figure 72 plaintext (generated from the ietf-jose cookbook; tag recomputed with ${ORACLE})`,
    operation: 'jwe.decrypt',
    input: decrypt(flat, c57.input.key, [c57.input.alg], [c57.input.enc]),
    expect: ok(utf8(c57.input.plaintext)),
  });
  write('json', 'rfc7520-5-7-a256gcmkw-a128cbc-hs256-flattened-encrypt', {
    source: src,
    description: `Encrypting with the RFC 7520 §5.7 random values as the drawn bytes (CEK, then the 96-bit key-wrap IV, then the content IV) and its protected header (kid in the protected header) reproduces the RFC 7520 §5.7 flattened JSON JWE exactly, in its erratum 4802 form (tag ${tag})`,
    operation: 'jwe.encrypt',
    input: {
      serialization: 'flattened',
      enc: c57.input.enc,
      plaintext_b64u: b64u(utf8(c57.input.plaintext)),
      recipients: [{ alg: c57.input.alg, key: c57.input.key }],
      protected: { kid: c57.input.key.kid },
      protected_b64u: flat.protected,
      rng_b64u: b64u(Buffer.concat([cek, unb64u(c57.encrypting_key.iv), unb64u(flat.iv)])),
    },
    expect: { ok: true, jwe: flat },
    features: ['fixed-rng'],
  });
}

// ---- RFC 7520 §5.9 in both JSON forms ---------------------------------------------------------
for (const [form, jwe] of [['flattened', c59.output.json_flat], ['general', c59.output.json]]) {
  if ((jwe.protected ?? '') !== c59.encrypting_content.protected_b64u) throw new Error('5.9 protected');
  write('zip', `rfc7520-5-9-a128kw-a128gcm-def-${form}-decrypt`, {
    source: 'RFC 7520 §5.9',
    description: `The RFC 7520 §5.9 ${form} JSON JWE (A128KW + A128GCM, zip DEF in the protected header) decrypts with the §5.9 key and inflates (RFC 7516 §5.2 step 17) to the Figure 72 plaintext (generated from the ietf-jose cookbook)`,
    operation: 'jwe.decrypt',
    input: decrypt(jwe, c59.input.key, [c59.input.alg], [c59.input.enc]),
    expect: ok(utf8(c59.input.plaintext)),
    features: ['deflate'],
  });
}

// ---- A256GCMKW with iv and tag in the per-recipient header ------------------------------------
{
  // RFC 7516 §7.2.1: iv and tag (RFC 7518 §4.7.1) are header parameters and may be in the
  // per-recipient unprotected header. The GCM tag authenticates the wrapped CEK under that iv,
  // so they stay integrity-protected there. Values: RFC 7520 §5.7's key, CEK, IVs and plaintext,
  // with only enc in the protected header, so the content tag is recomputed here.
  const key = c57.input.key;
  const cek = unb64u(c57.generated.cek);
  const kwIv = unb64u(c57.encrypting_key.iv);
  const kw = gcmKw(unb64u(key.k), kwIv, cek);
  if (b64u(kw.encryptedKey) !== c57.encrypting_key.encrypted_key || b64u(kw.tag) !== c57.encrypting_key.tag) throw new Error('5.7 key wrap');
  const enc = c57.input.enc;
  const iv = unb64u(c57.generated.iv);
  const pt = utf8(c57.input.plaintext);
  const protectedB64 = b64u(utf8(JSON.stringify({ enc })));
  const [ct, tag] = contentEncrypt(enc, cek, iv, Buffer.from(protectedB64, 'ascii'), pt);
  const header = { alg: 'A256GCMKW', kid: key.kid, iv: b64u(kwIv), tag: b64u(kw.tag) };
  const general = {
    protected: protectedB64,
    recipients: [{ header, encrypted_key: b64u(kw.encryptedKey) }],
    iv: b64u(iv),
    ciphertext: b64u(ct),
    tag: b64u(tag),
  };
  const flattened = {
    protected: protectedB64,
    header,
    encrypted_key: b64u(kw.encryptedKey),
    iv: b64u(iv),
    ciphertext: b64u(ct),
    tag: b64u(tag),
  };
  const built = `built with ${ORACLE} from the RFC 7520 §5.7 key, CEK, IVs and plaintext, independently of polyjose`;
  write('gcmkw', 'per-recipient-iv-tag-general-decrypt', {
    source: 'RFC 7518 §4.7.1',
    description: `RFC 7516 §7.2.1, RFC 7518 §4.7.1: a general JSON A256GCMKW + A128CBC-HS256 JWE with alg, kid, iv and tag in the per-recipient header (only enc protected) decrypts to the Figure 72 plaintext as recipient 0 (${built})`,
    operation: 'jwe.decrypt',
    input: decrypt(general, key, ['A256GCMKW'], [enc]),
    expect: ok(pt),
  });
  write('gcmkw', 'per-recipient-iv-tag-flattened-decrypt', {
    source: 'RFC 7518 §4.7.1',
    description: `RFC 7516 §7.2.2, RFC 7518 §4.7.1: the same JWE in the flattened form, alg, kid, iv and tag in its (per-recipient) header member, decrypts to the Figure 72 plaintext (${built})`,
    operation: 'jwe.decrypt',
    input: decrypt(flattened, key, ['A256GCMKW'], [enc]),
    expect: ok(pt),
  });
  for (const [what, name] of [['iv', 'IV'], ['tag', 'authentication tag']]) {
    const tampered = structuredClone(general);
    tampered.recipients[0].header[what] = flipB64u(header[what], what === 'iv' ? 0 : -1);
    write('gcmkw', `per-recipient-${what}-tampered`, {
      source: 'RFC 7518 §4.7.1',
      description: `RFC 7518 §4.7.1, RFC 7516 §11.5: per-recipient-iv-tag-general-decrypt with one bit of the key-wrap ${name} in the per-recipient header flipped is DecryptionFailed: the unprotected ${what} is still bound by the GCM key wrap (${built})`,
      operation: 'jwe.decrypt',
      input: decrypt(tampered, key, ['A256GCMKW'], [enc]),
      expect: fails('DecryptionFailed'),
    });
  }
  write('gcmkw', 'per-recipient-iv-tag-general-encrypt', {
    source: 'RFC 7518 §4.7.1',
    description: `Encrypting to the RFC 7520 §5.7 key in the general form with kid in the per-recipient header and the §5.7 random values as the drawn bytes (CEK, then the 96-bit key-wrap IV, then the content IV) reproduces per-recipient-iv-tag-general-decrypt exactly: polyjose puts alg, iv and tag in the recipient's header and only enc in the protected header (RFC 7516 §7.2.1; expected value ${built})`,
    operation: 'jwe.encrypt',
    input: {
      serialization: 'general',
      enc,
      plaintext_b64u: b64u(pt),
      recipients: [{ alg: 'A256GCMKW', key, header: { kid: key.kid } }],
      protected_b64u: protectedB64,
      rng_b64u: b64u(Buffer.concat([cek, kwIv, iv])),
    },
    expect: { ok: true, jwe: general },
    features: ['fixed-rng'],
  });
}

console.log(`${files.length} vectors:\n${files.join('\n')}`);
