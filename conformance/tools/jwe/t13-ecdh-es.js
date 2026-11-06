// Independent oracle for the T13 ECDH-ES conformance vectors: Node's own
// crypto (OpenSSL), not RustCrypto. Usage: node t13-ecdh-es.js <cookbook-jwe-dir> <out-dir>
// The P-521 recipient and the other P-384 key are read from t13-p521-key.json and
// t13-p384-key.json (test-only keys, their d already in the committed vectors).
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const [cookbookDir, outDir] = process.argv.slice(2);
const b64u = (b) => Buffer.from(b).toString('base64url');
const unb64u = (s) => Buffer.from(s, 'base64url');
const be32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const lp = (b) => Buffer.concat([be32(b.length), b]);

function concatKdf(z, algId, apu, apv, bits) {
  const other = Buffer.concat([lp(Buffer.from(algId, 'ascii')), lp(apu), lp(apv), be32(bits)]);
  let out = Buffer.alloc(0);
  for (let i = 1; out.length < bits / 8; i++) {
    out = Buffer.concat([out, crypto.createHash('sha256').update(Buffer.concat([be32(i), z, other])).digest()]);
  }
  return out.subarray(0, bits / 8);
}

const CEK_LEN = { 'A128GCM': 16, 'A192GCM': 24, 'A256GCM': 32, 'A128CBC-HS256': 32, 'A192CBC-HS384': 48, 'A256CBC-HS512': 64 };
const IV_LEN = (enc) => (enc.endsWith('GCM') ? 12 : 16);
const KW_BITS = { 'ECDH-ES+A128KW': 128, 'ECDH-ES+A192KW': 192, 'ECDH-ES+A256KW': 256 };
const CURVE = { 'P-256': ['prime256v1', 32], 'P-384': ['secp384r1', 48], 'P-521': ['secp521r1', 66] };

function contentEncrypt(enc, cek, iv, aad, pt) {
  if (enc.endsWith('GCM')) {
    const c = crypto.createCipheriv(`aes-${cek.length * 8}-gcm`, cek, iv);
    c.setAAD(aad);
    const ct = Buffer.concat([c.update(pt), c.final()]);
    return [ct, c.getAuthTag()];
  }
  // RFC 7518 §5.2.2.1
  const half = cek.length / 2;
  const mac = cek.subarray(0, half), key = cek.subarray(half);
  const c = crypto.createCipheriv(`aes-${half * 8}-cbc`, key, iv);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  const al = Buffer.alloc(8); al.writeBigUInt64BE(BigInt(aad.length * 8));
  const hash = { 16: 'sha256', 24: 'sha384', 32: 'sha512' }[half];
  const m = crypto.createHmac(hash, mac).update(Buffer.concat([aad, iv, ct, al])).digest();
  return [ct, m.subarray(0, half)];
}

function aesKw(kek, cek) {
  const c = crypto.createCipheriv(`id-aes${kek.length * 8}-wrap`, kek, Buffer.from('A6A6A6A6A6A6A6A6', 'hex'));
  return Buffer.concat([c.update(cek), c.final()]);
}

/** Ephemeral key and Z, by Node: EC through ECDH, X25519 through KeyObjects. */
function agree(recipient, ephD) {
  if (recipient.kty === 'EC') {
    const [name, len] = CURVE[recipient.crv];
    const ecdh = crypto.createECDH(name);
    ecdh.setPrivateKey(ephD);
    const pub = ecdh.getPublicKey(null, 'uncompressed');
    const peer = Buffer.concat([Buffer.from([4]), unb64u(recipient.x), unb64u(recipient.y)]);
    const z = ecdh.computeSecret(peer);
    if (z.length !== len) throw new Error('Z length');
    return [{ kty: 'EC', crv: recipient.crv, x: b64u(pub.subarray(1, 1 + len)), y: b64u(pub.subarray(1 + len)) }, z];
  }
  // RFC 8037 §3.2 / RFC 7748 §6.1. PKCS#8 wrapper of a raw X25519 key.
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), ephD]);
  const priv = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const x = crypto.createPublicKey(priv).export({ format: 'jwk' }).x;
  const peer = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: recipient.x }, format: 'jwk' });
  return [{ kty: 'OKP', crv: 'X25519', x }, crypto.diffieHellman({ privateKey: priv, publicKey: peer })];
}

/** A compact ECDH-ES JWE with polyjose's header order; returns token and rng bytes. */
function encrypt({ alg, enc, recipient, ephD, cek, iv, apu, apv, pt }) {
  const [epk, z] = agree(recipient, ephD);
  const header = { alg, enc, epk };
  if (apu) header.apu = b64u(apu);
  if (apv) header.apv = b64u(apv);
  const protectedB64 = b64u(JSON.stringify(header));
  let ek = Buffer.alloc(0), rng;
  if (alg === 'ECDH-ES') {
    cek = concatKdf(z, enc, apu || Buffer.alloc(0), apv || Buffer.alloc(0), CEK_LEN[enc] * 8);
    rng = Buffer.concat([ephD, iv]);
  } else {
    const kek = concatKdf(z, alg, apu || Buffer.alloc(0), apv || Buffer.alloc(0), KW_BITS[alg]);
    ek = aesKw(kek, cek);
    rng = Buffer.concat([cek, ephD, iv]);
  }
  const [ct, tag] = contentEncrypt(enc, cek, iv, Buffer.from(protectedB64, 'ascii'), pt);
  return { token: [protectedB64, b64u(ek), b64u(iv), b64u(ct), b64u(tag)].join('.'), rng, protectedB64 };
}

const written = [];
function write(name, vector) {
  const file = path.join(outDir, `${name}.json`);
  fs.writeFileSync(file, JSON.stringify(vector, null, 2) + '\n');
  written.push(name);
}

const ALL_ALGS = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];
const pub = (k) => { const { d, ...rest } = k; return rest; };

function decryptVector(name, source, description, token, key, alg, enc, pt) {
  write(name, {
    source, description, operation: 'jwe.decrypt',
    input: { jwe: token, key, allowed_algs: [alg], allowed_enc: [enc] },
    expect: { ok: true, plaintext_b64u: b64u(pt), recipient: 0 },
  });
}

function failDecrypt(name, description, token, key, error = 'DecryptionFailed', source = 'polyjose') {
  write(name, {
    source, description, operation: 'jwe.decrypt',
    input: { jwe: token, key, allowed_algs: ALL_ALGS, allowed_enc: Object.keys(CEK_LEN) },
    expect: { ok: false, error },
  });
}

// --- RFC 7520 §5.4 and §5.5 from the cookbook --------------------------------
for (const [file, sec, slug] of [
  ['5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json', '5.4', 'ecdh-es-a128kw-p384-a128gcm'],
  ['5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json', '5.5', 'ecdh-es-p256-a128cbc-hs256'],
]) {
  const c = JSON.parse(fs.readFileSync(path.join(cookbookDir, file), 'utf8'));
  const { alg, enc, key, plaintext } = c.input;
  const pt = Buffer.from(plaintext, 'utf8');
  decryptVector(`rfc7520-${sec.replace('.', '-')}-${slug}-decrypt`, `RFC 7520 §${sec}`,
    `The RFC 7520 §${sec} compact JWE (${alg}, ${enc}) decrypts with the recipient's private key (RFC 7518 §4.6)`,
    c.output.compact, key, alg, enc, pt);
  // Independent re-derivation of the RFC output from its printed values.
  const ephD = unb64u(c.encrypting_key.epk.d);
  const cek = c.generated.cek ? unb64u(c.generated.cek) : undefined;
  const [epk] = agree(key, ephD);
  if (epk.x !== c.encrypting_key.epk.x || epk.y !== c.encrypting_key.epk.y) throw new Error(`${sec}: epk`);
  const rng = Buffer.concat([...(cek ? [cek] : []), ephD, unb64u(c.generated.iv)]);
  const what = cek ? 'CEK, then the ephemeral d, then the IV' : 'the ephemeral d, then the IV';
  write(`rfc7520-${sec.replace('.', '-')}-${slug}-encrypt`, {
    source: `RFC 7520 §${sec}`,
    description: `Encrypting with the RFC 7520 §${sec} random values as the drawn bytes (${what}; the d is accepted on the first draw) and its protected header (kid in the protected header) reproduces the RFC 7520 §${sec} compact JWE exactly`,
    operation: 'jwe.encrypt',
    input: {
      serialization: 'compact', enc, plaintext_b64u: b64u(pt),
      recipients: [{ alg, key: pub(key) }],
      protected: { kid: key.kid },
      protected_b64u: c.encrypting_content.protected_b64u,
      rng_b64u: b64u(rng),
    },
    expect: { ok: true, jwe: c.output.compact },
    features: ['fixed-rng'],
  });
}

// --- KATs computed by this oracle -------------------------------------------
const PT = Buffer.from('Live long and prosper.', 'utf8');
// RFC 7748 §6.1 Alice (ephemeral) and Bob (recipient).
const ALICE_X25519_D = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex');
const BOB_X25519 = { kty: 'OKP', crv: 'X25519', x: b64u(Buffer.from('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex')), d: b64u(Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex')) };
// RFC 7518 Appendix C.
const APPC_ALICE_D = unb64u('0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo');
const APPC_BOB = { kty: 'EC', crv: 'P-256', x: 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ', y: 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck', d: 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw' };
const fixed = (n, byte) => Buffer.alloc(n, byte);

// A P-521 recipient key, made once by Node and kept in the vectors.
const p521File = path.join(__dirname, 't13-p521-key.json');
let P521;
if (fs.existsSync(p521File)) P521 = JSON.parse(fs.readFileSync(p521File, 'utf8'));
else {
  P521 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-521' }).privateKey.export({ format: 'jwk' });
  fs.writeFileSync(p521File, JSON.stringify(P521));
}
P521 = { kty: 'EC', crv: 'P-521', x: P521.x, y: P521.y, d: P521.d };
const P521_EPH_D = Buffer.concat([Buffer.from([0x01]), Buffer.alloc(65, 0x23)]);

const kats = [
  { name: 'kat-x25519-ecdh-es-a128gcm', alg: 'ECDH-ES', enc: 'A128GCM', recipient: BOB_X25519, ephD: ALICE_X25519_D, iv: fixed(12, 0x31), src: 'RFC 7748 §6.1 keys' },
  { name: 'kat-x25519-ecdh-es-a128kw-a128cbc-hs256', alg: 'ECDH-ES+A128KW', enc: 'A128CBC-HS256', recipient: BOB_X25519, ephD: ALICE_X25519_D, cek: fixed(32, 0x41), iv: fixed(16, 0x32), src: 'RFC 7748 §6.1 keys' },
  { name: 'kat-x25519-ecdh-es-a192kw-a192gcm', alg: 'ECDH-ES+A192KW', enc: 'A192GCM', recipient: BOB_X25519, ephD: ALICE_X25519_D, cek: fixed(24, 0x42), iv: fixed(12, 0x33), apu: Buffer.from('Alice'), apv: Buffer.from('Bob'), src: 'RFC 7748 §6.1 keys' },
  { name: 'kat-x25519-ecdh-es-a256kw-a256cbc-hs512', alg: 'ECDH-ES+A256KW', enc: 'A256CBC-HS512', recipient: BOB_X25519, ephD: ALICE_X25519_D, cek: fixed(64, 0x43), iv: fixed(16, 0x34), src: 'RFC 7748 §6.1 keys' },
  { name: 'kat-p256-rfc7518-appc-ecdh-es-a128gcm', alg: 'ECDH-ES', enc: 'A128GCM', recipient: APPC_BOB, ephD: APPC_ALICE_D, iv: fixed(12, 0x35), apu: Buffer.from('Alice'), apv: Buffer.from('Bob'), src: 'RFC 7518 Appendix C keys' },
  { name: 'kat-p521-ecdh-es-a256kw-a256gcm', alg: 'ECDH-ES+A256KW', enc: 'A256GCM', recipient: P521, ephD: P521_EPH_D, cek: fixed(32, 0x44), iv: fixed(12, 0x36), src: 'a Node-generated P-521 key' },
];
const tokens = {};
for (const k of kats) {
  const { token, rng } = encrypt({ ...k, pt: PT });
  tokens[k.name] = token;
  const party = k.apu ? ', apu "Alice" and apv "Bob"' : '';
  write(`${k.name}-encrypt`, {
    source: 'polyjose',
    description: `RFC 7518 §4.6 ${k.alg} with ${k.enc} on ${k.recipient.crv} (${k.src}${party}), the drawn bytes in the documented order: the exact compact JWE, computed independently with Node.js crypto (OpenSSL)`,
    operation: 'jwe.encrypt',
    input: {
      serialization: 'compact', enc: k.enc, plaintext_b64u: b64u(PT),
      recipients: [{ alg: k.alg, key: pub(k.recipient), ...(k.apu ? { apu_b64u: b64u(k.apu) } : {}), ...(k.apv ? { apv_b64u: b64u(k.apv) } : {}) }],
      rng_b64u: b64u(rng),
    },
    expect: { ok: true, jwe: token },
    features: ['fixed-rng'],
  });
  decryptVector(`${k.name}-decrypt`, 'polyjose',
    `RFC 7518 §4.6: the ${k.alg} ${k.enc} JWE on ${k.recipient.crv} computed with Node.js crypto decrypts with the recipient's private key`,
    token, k.recipient, k.alg, k.enc, PT);
}

// --- Round trips on the OS CSPRNG ------------------------------------------
const c54key = JSON.parse(fs.readFileSync(path.join(cookbookDir, '5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json'), 'utf8')).input.key;
for (const [name, alg, enc, key, apu] of [
  ['roundtrip-p256-ecdh-es-a256gcm', 'ECDH-ES', 'A256GCM', APPC_BOB, null],
  ['roundtrip-p384-ecdh-es-a192kw-a192cbc-hs384', 'ECDH-ES+A192KW', 'A192CBC-HS384', c54key, Buffer.from('producer')],
  ['roundtrip-p521-ecdh-es-a128kw-a256cbc-hs512', 'ECDH-ES+A128KW', 'A256CBC-HS512', P521, null],
  ['roundtrip-x25519-ecdh-es-a256cbc-hs512', 'ECDH-ES', 'A256CBC-HS512', BOB_X25519, Buffer.from('producer')],
]) {
  write(name, {
    source: 'polyjose',
    description: `RFC 7516 §5.1/§5.2: a compact ${alg} + ${enc} encryption to a ${key.crv} public key on the OS CSPRNG (RFC 7518 §4.6, a fresh ephemeral key) decrypts with the private key to the plaintext`,
    operation: 'jwe.encrypt',
    input: {
      serialization: 'compact', enc, plaintext_b64u: b64u(PT),
      recipients: [{ alg, key: pub(key), ...(apu ? { apu_b64u: b64u(apu) } : {}) }],
    },
    expect: { ok: true, decrypt_with: { key, allowed_algs: [alg], allowed_enc: [enc] } },
  });
}

// --- Negative decrypt: invalid epk and encrypted key -------------------------
const base = tokens['kat-p256-rfc7518-appc-ecdh-es-a128gcm'].split('.');
const withHeader = (h, ek = '') => [b64u(JSON.stringify(h)), ek, base[2], base[3], base[4]].join('.');
const AX = 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0', AY = 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps';
const ec = (x, y, crv = 'P-256') => ({ kty: 'EC', crv, x, y });
const hdr = (epk) => (epk ? { alg: 'ECDH-ES', enc: 'A128GCM', epk } : { alg: 'ECDH-ES', enc: 'A128GCM' });
const Z43 = 'A'.repeat(43);
const negatives = [
  ['epk-missing', 'RFC 7518 §4.6.1.1: an ECDH-ES JWE without "epk" ("MUST be present") is DecryptionFailed', hdr(null)],
  ['epk-private-d', 'RFC 7518 §4.6.1.1: an "epk" carrying the private member d ("MUST contain only public key parameters") is DecryptionFailed', hdr({ ...ec(AX, AY), d: '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo' })],
  ['epk-kty-mismatch', 'RFC 7518 §4.6, RFC 8725 §3.4: an OKP X25519 "epk" for a P-256 recipient key is DecryptionFailed', hdr({ kty: 'OKP', crv: 'X25519', x: BOB_X25519.x })],
  ['epk-crv-mismatch', 'RFC 7518 §4.6, RFC 8725 §3.4: a valid P-384 "epk" (RFC 7520 §5.4) for a P-256 recipient key is DecryptionFailed', hdr(ec('uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3', 'sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-JdaY8tb7E0', 'P-384'))],
  ['epk-short-coordinate', 'RFC 7518 §6.2.1.2: an "epk" whose x is 31 octets instead of the full 32 is DecryptionFailed', hdr(ec(AX.slice(0, 42).replace(/.$/, 'Q'), AY))],
  ['epk-off-curve', 'RFC 8725 §3.4, ADR 0041 §4: an "epk" point off P-256 (the RFC 7518 App. C point with y changed) is DecryptionFailed', hdr(ec(AX, 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFppo'))],
  ['epk-identity', 'RFC 8725 §3.4, ADR 0041 §4: an "epk" of (0, 0), the identity spelled in affine coordinates and off P-256, is DecryptionFailed', hdr(ec(Z43, Z43))],
  ['epk-invalid-curve-point', 'RFC 8725 §2.5/§3.4 (invalid-curve attack, CVE-2017-16007): an "epk" on y^2 = x^3 - 3x + b\' over the P-256 field, b\' != b, is DecryptionFailed', hdr(ec('axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY', 'T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfY'))],
  ['epk-twist-point', 'RFC 8725 §3.4 (Sanso 2017): an "epk" that is a low-order point of the quadratic twist of P-256 (Wycheproof ecdh_secp256r1_ecpoint tcId 350) is DecryptionFailed', hdr(ec('793jsyhyqe_887lMv3Oqezn5aD7OkSG5hSFn9OPaYJs', '6rahtGMUwhn3AU4EFtzM7Ice2VkxZ8AgMIZQw-EQ6Uo'))],
];
for (const [name, description, h] of negatives) failDecrypt(name, description, withHeader(h), APPC_BOB);
failDecrypt('direct-non-empty-encrypted-key',
  'RFC 7516 §5.2 step 10: the RFC 7518 App. C keyed ECDH-ES JWE with a one-octet JWE Encrypted Key (it must be empty for Direct Key Agreement) is DecryptionFailed',
  [base[0], 'AA', base[2], base[3], base[4]].join('.'), APPC_BOB);
const xBase = tokens['kat-x25519-ecdh-es-a128gcm'].split('.');
for (const [name, u, what] of [
  ['x25519-epk-low-order', 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'the point of order 8 (Wycheproof x25519 LowOrderPublic)'],
  ['x25519-epk-zero', '0000000000000000000000000000000000000000000000000000000000000000', 'u = 0 (Wycheproof x25519 LowOrderPublic)'],
]) {
  const h = { alg: 'ECDH-ES', enc: 'A128GCM', epk: { kty: 'OKP', crv: 'X25519', x: b64u(Buffer.from(u, 'hex')) } };
  failDecrypt(name, `RFC 7748 §6.1, ADR 0043 §2: an X25519 "epk" of ${what} gives the all-zero shared secret, which is rejected: DecryptionFailed`,
    [b64u(JSON.stringify(h)), '', xBase[2], xBase[3], xBase[4]].join('.'), BOB_X25519);
}
{
  const h = { alg: 'ECDH-ES', enc: 'A128GCM', epk: { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' } };
  failDecrypt('x25519-epk-ed25519', 'RFC 8037 §3.2: an Ed25519 "epk" ("MUST NOT be used for ECDH-ES") for an X25519 recipient key is DecryptionFailed',
    [b64u(JSON.stringify(h)), '', xBase[2], xBase[3], xBase[4]].join('.'), BOB_X25519);
}
{
  const c55 = JSON.parse(fs.readFileSync(path.join(cookbookDir, '5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json'), 'utf8'));
  failDecrypt('rfc7520-5-5-public-key-cannot-decrypt', 'RFC 7518 §4.6: the RFC 7520 §5.5 JWE with only the public part of the recipient key has no candidate key: KeyAlgorithmMismatch',
    c55.output.compact, pub(c55.input.key), 'KeyAlgorithmMismatch', 'RFC 7520 §5.5');
  const c54 = JSON.parse(fs.readFileSync(path.join(cookbookDir, '5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json'), 'utf8'));
  const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey.export({ format: 'jwk' });
  const otherFile = path.join(__dirname, 't13-p384-key.json');
  const p384 = fs.existsSync(otherFile) ? JSON.parse(fs.readFileSync(otherFile, 'utf8')) : (fs.writeFileSync(otherFile, JSON.stringify(other)), other);
  failDecrypt('rfc7520-5-4-wrong-key', 'RFC 3394 §2.2.3: the RFC 7520 §5.4 JWE with another P-384 private key fails the key unwrap integrity check: DecryptionFailed',
    c54.output.compact, { kty: 'EC', crv: 'P-384', x: p384.x, y: p384.y, d: p384.d }, 'DecryptionFailed', 'RFC 7520 §5.4');
}

// --- Negative encrypt -------------------------------------------------------
for (const alg of ['ECDH-ES', 'ECDH-ES+A128KW']) {
  write(`encrypt-apu-equals-apv-${alg === 'ECDH-ES' ? 'direct' : 'a128kw'}`, {
    source: 'polyjose',
    description: `RFC 7518 §4.6.2 ("The "apu" and "apv" values MUST be distinct, when used"): encrypting ${alg} with apu equal to apv is InvalidFormat`,
    operation: 'jwe.encrypt',
    input: { serialization: 'compact', enc: 'A128GCM', plaintext_b64u: b64u(PT), recipients: [{ alg, key: pub(APPC_BOB), apu_b64u: b64u('same'), apv_b64u: b64u('same') }] },
    expect: { ok: false, error: 'InvalidFormat' },
  });
}
write('encrypt-direct-two-recipients', {
  source: 'polyjose',
  description: 'RFC 7516 §5.1 step 5, RFC 7518 §4.6: Direct Key Agreement fixes the CEK from one recipient, so a general JSON ECDH-ES encryption to two recipients is InvalidFormat',
  operation: 'jwe.encrypt',
  input: { serialization: 'general', enc: 'A128GCM', plaintext_b64u: b64u(PT), recipients: [{ alg: 'ECDH-ES', key: pub(APPC_BOB) }, { alg: 'ECDH-ES', key: pub(BOB_X25519) }] },
  expect: { ok: false, error: 'InvalidFormat' },
});
write('encrypt-ed25519-key', {
  source: 'polyjose',
  description: 'RFC 8037 §3.2 (Ed25519 "MUST NOT be used for ECDH-ES"), RFC 8725 §3.1: encrypting ECDH-ES to an Ed25519 key is KeyAlgorithmMismatch',
  operation: 'jwe.encrypt',
  input: { serialization: 'compact', enc: 'A128GCM', plaintext_b64u: b64u(PT), recipients: [{ alg: 'ECDH-ES', key: { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' } }] },
  expect: { ok: false, error: 'KeyAlgorithmMismatch' },
});
console.log(written.length, 'vectors:', written.join(' '));
