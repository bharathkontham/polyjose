// Two-way interop of @polyjose/node with panva/jose 6.x (feature 0010 I1).
//
// polyjose → jose: polyjose signs or encrypts with keys it generated, and jose verifies or decrypts
// with the JWKs polyjose exported. jose → polyjose: jose signs or encrypts with keys it generated,
// and polyjose verifies or decrypts with the JWKs jose exported (RFC 7517 §4), always under an
// explicit allow-list, never trusting the header `alg` (RFC 8725 §3.1, ADR 0007). Each case also
// flips one bit of the signature (RFC 7515 §5.2 step 8) or the authentication tag (RFC 7516 §5.2
// step 14) and expects the consumer to reject it. Both libraries are called with explicit
// algorithm lists on every verify and decrypt (jose: `algorithms`, `keyManagementAlgorithms`,
// `contentEncryptionAlgorithms`, which PBES2 requires in jose 6).
//
// @polyjose/node is the package built from this tree (bindings/node, by interop/node/test.sh); jose
// is the exact version pinned in package.json and package-lock.json. All keys are generated here,
// at run time, for this run only. JWT times are fixed (`now` / `currentDate`), never the clock.
//
// Not covered, with the reason:
// - ES256K (RFC 8812 §3.2): polyjose supports it; jose 6 does not (its JWS table has no secp256k1).
// - RSA key generation: polyjose has none (ADR 0067 §3), so every RSA case (RS*, PS*, RSA-OAEP-256,
//   both directions) uses a key pair jose generated; polyjose imports its exported private JWK.
// - RSA-OAEP (SHA-1), RSA-OAEP-384/512: jose 6 supports them; polyjose does not (ADR 0022, ADR 0067
//   §3: RSA-OAEP-256 only). RSA1_5 (RFC 7518 §4.2): neither (RFC 8725 §3.2 advice; jose 6 has none).
// - ML-DSA-44/65/87: jose 6 only; polyjose 0.1.0 has no ML-DSA.
// - Ed448, X448 (RFC 8037): neither library.
// - zip: "DEF" (RFC 7516 §4.1.3): the bindings build without polyjose's `deflate` feature.
// - Unencoded payloads, b64: false (RFC 7797): jose rejects them in the compact form (research.md
//   §2.1), and this suite tests the compact serializations only.
import { assert, test } from "../../bindings/js/dist/node/builtins.js";
import * as pj from "../../bindings/node/index.js";
import type { JwkObject } from "../../bindings/node/index.js";
import * as jose from "jose";

const enc = new TextEncoder();
const PAYLOAD = enc.encode('{"interop":"polyjose ⇄ jose","n":42}');
type JoseKey = jose.CryptoKey | Uint8Array | jose.JWK;

/** The fixed "current time" of every JWT check, in seconds since the epoch (RFC 7519 §2). */
const NOW = 1_800_000_000;
const CLAIMS = { iss: "https://issuer.example", aud: "interop", sub: "alice", iat: NOW - 60, nbf: NOW - 60, exp: NOW + 600 };

const asJwk = (k: JwkObject): jose.JWK => k as unknown as jose.JWK;
const asPj = (k: jose.JWK): JwkObject => k as unknown as JwkObject;

/** Flips the low bit of the first byte of compact segment `index`, re-encoded canonically. */
function flipBit(token: string, index: number): string {
  const parts = token.split(".");
  const bytes = jose.base64url.decode(parts[index] ?? "");
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  parts[index] = jose.base64url.encode(bytes);
  return parts.join(".");
}

/** Asserts that `p` rejects with a jose error of this `code`. */
async function joseRejects(p: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(p, (e: unknown) => (e as { code?: unknown }).code === code);
}

/** Asserts that `p` rejects with a PolyjoseError of this `code` (ADR 0030 §5). */
async function polyjoseRejects(p: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(p, (e: unknown) => e instanceof pj.PolyjoseError && e.code === code);
}

// --- JWS (RFC 7515 §5, RFC 7518 §3, RFC 8037 §3.1, RFC 9864 §2.2) ---------------------------------

const BOTH_WAYS_JWS = ["HS256", "HS384", "HS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"];
/** RSA signatures (RFC 7518 §3.3, §3.5), both ways with jose-generated keys (ADR 0067 §2, §3). */
const RSA_JWS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];

for (const alg of BOTH_WAYS_JWS) {
  test(`JWS ${alg}: polyjose signs, jose verifies`, async () => {
    const priv = await pj.jwkGenerateForAlg(alg);
    const pub = alg.startsWith("HS") ? priv : await pj.jwkToPublic(priv);
    const header = { alg, kid: `pj-${alg}` };
    const token = await pj.jwsSignCompact(PAYLOAD, priv, { protectedHeader: header });

    const out = await jose.compactVerify(token, asJwk(pub), { algorithms: [alg] });
    assert.deepEqual(out.payload, PAYLOAD);
    assert.deepEqual(out.protectedHeader, header);
    await joseRejects(jose.compactVerify(flipBit(token, 2), asJwk(pub), { algorithms: [alg] }), "ERR_JWS_SIGNATURE_VERIFICATION_FAILED");
  });
}

for (const alg of RSA_JWS) {
  test(`JWS ${alg}: polyjose signs with a jose RSA private JWK, jose verifies`, async () => {
    const pair = await jose.generateKeyPair(alg, { extractable: true });
    const priv = asPj(await jose.exportJWK(pair.privateKey));
    const header = { alg, kid: `pj-${alg}` };
    const token = await pj.jwsSignCompact(PAYLOAD, priv, { protectedHeader: header });

    const out = await jose.compactVerify(token, pair.publicKey, { algorithms: [alg] });
    assert.deepEqual(out.payload, PAYLOAD);
    assert.deepEqual(out.protectedHeader, header);
    await joseRejects(jose.compactVerify(flipBit(token, 2), pair.publicKey, { algorithms: [alg] }), "ERR_JWS_SIGNATURE_VERIFICATION_FAILED");
    // The same through a JWT (RFC 7519 §7.1): polyjose issues, jose validates.
    const jwt = await pj.jwtSign(CLAIMS, priv, { alg });
    const claims = await jose.jwtVerify(jwt, pair.publicKey, { algorithms: [alg], currentDate: new Date(NOW * 1000) });
    assert.deepEqual(claims.payload, CLAIMS);
  });
}

for (const alg of [...BOTH_WAYS_JWS, ...RSA_JWS]) {
  test(`JWS ${alg}: jose signs, polyjose verifies`, async () => {
    let signKey: JoseKey;
    let verifyJwk: jose.JWK;
    if (alg.startsWith("HS")) {
      signKey = await jose.generateSecret(alg, { extractable: true });
      verifyJwk = await jose.exportJWK(signKey);
    } else {
      const pair = await jose.generateKeyPair(alg, { extractable: true });
      signKey = pair.privateKey;
      verifyJwk = await jose.exportJWK(pair.publicKey);
    }
    const header = { alg, kid: `jose-${alg}` };
    const token = await new jose.CompactSign(PAYLOAD).setProtectedHeader(header).sign(signKey);

    const out = await pj.jwsVerifyCompact(token, asPj(verifyJwk), { allowedAlgs: [alg] });
    assert.equal(out.alg, alg);
    assert.deepEqual(out.payload, PAYLOAD);
    assert.deepEqual(out.protectedHeader, header);
    await polyjoseRejects(pj.jwsVerifyCompact(flipBit(token, 2), asPj(verifyJwk), { allowedAlgs: [alg] }), "InvalidSignature");
  });
}

// --- JWE (RFC 7516 §5, RFC 7518 §4-§5) ----------------------------------------------------------

const ENCS = ["A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"];
/** CEK octets per `enc` (RFC 7518 §5.2.3-§5.2.5, §5.3): the `dir` key length. */
const CEK_LEN: Record<string, number> = {
  A128GCM: 16,
  A192GCM: 24,
  A256GCM: 32,
  "A128CBC-HS256": 32,
  "A192CBC-HS384": 48,
  "A256CBC-HS512": 64,
};
/** PBES2 password and count: p2c within both libraries' default bound (ADR 0023: 10,000). */
const PASSWORD = enc.encode("correct horse battery staple, interop only");
const P2C = 2048;

interface JweCase {
  alg: string;
  enc: string;
  /** The curve of an ECDH-ES case (RFC 7518 §4.6, RFC 8037 §3.2). */
  crv?: string;
}

const jweCases: JweCase[] = [];
for (const e of ENCS) jweCases.push({ alg: "dir", enc: e });
const others: Omit<JweCase, "enc">[] = [
  ...["A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW"].map((alg) => ({ alg })),
  ...["P-256", "P-384", "P-521", "X25519"].flatMap((crv) =>
    ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"].map((alg) => ({ alg, crv })),
  ),
  ...["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"].map((alg) => ({ alg })),
];
// Each other alg with one enc, in turn, so every enc meets every alg family.
others.forEach((c, i) => jweCases.push({ ...c, enc: ENCS[i % ENCS.length] ?? "A128GCM" }));

const name = (c: JweCase): string => `${c.alg}${c.crv ? ` (${c.crv})` : ""} / ${c.enc}`;
const octLen = (alg: string): number => Number(alg.slice(1, 4)) / 8;

/** polyjose-generated keys: the one polyjose encrypts to, and the one jose decrypts with. */
async function polyjoseKeys(c: JweCase): Promise<{ encrypt: JwkObject; decrypt: JoseKey }> {
  if (c.alg === "dir") {
    const k = await pj.jwkGenerateOct(CEK_LEN[c.enc] ?? 0);
    return { encrypt: k, decrypt: asJwk(k) };
  }
  if (c.alg.startsWith("PBES2")) {
    return { encrypt: { kty: "oct", k: jose.base64url.encode(PASSWORD) }, decrypt: PASSWORD };
  }
  if (c.crv) {
    const priv = c.crv === "X25519" ? await pj.jwkGenerateOkp("X25519") : await pj.jwkGenerateEc(c.crv as "P-256" | "P-384" | "P-521");
    return { encrypt: await pj.jwkToPublic(priv), decrypt: asJwk(priv) };
  }
  const k = await pj.jwkGenerateOct(octLen(c.alg));
  return { encrypt: k, decrypt: asJwk(k) };
}

/** jose-generated keys: the one jose encrypts with, and its JWK export polyjose decrypts with. */
async function joseKeys(c: JweCase): Promise<{ encrypt: JoseKey; decrypt: JwkObject }> {
  if (c.alg.startsWith("PBES2")) {
    return { encrypt: PASSWORD, decrypt: { kty: "oct", k: jose.base64url.encode(PASSWORD) } };
  }
  if (c.crv) {
    const pair = await jose.generateKeyPair(c.alg, { crv: c.crv, extractable: true });
    return { encrypt: pair.publicKey, decrypt: asPj(await jose.exportJWK(pair.privateKey)) };
  }
  const secret = await jose.generateSecret(c.alg === "dir" ? c.enc : c.alg, { extractable: true });
  return { encrypt: secret, decrypt: asPj(await jose.exportJWK(secret)) };
}

for (const c of jweCases) {
  test(`JWE ${name(c)}: polyjose encrypts, jose decrypts`, async () => {
    const keys = await polyjoseKeys(c);
    const token = await pj.jweEncryptCompact(PAYLOAD, {
      enc: c.enc,
      recipients: [{ alg: c.alg, key: keys.encrypt, ...(c.alg.startsWith("PBES2") ? { p2c: P2C } : {}) }],
      protectedHeader: { kid: "pj-jwe" },
    });
    const options = { keyManagementAlgorithms: [c.alg], contentEncryptionAlgorithms: [c.enc] };

    const out = await jose.compactDecrypt(token, keys.decrypt, options);
    assert.deepEqual(out.plaintext, PAYLOAD);
    assert.equal(out.protectedHeader.alg, c.alg);
    assert.equal(out.protectedHeader.enc, c.enc);
    assert.equal(out.protectedHeader.kid, "pj-jwe");
    assert.deepEqual(out.protectedHeader, jose.decodeProtectedHeader(token));
    await joseRejects(jose.compactDecrypt(flipBit(token, 4), keys.decrypt, options), "ERR_JWE_DECRYPTION_FAILED");
  });

  test(`JWE ${name(c)}: jose encrypts, polyjose decrypts`, async () => {
    const keys = await joseKeys(c);
    const builder = new jose.CompactEncrypt(PAYLOAD).setProtectedHeader({ alg: c.alg, enc: c.enc, kid: "jose-jwe" });
    if (c.alg.startsWith("PBES2")) builder.setKeyManagementParameters({ p2c: P2C });
    const token = await builder.encrypt(keys.encrypt);
    const options = { allowedAlgs: [c.alg], allowedEnc: [c.enc] };

    const out = await pj.jweDecryptCompact(token, keys.decrypt, options);
    assert.deepEqual(out.plaintext, PAYLOAD);
    assert.deepEqual(out.protectedHeader, jose.decodeProtectedHeader(token));
    await polyjoseRejects(pj.jweDecryptCompact(flipBit(token, 4), keys.decrypt, options), "DecryptionFailed");
  });
}

// RSA-OAEP-256 (RFC 7518 §4.3), both ways, with a jose key pair (polyjose generates no RSA keys).
for (const e of ["A256GCM", "A128CBC-HS256"]) {
  test(`JWE RSA-OAEP-256 / ${e}: polyjose encrypts, jose decrypts`, async () => {
    const pair = await jose.generateKeyPair("RSA-OAEP-256", { extractable: true });
    const pub = asPj(await jose.exportJWK(pair.publicKey));
    const token = await pj.jweEncryptCompact(PAYLOAD, { enc: e, recipients: [{ alg: "RSA-OAEP-256", key: pub }] });
    const options = { keyManagementAlgorithms: ["RSA-OAEP-256"], contentEncryptionAlgorithms: [e] };

    const out = await jose.compactDecrypt(token, pair.privateKey, options);
    assert.deepEqual(out.plaintext, PAYLOAD);
    assert.deepEqual(out.protectedHeader, { alg: "RSA-OAEP-256", enc: e });
    await joseRejects(jose.compactDecrypt(flipBit(token, 4), pair.privateKey, options), "ERR_JWE_DECRYPTION_FAILED");
  });

  test(`JWE RSA-OAEP-256 / ${e}: jose encrypts, polyjose decrypts with the exported private JWK`, async () => {
    const pair = await jose.generateKeyPair("RSA-OAEP-256", { extractable: true });
    const priv = asPj(await jose.exportJWK(pair.privateKey));
    const header = { alg: "RSA-OAEP-256", enc: e, kid: "jose-rsa" };
    const token = await new jose.CompactEncrypt(PAYLOAD).setProtectedHeader(header).encrypt(pair.publicKey);
    const options = { allowedAlgs: ["RSA-OAEP-256"], allowedEnc: [e] };

    const out = await pj.jweDecryptCompact(token, priv, options);
    assert.deepEqual(out.plaintext, PAYLOAD);
    assert.deepEqual(out.protectedHeader, jose.decodeProtectedHeader(token));
    // A bad tag and a bad Encrypted Key both fail as DecryptionFailed (RFC 7516 §11.5).
    await polyjoseRejects(pj.jweDecryptCompact(flipBit(token, 4), priv, options), "DecryptionFailed");
    await polyjoseRejects(pj.jweDecryptCompact(flipBit(token, 1), priv, options), "DecryptionFailed");
  });
}

// --- JWT (RFC 7519 §7.1-§7.2), with a fixed current time ------------------------------------------

for (const alg of ["HS256", "ES256"]) {
  test(`JWT ${alg}: polyjose issues, jose validates`, async () => {
    const priv = await pj.jwkGenerateForAlg(alg);
    const pub = alg === "HS256" ? priv : await pj.jwkToPublic(priv);
    const token = await pj.jwtSign(CLAIMS, priv, { alg });
    const options = { algorithms: [alg], issuer: CLAIMS.iss, audience: CLAIMS.aud, subject: CLAIMS.sub, typ: "JWT" };

    const out = await jose.jwtVerify(token, asJwk(pub), { ...options, currentDate: new Date(NOW * 1000) });
    assert.deepEqual(out.payload, CLAIMS);
    assert.deepEqual(out.protectedHeader, { alg, typ: "JWT" });
    await joseRejects(jose.jwtVerify(token, asJwk(pub), { ...options, currentDate: new Date((NOW + 3600) * 1000) }), "ERR_JWT_EXPIRED");
  });

  test(`JWT ${alg}: jose issues, polyjose validates`, async () => {
    let signKey: JoseKey;
    let verifyJwk: jose.JWK;
    if (alg === "HS256") {
      signKey = await jose.generateSecret(alg, { extractable: true });
      verifyJwk = await jose.exportJWK(signKey);
    } else {
      const pair = await jose.generateKeyPair(alg, { extractable: true });
      signKey = pair.privateKey;
      verifyJwk = await jose.exportJWK(pair.publicKey);
    }
    const token = await new jose.SignJWT(CLAIMS).setProtectedHeader({ alg, typ: "JWT" }).sign(signKey);
    const options = { allowedAlgs: [alg], issuers: [CLAIMS.iss], audiences: [CLAIMS.aud], subject: CLAIMS.sub };

    const out = await pj.jwtVerify(token, asPj(verifyJwk), { ...options, now: NOW });
    assert.deepEqual(out.claims, CLAIMS);
    assert.deepEqual(out.header, { alg, typ: "JWT" });
    assert.equal(out.alg, alg);
    await polyjoseRejects(pj.jwtVerify(token, asPj(verifyJwk), { ...options, now: NOW + 3600 }), "TokenExpired");
  });
}
