// Generates conformance/vectors/jwe/gcmkw/*.json for 0003 T10.
// Usage: node t10-gcmkw.mjs <cookbook 5_7 json> <output dir>
// RFC 7520 §5.7 values are read from the vendored cookbook (never typed in).
// Non-RFC tokens are built with node:crypto (OpenSSL), independently of polyjose,
// from deterministic SHA-256-derived bytes so a rerun gives identical files.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createCipheriv, createHash, createHmac } from "node:crypto";
import { join } from "node:path";

const [cookbookPath, outDir] = process.argv.slice(2);
const doc = JSON.parse(readFileSync(cookbookPath, "utf8"));
mkdirSync(outDir, { recursive: true });

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const unb64u = (s) => {
  const b = Buffer.from(s, "base64url");
  if (b64u(b) !== s) throw new Error("non-canonical base64url: " + s);
  return b;
};
const derive = (label, len) => {
  let out = Buffer.alloc(0);
  for (let i = 0; out.length < len; i++)
    out = Buffer.concat([out, createHash("sha256").update(`polyjose 0003 T10 ${label} ${i}`).digest()]);
  return out.subarray(0, len);
};
const ORACLE = `Node.js ${process.versions.node} node:crypto (OpenSSL ${process.versions.openssl})`;

// AES-GCM with a 96-bit IV and a 128-bit tag (RFC 7518 §4.7, §5.3).
function gcm(key, iv, aad, pt) {
  const c = createCipheriv(`aes-${key.length * 8}-gcm`, key, iv, { authTagLength: 16 });
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  return { ct, tag: c.getAuthTag() };
}

// A compact A*GCMKW + A*GCM JWE (RFC 7516 §5.1, RFC 7518 §4.7, §5.3).
function oracleToken(kek, enc, cek, wrapIv, contentIv, plaintext, extra = {}) {
  const wrap = gcm(kek, wrapIv, Buffer.alloc(0), cek);
  const header = { alg: `A${kek.length * 8}GCMKW`, enc, ...extra, iv: b64u(wrapIv), tag: b64u(wrap.tag) };
  const protectedB64 = b64u(Buffer.from(JSON.stringify(header)));
  const content = gcm(cek, contentIv, Buffer.from(protectedB64, "ascii"), plaintext);
  return {
    wrap,
    token: [protectedB64, b64u(wrap.ct), b64u(contentIv), b64u(content.ct), b64u(content.tag)].join("."),
  };
}

const octJwk = (bytes) => ({ kty: "oct", k: b64u(bytes) });
const files = [];
function write(name, vector) {
  const ordered = { source: vector.source, description: vector.description, operation: vector.operation, input: vector.input, expect: vector.expect };
  if (vector.features) ordered.features = vector.features;
  writeFileSync(join(outDir, name), JSON.stringify(ordered, null, 2) + "\n");
  files.push(name);
}
const decrypt = (source, description, jwe, key, alg, enc, expect) => ({
  source, description, operation: "jwe.decrypt",
  input: { jwe, key, allowed_algs: [alg], allowed_enc: [enc] }, expect,
});
const fails = (error) => ({ ok: false, error });

// ---------------------------------------------------------------- RFC 7520 §5.7
const key = doc.input.key;
const kek57 = unb64u(key.k);
const plaintext57 = Buffer.from(doc.input.plaintext, "utf8");
const compact = doc.output.compact;
const parts = compact.split(".");
const protected57 = JSON.parse(unb64u(parts[0]).toString("utf8"));
if (parts[0] !== doc.encrypting_content.protected_b64u) throw new Error("cookbook protected mismatch");
if (parts[1] !== doc.encrypting_key.encrypted_key) throw new Error("cookbook encrypted_key mismatch");
if (protected57.iv !== doc.encrypting_key.iv || protected57.tag !== doc.encrypting_key.tag) throw new Error("cookbook iv/tag mismatch");
// Cross-check the RFC's wrap with OpenSSL before using it.
const rfcWrap = gcm(kek57, unb64u(doc.encrypting_key.iv), Buffer.alloc(0), unb64u(doc.generated.cek));
if (b64u(rfcWrap.ct) !== parts[1] || b64u(rfcWrap.tag) !== protected57.tag) throw new Error("RFC 7520 §5.7 wrap does not match OpenSSL");

const A = "A256GCMKW", E = "A128CBC-HS256";
write("rfc7520-5-7-a256gcmkw-a128cbc-hs256-decrypt.json", decrypt(
  "RFC 7520 §5.7",
  "The RFC 7520 §5.7 compact JWE (A256GCMKW + A128CBC-HS256) decrypts with the RFC 7520 §5.7 key to the Figure 72 plaintext (§5.7.5 output; generated from the ietf-jose cookbook)",
  compact, key, A, E, { ok: true, plaintext_b64u: b64u(plaintext57), recipient: 0 }));

write("rfc7520-5-7-a256gcmkw-a128cbc-hs256-encrypt.json", {
  source: "RFC 7520 §5.7",
  description: "Encrypting with the RFC 7520 §5.7 random values as the drawn bytes (CEK, then the 96-bit key-wrap IV, then the content IV) and its protected header (kid, tag and iv in the protected header) reproduces the RFC 7520 §5.7 compact JWE exactly",
  operation: "jwe.encrypt",
  input: {
    serialization: "compact", enc: E, plaintext_b64u: b64u(plaintext57),
    recipients: [{ alg: A, key }],
    protected: { kid: key.kid },
    protected_b64u: parts[0],
    rng_b64u: b64u(Buffer.concat([unb64u(doc.generated.cek), unb64u(doc.encrypting_key.iv), unb64u(doc.generated.iv)])),
  },
  expect: { ok: true, jwe: compact },
  features: ["fixed-rng"],
});

// §5.7 with its protected header changed (every other segment kept).
const reheader = (header) => [b64u(Buffer.from(JSON.stringify(header))), ...parts.slice(1)].join(".");
const with57 = (changes) => {
  const h = { ...protected57 };
  for (const [k, v] of Object.entries(changes)) v === undefined ? delete h[k] : (h[k] = v);
  return reheader(h);
};
const neg = (name, description, jwe, error = "DecryptionFailed", k = key) =>
  write(name, decrypt("polyjose", description, jwe, k, A, E, fails(error)));

const iv57 = unb64u(protected57.iv), tag57 = unb64u(protected57.tag);
neg("reject-iv-missing.json", "RFC 7518 §4.7.1.1: the RFC 7520 §5.7 JWE with iv removed from its protected header is DecryptionFailed (iv MUST be present)", with57({ iv: undefined }));
neg("reject-tag-missing.json", "RFC 7518 §4.7.1.2: the RFC 7520 §5.7 JWE with tag removed from its protected header is DecryptionFailed (tag MUST be present)", with57({ tag: undefined }));
neg("reject-iv-not-base64url.json", "RFC 7518 §4.7.1.1, RFC 7515 §2: the RFC 7520 §5.7 JWE whose iv uses the base64 '/' instead of the base64url '_' is DecryptionFailed", with57({ iv: protected57.iv.replaceAll("_", "/") }));
neg("reject-tag-padded.json", "RFC 7518 §4.7.1.2, RFC 7515 §2: the RFC 7520 §5.7 JWE whose tag carries '==' padding is DecryptionFailed (base64url without padding)", with57({ tag: protected57.tag + "==" }));
neg("reject-iv-16-bytes.json", "RFC 7518 §4.7: the RFC 7520 §5.7 JWE with a 128-bit iv (its 96-bit IV plus four zero octets) is DecryptionFailed (a 96-bit IV is REQUIRED)", with57({ iv: b64u(Buffer.concat([iv57, Buffer.alloc(4)])) }));
neg("reject-tag-truncated-15-bytes.json", "RFC 7518 §4.7: the RFC 7520 §5.7 JWE with its key-wrap tag cut to its first 15 octets is DecryptionFailed (the tag MUST be 128 bits)", with57({ tag: b64u(tag57.subarray(0, 15)) }));
const flipped = Buffer.from(tag57); flipped[15] ^= 1;
neg("reject-tag-mismatch.json", "RFC 7518 §4.7, NIST SP 800-38D §7.2: the RFC 7520 §5.7 JWE with the last bit of its key-wrap tag flipped is DecryptionFailed", with57({ tag: b64u(flipped) }));
neg("reject-iv-tag-exchanged.json", "RFC 7518 §4.7.1: the RFC 7520 §5.7 JWE with the values of iv and tag exchanged is DecryptionFailed", with57({ iv: protected57.tag, tag: protected57.iv }));
neg("reject-iv-not-a-string.json", "RFC 7518 §4.7.1.1, RFC 7516 §5.2 step 4: the RFC 7520 §5.7 JWE with iv as a JSON number is InvalidHeader, found before key management", with57({ iv: 12 }), "InvalidHeader");
const ek = unb64u(parts[1]); ek[0] ^= 1;
neg("reject-encrypted-key-tampered.json", "RFC 7518 §4.7: the RFC 7520 §5.7 JWE with the first bit of its JWE Encrypted Key flipped is DecryptionFailed (the key-wrap tag fails)", [parts[0], b64u(ek), ...parts.slice(2)].join("."));
neg("reject-wrong-key.json", "RFC 7518 §4.7: the RFC 7520 §5.7 JWE decrypted with another 256-bit key is DecryptionFailed (the key-wrap tag fails)", compact, "DecryptionFailed", octJwk(derive("wrong kek", 32)));
neg("reject-key-too-short-for-alg.json", "RFC 7518 §4.7, RFC 8725 §3.1: the RFC 7520 §5.7 JWE (A256GCMKW) decrypted with a 128-bit oct key is KeyAlgorithmMismatch", compact, "KeyAlgorithmMismatch", octJwk(derive("short kek", 16)));

// Another valid wrap under the §5.7 key: its iv and tag in the §5.7 header.
const otherCek = derive("other cek", 32), otherIv = derive("other wrap iv", 12);
const other = oracleToken(kek57, "A256GCM", otherCek, otherIv, derive("other content iv", 12), Buffer.from("Another token under the RFC 7520 §5.7 key."), { kid: key.kid });
write("oracle-a256gcmkw-a256gcm-rfc7520-key-decrypt.json", decrypt(ORACLE,
  "RFC 7518 §4.7, §5.3: a compact A256GCMKW + A256GCM JWE built with OpenSSL under the RFC 7520 §5.7 key decrypts to its plaintext",
  other.token, key, A, "A256GCM", { ok: true, plaintext_b64u: b64u(Buffer.from("Another token under the RFC 7520 §5.7 key.")), recipient: 0 }));
neg("reject-iv-tag-from-another-token.json", "RFC 7518 §4.7, RFC 7516 §5.1 step 14: the RFC 7520 §5.7 JWE carrying the iv and tag of another valid A256GCMKW wrap under the same key (oracle-a256gcmkw-a256gcm-rfc7520-key-decrypt.json) is DecryptionFailed", with57({ iv: b64u(otherIv), tag: b64u(other.wrap.tag) }));

// A valid wrap of a 16-byte CEK where enc A128CBC-HS256 needs 32 bytes.
const shortIv = derive("short cek wrap iv", 12);
const shortWrap = gcm(kek57, shortIv, Buffer.alloc(0), derive("short cek", 16));
write("reject-cek-length-for-enc.json", decrypt("polyjose",
  "RFC 7516 §5.2 step 9: the RFC 7520 §5.7 JWE whose encrypted key, iv and tag are an OpenSSL-made valid A256GCMKW wrap of a 16-byte CEK is DecryptionFailed (A128CBC-HS256 needs a 32-byte CEK)",
  [b64u(Buffer.from(JSON.stringify({ ...protected57, iv: b64u(shortIv), tag: b64u(shortWrap.tag) }))), b64u(shortWrap.ct), ...parts.slice(2)].join("."),
  key, A, E, fails("DecryptionFailed")));

// ---------------------------------------------------------------- Oracle tokens, other sizes
for (const [bits, enc] of [[128, "A128GCM"], [192, "A192GCM"]]) {
  const kek = derive(`oracle kek ${bits}`, bits / 8);
  const pt = Buffer.from(`A${bits}GCMKW interop: built with OpenSSL, decrypted by polyjose.`);
  const t = oracleToken(kek, enc, derive(`oracle cek ${bits}`, bits / 8), derive(`oracle wrap iv ${bits}`, 12), derive(`oracle content iv ${bits}`, 12), pt);
  write(`oracle-a${bits}gcmkw-a${bits}gcm-decrypt.json`, decrypt(ORACLE,
    `RFC 7518 §4.7, §5.3: a compact A${bits}GCMKW + A${bits}GCM JWE built with OpenSSL (key-wrap IV and tag in the protected header) decrypts to its plaintext`,
    t.token, octJwk(kek), `A${bits}GCMKW`, enc, { ok: true, plaintext_b64u: b64u(pt), recipient: 0 }));
}

// ---------------------------------------------------------------- Encrypt on the OS CSPRNG
for (const [alg, enc, len] of [["A128GCMKW", "A128GCM", 16], ["A192GCMKW", "A192CBC-HS384", 24], ["A256GCMKW", "A256CBC-HS512", 32]]) {
  const k = octJwk(derive(`roundtrip ${alg}`, len));
  write(`roundtrip-${alg.toLowerCase()}-${enc.toLowerCase()}.json`, {
    source: "polyjose",
    description: `RFC 7516 §5.1/§5.2: a compact ${alg} + ${enc} encryption on the OS CSPRNG (RFC 7518 §4.7, a fresh 96-bit key-wrap IV) has five parts and decrypts with the same key to the plaintext`,
    operation: "jwe.encrypt",
    input: { serialization: "compact", enc, plaintext_b64u: b64u(Buffer.from("Live long and prosper.")), recipients: [{ alg, key: k }] },
    expect: { ok: true, decrypt_with: { key: k, allowed_algs: [alg], allowed_enc: [enc] } },
  });
}
write("encrypt-reject-kek-wrong-size.json", {
  source: "polyjose",
  description: "RFC 7518 §4.7: encrypting with A128GCMKW and a 256-bit oct key is InvalidKey (A128GCMKW uses a 128-bit key)",
  operation: "jwe.encrypt",
  input: { serialization: "compact", enc: "A128GCM", plaintext_b64u: b64u(Buffer.from("x")), recipients: [{ alg: "A128GCMKW", key: octJwk(derive("encrypt wrong size", 32)) }] },
  expect: fails("InvalidKey"),
});
write("encrypt-reject-caller-iv.json", {
  source: "polyjose",
  description: "RFC 7518 §4.7.1.1: a caller-supplied iv in the protected header of an A128GCMKW encryption is InvalidHeader (polyjose draws the key-wrap IV itself)",
  operation: "jwe.encrypt",
  input: { serialization: "compact", enc: "A128GCM", plaintext_b64u: b64u(Buffer.from("x")), recipients: [{ alg: "A128GCMKW", key: octJwk(derive("encrypt caller iv", 16)) }], protected: { iv: b64u(Buffer.alloc(12)) } },
  expect: fails("InvalidHeader"),
});

console.log(files.length, "files:", files.join(" "));
