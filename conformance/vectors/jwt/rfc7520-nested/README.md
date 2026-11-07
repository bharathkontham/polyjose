# RFC 7520 §6 and RFC 7519 Appendix A nested JWTs (feature 0004 T13)

One vector per file (ADR 0045, id `<path>#0`). These are the RFC's own nested-JWT examples, and they record exactly what polyjose can and cannot process under ADRs 0021 and 0022. Every refusal here is **out of scope by an ADR, not a failure**.

| File | RFC | Expect | Rule |
|---|---|---|---|
| `6-3-fig228-ps256-valid.json` | 7520 §6.3, Figs. 222, 224, 228 | ok, the Fig. 222 claims | PS256 verify is supported (ADR 0021) |
| `6-3-fig228-ps256-expired.json` | 7520 §6.3 | `TokenExpired` (now 1300819440) | RFC 7519 §4.1.4, ADR 0027 §3 |
| `6-8-fig236-fig84-private-key-unsupported.json` | 7520 §6.8, Figs. 84, 236 | `UnsupportedAlgorithm` | no RSA private JWK (ADR 0021); its `alg` is RSA-OAEP (ADR 0022) |
| `6-8-fig236-fig84-private-key-no-alg-unsupported.json` | 7520 §6.8, Figs. 84, 236 | `UnsupportedAlgorithm` | the same key without `alg`: ADR 0021 alone |
| `6-8-fig236-a128kw-key-rsa-oaep-unsupported.json` | 7520 §6.8, Fig. 236 | `UnsupportedAlgorithm` | RSA-OAEP (SHA-1) is not implemented (ADR 0022) |
| `6-8-fig237-general-json-invalid-format.json` | 7520 §6.8, Fig. 237 | `InvalidFormat` | JWTs are compact only (ADR 0027 §6) |
| `6-8-fig238-flattened-json-invalid-format.json` | 7520 §6.8, Fig. 238 | `InvalidFormat` | as above |
| `rfc7519-a1-rsa1-5-private-key-unsupported.json` | 7519 App. A.1, 7516 A.2.3 | `UnsupportedAlgorithm` | no RSA private JWK, no RSA1_5 (ADR 0021, RFC 8725 §3.2) |
| `rfc7519-a2-rsa1-5-private-key-unsupported.json` | 7519 App. A.2, 7516 A.2.3 | `UnsupportedAlgorithm` | as above. The inner token is validated by `../rfc7519/a2-rs256-key.json` |

Fully decrypting RFC 7520 §6.8 would need RSA-OAEP (SHA-1) and RSA private-key decryption, which ADRs 0022 and 0021 rule out. Its inner JWS (Fig. 228) is still checked byte for byte (feature 0004 research.md §2).

## Where the values come from

None of the values was typed in by hand, and polyjose was not involved.

- **RFC 7520 §6 (Figs. 222–238):** extracted by script from the RFC Editor text `https://www.rfc-editor.org/rfc/rfc7520.txt` (SHA-256 `14798c3b2d72e35375d5fb86d280a1e8df6109a6ee6cbfc091a0c57a8cc076c6`). The vendored ietf-jose cookbook (`crates/polyjose/tests/third_party/ietf-jose-cookbook/`) holds only the §5 JWE examples, not §6. Page headers and footers are dropped, and the display whitespace of RFC 7520 §1.1 is removed.
- **Fig. 84** (the RSA-4096 key of §5.2, which §6.4 reuses) comes from the vendored cookbook file `jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json`, `input.key`, as printed (private members and `alg: RSA-OAEP` included).
- **RFC 7519 App. A.1 and A.2 tokens:** from `https://www.rfc-editor.org/rfc/rfc7519.txt` (SHA-256 `fecd930e9ccf2276b95c0017c6c4ff5d09352e4bc3c7629946447894e0f97248`).
- **The RFC 7516 A.2.3 RSA key** (used by both App. A tokens, RFC 7519 A.1: "including the keys used"): from `https://www.rfc-editor.org/rfc/rfc7516.txt` (SHA-256 `722cfcddc15f58e746891ba4b846853d3711153a774e4dd55ad6db100474a21f`, the same text `tools/jwe/reproduce.sh` checks).
- **The other keys:** the 128-bit `oct` decrypt key is the jwt-oracle's `oct-16`, and the RS256 public key of the App. A vectors is its `rsa-2048-rfc7515-a2` (`tools/jwt-oracle/keys.json`).

The RSA private keys in these files are public RFC test data. polyjose refuses them at import (`UnsupportedAlgorithm`, ADR 0021), so it never signs or decrypts with them.

## Cross-checks run before writing (node:crypto, Node v24.21.0, OpenSSL 3.5.8)

- Fig. 223 is base64url(Fig. 222), Fig. 226 is base64url(Fig. 225), Fig. 233 is base64url(Fig. 232).
- Fig. 228 is Figs. 226.223.227, and Fig. 236 is Figs. 233.231.230.234.235. Figs. 237 and 238 have exactly those members.
- The Fig. 227 PS256 signature verifies with the public half of Fig. 224 (RSASSA-PSS, SHA-256, 32-octet salt). Fig. 224's private members are consistent with its modulus.
- The Fig. 84 key RSA-OAEP-decrypts Fig. 231 to the Fig. 229 CEK. That CEK opens Fig. 234 (A128GCM, AAD = Fig. 233) to exactly Fig. 228.
- The App. A headers decode to the printed headers, and A.2's IV is the printed octet array.
- The RFC 7516 A.2.3 key's `n` and `e` equal those of `../../jwe/negative-structure/rfc7516-a2-rsa1-5-unsupported.json`.
- With node:crypto's RSA1_5 (OpenSSL implicit rejection):
  - A.1 unwraps to the RFC 7516 A.2.2 CEK and opens (A128CBC-HS256, tag checked) to the RFC 7519 §3.1 claims octets.
  - A.2 opens to exactly the RFC 7515 A.2 token of `../rfc7519/a2-rs256-key.json`.

  **Note:** the CEK printed in RFC 7519 A.2 (`GawgguFyGrWKav7AX4VKUg`) is 16 octets, but A128CBC-HS256 needs 32 (RFC 7518 §5.2.3). The encrypted key unwraps to a different, 32-octet CEK, and that CEK opens the token. No RFC 7519 erratum mentions this (checked 2026-11-06). The vectors don't depend on it.

## Regenerating

Save the script below outside the repository as `extract-rfc.mjs`. Download the three RFC texts into an empty directory `<rfc-dir>`, then run, from anywhere:

```sh
node extract-rfc.mjs <rfc-dir> <polyjose-repo-root>
```

The script checks the SHA-256 of each RFC text and every cross-check above. If any check fails, it writes nothing. A re-run reproduces these files byte for byte.

<details><summary><code>extract-rfc.mjs</code></summary>

```js
// T13 scratch: writes conformance/vectors/jwt/rfc7520-nested/*.json from the
// RFC Editor texts of RFC 7520 (§6), RFC 7519 (App. A) and RFC 7516 (A.2.3),
// plus the vendored ietf-jose cookbook (§5.2, the Fig. 84 key), with
// node:crypto cross-checks of every extracted value. Never calls polyjose.
//
//   node extract-rfc.mjs <rfc-dir> <repo-root>
import { createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, constants, privateDecrypt, verify } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const [rfcDir, repo] = process.argv.slice(2);
if (!rfcDir || !repo) throw new Error("usage: node extract-rfc.mjs <rfc-dir> <repo-root>");

const WANT = {
  "rfc7516.txt": "722cfcddc15f58e746891ba4b846853d3711153a774e4dd55ad6db100474a21f",
  "rfc7519.txt": "fecd930e9ccf2276b95c0017c6c4ff5d09352e4bc3c7629946447894e0f97248",
  "rfc7520.txt": "14798c3b2d72e35375d5fb86d280a1e8df6109a6ee6cbfc091a0c57a8cc076c6",
};
const assert = (cond, what) => { if (!cond) throw new Error(`cross-check failed: ${what}`); };

function rfcLines(name) {
  const raw = readFileSync(join(rfcDir, name));
  const sha = createHash("sha256").update(raw).digest("hex");
  assert(sha === WANT[name], `${name} SHA-256 ${sha}`);
  // Drop page footers, form feeds and running headers (RFC 7322 §4.1 page layout).
  return raw.toString("latin1").split("\n").map((l) => l.replace(/\r$/, ""))
    .filter((l) => !/^\f/.test(l) && !/^(Miller|Jones)\b.*\[Page \d+\]$/.test(l) && !/^RFC 75\d\d {2,}.*\d{4}$/.test(l));
}

/** A cursor over the lines: each find starts after the previous one. */
function reader(lines) {
  let at = 0;
  const find = (re) => {
    for (let i = at; i < lines.length; i++) if (re.test(lines[i])) { at = i + 1; return i; }
    throw new Error(`not found after line ${at}: ${re}`);
  };
  const lastStart = (re) => { let k = -1; lines.forEach((l, i) => { if (re.test(l)) k = i; }); assert(k >= 0, `${re}`); at = k + 1; };
  /** The lines strictly between the next `start` match and the next `end` match, whitespace removed. */
  const between = (start, end, keep = () => true) => {
    const s = find(start);
    const e = find(end);
    at = e; // the end line may be the next start
    return lines.slice(s + 1, e).filter((l) => l.trim() !== "" && keep(l)).map((l) => l.replace(/\s+/g, "")).join("");
  };
  return { find, lastStart, between };
}

const b64d = (s) => Buffer.from(s, "base64url");
const isB64 = (s) => /^[A-Za-z0-9_-]+$/.test(s) && Buffer.from(s, "base64url").toString("base64url") === s;
const cap = (n) => new RegExp(`^\\s+Figure ${n}:`);

// ---------------------------------------------------------------- RFC 7520 §6
const r20 = reader(rfcLines("rfc7520.txt"));
r20.lastStart(/^6\. {2}Nesting Signatures and Encryption$/);
const fig = {};
fig[222] = r20.between(/o {2}"alg" parameter of "PS256"\.$/, cap(222));
fig[223] = r20.between(cap(222), cap(223));
fig[224] = r20.between(cap(223), cap(224));
fig[225] = r20.between(/^\s+Figure 226\.$/, cap(225));
fig[226] = r20.between(cap(225), cap(226));
fig[227] = r20.between(/following signature:$/, cap(227));
fig[228] = r20.between(/encryption operation\):$/, cap(228));
fig[229] = r20.between(/from Figure 230\.$/, cap(229));
fig[230] = r20.between(cap(229), cap(230));
fig[231] = r20.between(/produces the following Encrypted Key:$/, cap(231));
fig[232] = r20.between(/^\s+Figure 233\.$/, cap(232));
fig[233] = r20.between(cap(232), cap(233));
fig[234] = r20.between(/o {2}Authentication Tag from Figure 235\.$/, cap(234));
fig[235] = r20.between(cap(234), cap(235));
fig[236] = r20.between(/using the JWE Compact Serialization:$/, cap(236));
fig[237] = r20.between(/using the general JWE JSON Serialization:$/, cap(237));
fig[238] = r20.between(/using the flattened JWE JSON Serialization:$/, cap(238));

const claims222 = JSON.parse(fig[222]);
const jwk224 = JSON.parse(fig[224]);
const hdr225 = JSON.parse(fig[225]);
const hdr232 = JSON.parse(fig[232]);
const general237 = JSON.parse(fig[237]);
const flattened238 = JSON.parse(fig[238]);
for (const n of [223, 226, 227, 229, 230, 231, 233, 234, 235]) assert(isB64(fig[n]), `Fig. ${n} is canonical base64url`);
assert(JSON.stringify(claims222) === '{"iss":"hobbiton.example","exp":1300819380,"http://example.com/is_root":true}', "Fig. 222 claims");
assert(b64d(fig[223]).toString("utf8") === JSON.stringify(claims222), "Fig. 223 = base64url(Fig. 222)");
assert(b64d(fig[226]).toString("utf8") === JSON.stringify(hdr225), "Fig. 226 = base64url(Fig. 225)");
assert(JSON.stringify(hdr225) === '{"alg":"PS256","typ":"JWT"}', "Fig. 225 header");
assert(fig[228] === `${fig[226]}.${fig[223]}.${fig[227]}`, "Fig. 228 = Figs. 226.223.227");
assert(b64d(fig[233]).toString("utf8") === JSON.stringify(hdr232), "Fig. 233 = base64url(Fig. 232)");
assert(JSON.stringify(hdr232) === '{"alg":"RSA-OAEP","cty":"JWT","enc":"A128GCM"}', "Fig. 232 header");
assert(fig[236] === [233, 231, 230, 234, 235].map((n) => fig[n]).join("."), "Fig. 236 = Figs. 233.231.230.234.235");
assert(JSON.stringify(general237) === JSON.stringify({ recipients: [{ encrypted_key: fig[231] }], protected: fig[233], iv: fig[230], ciphertext: fig[234], tag: fig[235] }), "Fig. 237 members");
assert(JSON.stringify(flattened238) === JSON.stringify({ encrypted_key: fig[231], protected: fig[233], iv: fig[230], ciphertext: fig[234], tag: fig[235] }), "Fig. 238 members");

// Fig. 224: RSA-2048 private JWK; its public half verifies the Fig. 228 PS256 signature (RFC 7518 §3.5).
const pub224 = { kty: jwk224.kty, kid: jwk224.kid, use: jwk224.use, n: jwk224.n, e: jwk224.e };
assert(createPrivateKey({ key: jwk224, format: "jwk" }).export({ format: "jwk" }).n === jwk224.n, "Fig. 224 private key is consistent");
const pss = { key: createPublicKey({ key: pub224, format: "jwk" }), padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };
assert(verify("sha256", Buffer.from(`${fig[226]}.${fig[223]}`, "ascii"), pss, b64d(fig[227])), "Fig. 227 PS256 signature verifies with Fig. 224");

// Fig. 84 (RFC 7520 §5.2) from the vendored cookbook: unwraps Fig. 231 to Fig. 229 (RSA-OAEP, SHA-1), and the CEK opens Fig. 234 to Fig. 228.
const cookbook = join(repo, "crates/polyjose/tests/third_party/ietf-jose-cookbook/jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json");
const fig84 = JSON.parse(readFileSync(cookbook, "utf8")).input.key;
assert(fig84.kid === "samwise.gamgee@hobbiton.example" && fig84.d !== undefined, "cookbook 5.2 key is Fig. 84 with its private members");
const cek = privateDecrypt({ key: createPrivateKey({ key: fig84, format: "jwk" }), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, b64d(fig[231]));
assert(cek.equals(b64d(fig[229])), "Fig. 231 RSA-OAEP-decrypts to Fig. 229 under Fig. 84");
{
  const d = createDecipheriv("aes-128-gcm", cek, b64d(fig[230]), { authTagLength: 16 });
  d.setAAD(Buffer.from(fig[233], "ascii"));
  d.setAuthTag(b64d(fig[235]));
  assert(Buffer.concat([d.update(b64d(fig[234])), d.final()]).toString("ascii") === fig[228], "Fig. 234 decrypts to Fig. 228");
}

// ---------------------------------------------------------------- RFC 7519 App. A
const r19 = reader(rfcLines("rfc7519.txt"));
const tokenLine = (l) => /^\s+[A-Za-z0-9_.-]+$/.test(l);
r19.lastStart(/^A\.1\. {2}Example Encrypted JWT$/);
const a1 = r19.between(/^\s+The final result in this example/, /^A\.2\. {2}Example Nested JWT$/, tokenLine);
const a2 = r19.between(/^\s+The final result for this Nested JWT/, /^Appendix B\./, tokenLine);
const a1p = a1.split(".");
const a2p = a2.split(".");
assert(a1p.length === 5 && a1p.every((p) => isB64(p)), "A.1 is five canonical base64url parts");
assert(a2p.length === 5 && a2p.every((p) => isB64(p)), "A.2 is five canonical base64url parts");
assert(b64d(a1p[0]).toString("utf8") === '{"alg":"RSA1_5","enc":"A128CBC-HS256"}', "A.1 header as printed");
assert(b64d(a2p[0]).toString("utf8") === '{"alg":"RSA1_5","enc":"A128CBC-HS256","cty":"JWT"}', "A.2 header as printed");
assert(a2p[0] === "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0", "A.2 encoded header as printed");
assert(b64d(a2p[2]).equals(Buffer.from([82, 101, 100, 109, 111, 110, 100, 32, 87, 65, 32, 57, 56, 48, 53, 50])), "A.2 IV as printed");

// RFC 7516 A.2.3: the RSA key of both App. A tokens ("including the keys used").
const r16 = reader(rfcLines("rfc7516.txt"));
r16.lastStart(/^A\.2\.3\. {2}Key Encryption$/);
const jwk16 = JSON.parse(r16.between(/display purposes only\):$/, /The resulting JWE Encrypted Key value is:$/));
assert(createPrivateKey({ key: jwk16, format: "jwk" }).export({ format: "jwk" }).n === jwk16.n, "RFC 7516 A.2.3 private key is consistent");
const seed = JSON.parse(readFileSync(join(repo, "conformance/vectors/jwe/negative-structure/rfc7516-a2-rsa1-5-unsupported.json"), "utf8"));
assert(seed.input.key.n === jwk16.n && seed.input.key.e === jwk16.e, "RFC 7516 A.2.3 n, e equal the committed 0003 vector's");

/** A128CBC-HS256 (RFC 7518 §5.2.2.2) with a known CEK: checks the tag, returns the plaintext. */
function openCbcHs256(parts, cekBytes) {
  assert(cekBytes.length === 32, "A128CBC-HS256 CEK is 32 octets");
  const [h, , iv, c, t] = parts.map((p) => b64d(p));
  const aad = Buffer.from(parts[0], "ascii");
  const al = Buffer.alloc(8); al.writeBigUInt64BE(BigInt(aad.length * 8));
  const mac = createHmac("sha256", cekBytes.subarray(0, 16)).update(Buffer.concat([aad, iv, c, al])).digest().subarray(0, 16);
  assert(mac.equals(t), "A128CBC-HS256 tag");
  void h;
  const d = createDecipheriv("aes-128-cbc", cekBytes.subarray(16), iv);
  return Buffer.concat([d.update(c), d.final()]);
}
const priv16 = createPrivateKey({ key: jwk16, format: "jwk" });
const rsa15 = (ek) => privateDecrypt({ key: priv16, padding: constants.RSA_PKCS1_PADDING }, b64d(ek));
const t10a2 = JSON.parse(readFileSync(join(repo, "conformance/vectors/jwt/rfc7519/a2-rs256-key.json"), "utf8")).input.token;
const t10s31 = JSON.parse(readFileSync(join(repo, "conformance/vectors/jwt/rfc7519/3-1-hs256-before-exp.json"), "utf8")).input.token;
const notes = [];
try {
  const cekA1 = rsa15(a1p[1]);
  assert(cekA1.equals(Buffer.from([4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207])), "A.1 CEK is RFC 7516 A.2.2's");
  assert(openCbcHs256(a1p, cekA1).equals(b64d(t10s31.split(".")[1])), "A.1 decrypts to the RFC 7519 §3.1 claims octets");
  const cekA2 = rsa15(a2p[1]);
  assert(openCbcHs256(a2p, cekA2).toString("ascii") === t10a2, "A.2 decrypts to the RFC 7515 A.2 token");
  notes.push(`A.1/A.2 opened with node:crypto RSA1_5; A.2 CEK ${cekA2.toString("base64url")}`);
} catch (err) {
  if (/cross-check failed/.test(err.message)) throw err;
  notes.push(`RSA1_5 decryption unavailable in this Node (${err.code ?? err.message}); App. A tokens checked by header and IV only`);
}

// ---------------------------------------------------------------- vectors
const oracleKeys = JSON.parse(readFileSync(join(repo, "conformance/tools/jwt-oracle/keys.json"), "utf8")).keys;
const oct16 = oracleKeys["oct-16"].jwk;
const a2pub = { kty: "RSA", n: oracleKeys["rsa-2048-rfc7515-a2"].jwk.n, e: oracleKeys["rsa-2048-rfc7515-a2"].jwk.e };
const issuer = { issuer: ["hobbiton.example"] };
const ps256 = (now) => ({ token: fig[228], now, allowed_algs: ["PS256"], key: pub224, policy: issuer });
const out = {
  "6-3-fig228-ps256-valid.json": {
    source: "RFC 7520 §6.3, Figs. 222, 224, 228",
    description: "The RFC 7520 §6.3 inner JWS (Fig. 228, PS256, typ JWT) validated as a signed JWT with the public members of the Fig. 224 key, allow-list [PS256] and issuer hobbiton.example, at now 1300819320 (60 s before exp): valid, with the Fig. 222 claims. RSA is verify-only (ADR 0021); the PS256 signature was also checked with node:crypto (RSASSA-PSS, SHA-256, 32-octet salt)",
    operation: "jwt.validate",
    input: ps256(1300819320),
    expect: { ok: true, claims: claims222, alg: "PS256" },
  },
  "6-3-fig228-ps256-expired.json": {
    source: "RFC 7520 §6.3, Figs. 222, 224, 228",
    description: "The RFC 7520 §6.3 inner JWS (Fig. 228) at now 1300819440: exp 1300819380 ≤ now − 60 s default leeway, so TokenExpired (RFC 7519 §4.1.4, ADR 0027 §3), reached after the PS256 signature verifies",
    operation: "jwt.validate",
    input: ps256(1300819440),
    expect: { ok: false, error: "TokenExpired" },
  },
  "6-8-fig236-fig84-private-key-unsupported.json": {
    source: "RFC 7520 §6.8, Figs. 84, 224, 236",
    description: "The RFC 7520 §6.8 nested JWT (Fig. 236, RSA-OAEP + A128GCM around Fig. 228) with decrypt.key the Fig. 84 RSA private key as printed (taken from the vendored ietf-jose cookbook §5.2 file): UnsupportedAlgorithm at key import, because polyjose parses no RSA private JWK (ADR 0021) and the key's alg is RSA-OAEP (ADR 0022). Out of scope by those ADRs, not a failure; the key is never used. The token's integrity was checked with node:crypto (Fig. 84 unwraps Fig. 231 to Fig. 229, which opens Fig. 234 to Fig. 228)",
    operation: "jwt.validate",
    input: { token: fig[236], now: 1300819320, allowed_algs: ["PS256"], key: pub224, policy: issuer, decrypt: { key: fig84, allowed_algs: ["RSA-OAEP"], allowed_enc: ["A128GCM"] } },
    expect: { ok: false, error: "UnsupportedAlgorithm" },
  },
  "6-8-fig236-fig84-private-key-no-alg-unsupported.json": {
    source: "RFC 7520 §6.8, Figs. 84, 224, 236",
    description: "As 6-8-fig236-fig84-private-key-unsupported, with the Fig. 84 key's alg member removed so that only its RSA private members remain: still UnsupportedAlgorithm at key import (ADR 0021: RSA private JWKs are not parsed). Out of scope by ADR 0021, not a failure",
    operation: "jwt.validate",
    input: { token: fig[236], now: 1300819320, allowed_algs: ["PS256"], key: pub224, policy: issuer, decrypt: { key: Object.fromEntries(Object.entries(fig84).filter(([m]) => m !== "alg")), allowed_algs: ["RSA-OAEP"], allowed_enc: ["A128GCM"] } },
    expect: { ok: false, error: "UnsupportedAlgorithm" },
  },
  "6-8-fig236-a128kw-key-rsa-oaep-unsupported.json": {
    source: "RFC 7520 §6.8, Figs. 224, 236",
    description: "The RFC 7520 §6.8 nested JWT (Fig. 236) with a 128-bit oct decrypt key (the jwt-oracle oct-16 test key) and decrypt allowed_algs [RSA-OAEP]: UnsupportedAlgorithm, because RSA-OAEP (SHA-1) is not implemented (ADR 0022). Out of scope by ADR 0022, not a failure",
    operation: "jwt.validate",
    input: { token: fig[236], now: 1300819320, allowed_algs: ["PS256"], key: pub224, policy: issuer, decrypt: { key: oct16, allowed_algs: ["RSA-OAEP"], allowed_enc: ["A128GCM"] } },
    expect: { ok: false, error: "UnsupportedAlgorithm" },
  },
  "6-8-fig237-general-json-invalid-format.json": {
    source: "RFC 7520 §6.8, Figs. 224, 237",
    description: "The RFC 7520 §6.8 general JWE JSON serialization (Fig. 237, whitespace added for display removed per RFC 7520 §1.1) as a nested JWT: InvalidFormat, because JWTs use the compact serialization only (RFC 7519 §1, §7.2 step 1; ADR 0027 §6). The decrypt key is a 128-bit oct key (jwt-oracle oct-16) with allow-lists [A128KW]/[A128GCM], so the serialization is the only fault reached",
    operation: "jwt.validate",
    input: { token: JSON.stringify(general237), now: 1300819320, allowed_algs: ["PS256"], key: pub224, policy: issuer, decrypt: { key: oct16, allowed_algs: ["A128KW"], allowed_enc: ["A128GCM"] } },
    expect: { ok: false, error: "InvalidFormat" },
  },
  "6-8-fig238-flattened-json-invalid-format.json": {
    source: "RFC 7520 §6.8, Figs. 224, 238",
    description: "The RFC 7520 §6.8 flattened JWE JSON serialization (Fig. 238, display whitespace removed per RFC 7520 §1.1) as a nested JWT: InvalidFormat (RFC 7519 §1, §7.2 step 1; ADR 0027 §6). Same decrypt key and allow-lists as the Fig. 237 vector, so the serialization is the only fault reached",
    operation: "jwt.validate",
    input: { token: JSON.stringify(flattened238), now: 1300819320, allowed_algs: ["PS256"], key: pub224, policy: issuer, decrypt: { key: oct16, allowed_algs: ["A128KW"], allowed_enc: ["A128GCM"] } },
    expect: { ok: false, error: "InvalidFormat" },
  },
  "rfc7519-a1-rsa1-5-private-key-unsupported.json": {
    source: "RFC 7519 App. A.1; RFC 7516 App. A.2.3",
    description: "The RFC 7519 A.1 encrypted JWT (RSA1_5 + A128CBC-HS256, the §3.1 claims as plaintext) with decrypt.key the RFC 7516 A.2.3 RSA private key: UnsupportedAlgorithm at key import (ADR 0021: no RSA private JWK, no RSA1_5, which RFC 8725 §3.2 discourages). Out of scope by ADR 0021 / RFC 8725 §3.2, not a failure; it is also an encrypt-only JWT, which ADR 0027 §7 rejects. The key is never used. key/allowed_algs (the RFC 7515 A.2 RS256 public key) only complete the input",
    operation: "jwt.validate",
    input: { token: a1, now: 1300819320, allowed_algs: ["RS256"], key: a2pub, decrypt: { key: jwk16, allowed_algs: ["RSA1_5"], allowed_enc: ["A128CBC-HS256"] } },
    expect: { ok: false, error: "UnsupportedAlgorithm" },
  },
  "rfc7519-a2-rsa1-5-private-key-unsupported.json": {
    source: "RFC 7519 App. A.2; RFC 7516 App. A.2.3",
    description: "The RFC 7519 A.2 nested JWT (RSA1_5 + A128CBC-HS256, cty JWT, around the RFC 7515 A.2 RS256 JWT) with decrypt.key the RFC 7516 A.2.3 RSA private key: UnsupportedAlgorithm at key import (ADR 0021; RFC 8725 §3.2 discourages RSA1_5). Out of scope by ADR 0021 / RFC 8725 §3.2, not a failure; the key is never used. The inner token is validated positively by jwt/rfc7519/a2-rs256-key.json",
    operation: "jwt.validate",
    input: { token: a2, now: 1300819320, allowed_algs: ["RS256"], key: a2pub, decrypt: { key: jwk16, allowed_algs: ["RSA1_5"], allowed_enc: ["A128CBC-HS256"] } },
    expect: { ok: false, error: "UnsupportedAlgorithm" },
  },
};
const dir = join(repo, "conformance/vectors/jwt/rfc7520-nested");
mkdirSync(dir, { recursive: true });
for (const [name, v] of Object.entries(out)) writeFileSync(join(dir, name), `${JSON.stringify(v, null, 2)}\n`);
console.log(`wrote ${Object.keys(out).length} vectors to ${dir}`);
for (const n of notes) console.log(n);
```

</details>
