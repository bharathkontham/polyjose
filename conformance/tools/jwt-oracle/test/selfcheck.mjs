// Self-check of the jwt-oracle generator: `node --test conformance/tools/jwt-oracle/test/`.
// Uses only node:test, node:assert, node:crypto, node:fs and node:path.
// Every check that needs an independent path re-derives the result here with
// node:crypto calls the generator does not use (see README.md, "Self-check").

import assert from "node:assert/strict";
import {
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  verify,
} from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { generate, loadKeys, ORACLE_SOURCE, run } from "../gen.mjs";

const toolDir = join(import.meta.dirname, "..");
const keysDoc = JSON.parse(readFileSync(join(toolDir, "keys.json"), "utf8"));
const KEYS = keysDoc.keys;
const unb64u = (s) => Buffer.from(s, "base64url");

describe("keys.json", () => {
  it("cites a source for every key", () => {
    for (const [name, entry] of Object.entries(KEYS)) {
      assert.equal(typeof entry.source, "string", name);
      assert.match(entry.source, /RFC \d+|generated once with crypto\.\w+.* on \d{4}-\d{2}-\d{2}/, name);
      assert.equal(typeof entry.jwk, "object", name);
    }
  });

  it("holds the keys the task names", () => {
    const want = [
      ["oct-32", "oct", 32],
      ["oct-48", "oct", 48],
      ["oct-64", "oct", 64],
      ["oct-16", "oct", 16],
      ["oct-32-kid-hs-32", "oct", 32],
      ["oct-64-kid-hs-64", "oct", 64],
    ];
    for (const [name, kty, len] of want) {
      assert.equal(KEYS[name].jwk.kty, kty, name);
      assert.equal(unb64u(KEYS[name].jwk.k).length, len, name);
    }
    for (const [name, crv] of [
      ["p256", "P-256"],
      ["p384", "P-384"],
      ["p521", "P-521"],
    ]) {
      assert.equal(KEYS[name].jwk.crv, crv, name);
    }
    assert.equal(KEYS.ed25519.jwk.crv, "Ed25519");
    assert.equal(KEYS["ed25519-other"].jwk.crv, "Ed25519");
    for (let i = 1; i <= 9; i += 1) {
      assert.equal(KEYS[`p256-cand-${i}`].jwk.crv, "P-256");
      assert.equal(KEYS[`p256-cand-${i}`].jwk.kid, undefined, "candidates are kid-less");
    }
  });

  it("uses the RFC 7515 A.1 HMAC key as oct-64 and the RFC 8037 A.1 key as ed25519", () => {
    assert.equal(
      KEYS["oct-64"].jwk.k,
      "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    );
    assert.equal(KEYS.ed25519.jwk.x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
  });

  it("gives distinct kids to the selection keys", () => {
    const kids = Object.values(KEYS)
      .map((e) => e.jwk.kid)
      .filter((k) => k !== undefined);
    assert.ok(kids.includes("a") && kids.includes("b") && kids.includes("c"));
    assert.ok(kids.includes("hs-32") && kids.includes("hs-64"));
    assert.equal(new Set(kids).size, kids.length);
  });

  it("has distinct key material for every key", () => {
    const material = Object.values(KEYS).map((e) => e.jwk.k ?? e.jwk.x ?? e.jwk.n);
    assert.equal(new Set(material).size, material.length);
  });

  it("derives each EC and OKP public key from its private key (node:crypto)", () => {
    for (const [name, { jwk }] of Object.entries(KEYS)) {
      if (jwk.kty !== "EC" && jwk.kty !== "OKP") continue;
      assert.ok(jwk.d, `${name} is a private key`);
      const derived = createPublicKey(createPrivateKey({ key: jwk, format: "jwk" })).export({
        format: "jwk",
      });
      assert.equal(derived.x, jwk.x, name);
      assert.equal(derived.y, jwk.y, name);
    }
  });

  it("holds RSA public keys only (ADR 0021)", () => {
    const rsa = Object.entries(KEYS).filter(([, e]) => e.jwk.kty === "RSA");
    assert.ok(rsa.length >= 3);
    const privateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth"];
    for (const [name, { jwk }] of rsa) {
      for (const m of privateMembers) assert.equal(jwk[m], undefined, `${name}.${m}`);
      createPublicKey({ key: jwk, format: "jwk" });
    }
  });

  it("holds the RFC 7520 Figure 3 RSA key and a 2048-bit RFC 7515 A.2 public key", () => {
    assert.equal(KEYS["rsa-2048"].jwk.kid, "bilbo.baggins@hobbiton.example");
    assert.match(KEYS["rsa-2048"].source, /RFC 7520 §3\.3 Figure 3/);
    for (const name of ["rsa-2048", "rsa-2048-rfc7515-a2"]) {
      const n = unb64u(KEYS[name].jwk.n);
      assert.equal(n.length * 8, 2048, name);
      assert.ok(n[0] & 0x80, `${name}: the modulus has its top bit set`);
    }
  });

  it("holds an RSA public key whose modulus is over 8192 bits (ADR 0041 §2)", () => {
    const n = unb64u(KEYS["rsa-8200"].jwk.n);
    assert.ok(n[0] & 0x80, "no leading zero octet: the bit length is the octet length times 8");
    assert.equal(n.length * 8, 8200);
    assert.ok(n.length * 8 > 8192);
    assert.match(KEYS["rsa-8200"].source, /private key was never written/);
  });
});

// ---------------------------------------------------------------------------
// Generator: JWS
// ---------------------------------------------------------------------------

const keys = loadKeys();
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const pub = (name) => createPublicKey({ key: KEYS[name].jwk, format: "jwk" });

/** A minimal spec entry; the token lands wherever "$token" is written. */
const entry = (directives, extra = {}) => ({
  description: "self-check entry",
  operation: "jwt.validate",
  input: { token: "$token", now: 1300819320, allowed_algs: ["HS256"] },
  expect: { ok: true },
  ...directives,
  ...extra,
});
const tokenOf = (jws, extra) => generate(entry({ jws }, extra), keys).input.token;
const parts = (token) => token.split(".");

// RFC 7519 §3.1: the example header and claims, octet for octet (CRLF and the
// leading spaces included), MACed with the RFC 7515 A.1 key.
const RFC7519_3_1_HEADER = '{"typ":"JWT",\r\n "alg":"HS256"}';
const RFC7519_3_1_PAYLOAD = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}';
const RFC7519_3_1_TOKEN =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
  ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
  ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

describe("gen.mjs: JWS compact", () => {
  it("reproduces the RFC 7519 §3.1 token byte for byte", () => {
    const token = tokenOf({
      header_text: RFC7519_3_1_HEADER,
      payload: RFC7519_3_1_PAYLOAD,
      key: "oct-64",
    });
    assert.equal(token, RFC7519_3_1_TOKEN);
    // The same octets are RFC 7515 A.1, already vendored as a jws.sign vector.
    const a1 = JSON.parse(
      readFileSync(join(toolDir, "../../vectors/jws-rfc7515/a1-hs256-compact-sign.json"), "utf8"),
    );
    assert.equal(token, a1.expect.jws);
  });

  it("signs HS384 and HS512 with RFC 7518 §3.2 HMACs", () => {
    for (const [alg, name, len] of [
      ["HS384", "oct-48", 48],
      ["HS512", "oct-64", 64],
      ["HS256", "oct-32", 32],
    ]) {
      const token = tokenOf({ header: { alg }, payload: '{"a":1}', key: name });
      assert.equal(unb64u(parts(token)[2]).length, len, alg);
    }
  });

  it("serializes a header object with JSON.stringify, in insertion order", () => {
    const token = tokenOf({ header: { alg: "HS256", typ: "JWT", kid: "k" }, payload: "{}", key: "oct-32" });
    assert.equal(unb64u(parts(token)[0]).toString(), '{"alg":"HS256","typ":"JWT","kid":"k"}');
  });

  it("emits ES256/384/512 as R || S that crypto.verify accepts (ieee-p1363, RFC 7518 §3.4)", () => {
    for (const [alg, name, hash, len] of [
      ["ES256", "p256", "sha256", 64],
      ["ES384", "p384", "sha384", 96],
      ["ES512", "p521", "sha512", 132],
    ]) {
      const token = tokenOf({ header: { alg, typ: "JWT" }, payload: '{"sub":"x"}', key: name });
      const [h, p, s] = parts(token);
      const sig = unb64u(s);
      assert.equal(sig.length, len, alg);
      const ok = verify(hash, Buffer.from(`${h}.${p}`, "ascii"), { key: pub(name), dsaEncoding: "ieee-p1363" }, sig);
      assert.ok(ok, `${alg} verifies`);
    }
  });

  it("signs EdDSA and Ed25519 (RFC 8037 §3.1) and both verify", () => {
    for (const alg of ["EdDSA", "Ed25519"]) {
      const [h, p, s] = parts(tokenOf({ header: { alg }, payload: '{"sub":"x"}', key: "ed25519" }));
      assert.ok(verify(null, Buffer.from(`${h}.${p}`, "ascii"), pub("ed25519"), unb64u(s)), alg);
    }
  });

  it("signs raw payload octets given as base64url, even when they are not UTF-8", () => {
    const raw = Buffer.from([0xff, 0xfe, 0x7b, 0x7d]);
    const token = tokenOf({ header: { alg: "HS256" }, payload_b64u: b64u(raw), key: "oct-32" });
    assert.deepEqual(unb64u(parts(token)[1]), raw);
  });

  it("signs malformed claims verbatim (duplicate names, string dates, 1e400)", () => {
    const text = '{"exp":1,"exp":2,"nbf":"0","iat":1e400}';
    const token = tokenOf({ header: { alg: "HS256" }, payload: text, key: "oct-32" });
    assert.equal(unb64u(parts(token)[1]).toString("utf8"), text);
  });

  it("serializes payload_json with JSON.stringify", () => {
    const token = tokenOf({ header: { alg: "HS256" }, payload_json: { iss: "a", aud: ["x", "y"] }, key: "oct-32" });
    assert.equal(unb64u(parts(token)[1]).toString(), '{"iss":"a","aud":["x","y"]}');
  });

  it("takes the header verbatim from header_b64u", () => {
    const h = b64u('{"alg":"HS256","alg":"HS256"}');
    assert.equal(parts(tokenOf({ header_b64u: h, payload: "{}", key: "oct-32" }))[0], h);
  });

  it("is deterministic for HMAC and EdDSA: two runs write identical files", () => {
    const spec = {
      vectors: [
        entry({ jws: { header: { alg: "HS256", typ: "JWT" }, payload: '{"a":1}', key: "oct-32" } }),
        entry({ jws: { header: { alg: "HS384" }, payload: '{"a":1}', key: "oct-48" } }),
        entry({ jws: { header: { alg: "HS512" }, payload: '{"a":1}', key: "oct-64" } }),
        entry({ jws: { header: { alg: "EdDSA" }, payload: '{"a":1}', key: "ed25519" } }),
        entry({ jws: { header: { alg: "Ed25519" }, payload: '{"a":1}', key: "ed25519-other" } }),
      ],
    };
    const dir = mkdtempSync(join(process.env.TMPDIR ?? "/tmp", "jwt-oracle-"));
    try {
      const specPath = join(dir, "spec.json");
      writeFileSync(specPath, JSON.stringify(spec));
      run(specPath, join(dir, "one.json"));
      run(specPath, join(dir, "two.json"));
      const one = readFileSync(join(dir, "one.json"));
      assert.ok(one.length > 0);
      assert.deepEqual(one, readFileSync(join(dir, "two.json")));
      assert.equal(JSON.parse(one).vectors.length, 5);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("gen.mjs: vector members", () => {
  it("passes every other member through and names the oracle and Node version in source", () => {
    const spec = entry(
      { jws: { header: { alg: "HS256" }, payload: "{}", key: "oct-32" } },
      {
        input: { token: "$token", now: 7, allowed_algs: ["HS256"], policy: { leeway: 0, audience: ["api"] } },
        expect: { ok: false, error: "InvalidClaim" },
        features: ["fixed-rng"],
      },
    );
    const v = generate(spec, keys);
    assert.deepEqual(Object.keys(v), ["source", "description", "operation", "input", "expect", "features"]);
    assert.equal(v.description, "self-check entry");
    assert.equal(v.input.now, 7);
    assert.deepEqual(v.input.policy, { leeway: 0, audience: ["api"] });
    assert.deepEqual(v.expect, { ok: false, error: "InvalidClaim" });
    assert.deepEqual(v.features, ["fixed-rng"]);
    assert.equal(v.jws, undefined);
    assert.ok(v.source.includes("conformance/tools/jwt-oracle"));
    assert.ok(v.source.includes(`Node ${process.version}`));
    assert.equal(v.source, ORACLE_SOURCE);
  });

  it("keeps a spec-given source in front of the oracle's", () => {
    const v = generate(
      entry({ jws: { header: { alg: "HS256" }, payload: "{}", key: "oct-32" } }, { source: "RFC 7519 §4.1.4" }),
      keys,
    );
    assert.equal(v.source, `RFC 7519 §4.1.4; ${ORACLE_SOURCE}`);
  });

  it("keeps the spec file's shape: array, {vectors}, or a single entry", () => {
    const e = entry({ jws: { header: { alg: "HS256" }, payload: "{}", key: "oct-32" } });
    assert.ok(Array.isArray(generate([e, e], keys)));
    const obj = generate({ comment: "kept", vectors: [e] }, keys);
    assert.equal(obj.comment, "kept");
    assert.equal(obj.vectors.length, 1);
    assert.equal(typeof generate(e, keys).input.token, "string");
  });

  it("replaces $token anywhere in the vector", () => {
    const v = generate(
      entry(
        { jws: { header: { alg: "HS256" }, payload: "{}", key: "oct-32" } },
        { operation: "jwt.issue", input: { claims: {} }, expect: { ok: true, token: "$token" } },
      ),
      keys,
    );
    assert.equal(parts(v.expect.token).length, 3);
  });

  it("resolves $key and $public references, with `with` overrides and null deletions", () => {
    const v = generate(
      entry(
        { jws: { header: { alg: "ES256", kid: "a", jwk: { $public: "p256-attacker" } }, payload: "{}", key: "p256-attacker" } },
        {
          input: {
            token: "$token",
            now: 0,
            jwks: { keys: [{ $public: "p256-kid-a", with: { use: "enc" } }, { $key: "oct-32-kid-hs-32", with: { kid: null } }] },
          },
        },
      ),
      keys,
    );
    const [a, oct] = v.input.jwks.keys;
    assert.equal(a.d, undefined);
    assert.equal(a.kid, "a");
    assert.equal(a.use, "enc");
    assert.equal(a.x, KEYS["p256-kid-a"].jwk.x);
    assert.equal(oct.k, KEYS["oct-32-kid-hs-32"].jwk.k);
    assert.equal(oct.kid, undefined);
    const header = JSON.parse(unb64u(parts(v.input.token)[0]));
    assert.deepEqual(header.jwk, { kty: "EC", crv: "P-256", x: KEYS["p256-attacker"].jwk.x, y: KEYS["p256-attacker"].jwk.y });
  });

  it("derives an HMAC key from an RSA public key's SPKI PEM ($oct_from, RFC 8725 §2.1 confusion)", () => {
    const token = tokenOf({
      header: { alg: "HS256" },
      payload: "{}",
      key: { $oct_from: "rsa-2048", encoding: "spki-pem" },
    });
    const pem = pub("rsa-2048").export({ type: "spki", format: "pem" });
    const [h, p, s] = parts(token);
    assert.equal(s, hmacB64u("sha256", Buffer.from(pem, "utf8"), `${h}.${p}`));
  });

  it("refuses $public of an oct key, unknown key names and unknown members", () => {
    assert.throws(() => generate(entry({}, { input: { key: { $public: "oct-32" } } }), keys), /oct/);
    assert.throws(() => tokenOf({ header: { alg: "HS256" }, payload: "{}", key: "no-such-key" }), /no-such-key/);
    assert.throws(() => tokenOf({ header: { alg: "HS256" }, payload: "{}", key: "oct-32", paylod: "x" }), /paylod/);
  });

  it("requires description, operation, input and expect", () => {
    for (const m of ["description", "operation", "input", "expect"]) {
      const e = entry({ jws: { header: { alg: "HS256" }, payload: "{}", key: "oct-32" } });
      delete e[m];
      assert.throws(() => generate(e, keys), new RegExp(m));
    }
  });

  it("refuses a built token that no $token uses, and a $token with nothing built", () => {
    assert.throws(
      () => generate(entry({ jws: { header: { alg: "HS256" }, payload: "{}", key: "oct-32" } }, { input: { now: 0 } }), keys),
      /\$token/,
    );
    assert.throws(() => generate(entry({}), keys), /\$token/);
  });
});

function hmacB64u(hash, key, text) {
  return b64u(createHmac(hash, key).update(Buffer.from(text, "ascii")).digest());
}

describe("gen.mjs: JWS negative-vector features", () => {
  const good = { header: { alg: "HS256", typ: "JWT" }, payload: '{"sub":"x"}', key: "oct-32" };

  it("corrupt_signature flips the low bit of the last signature octet, nothing else", () => {
    for (const spec of [good, { header: { alg: "ES256" }, payload: "{}", key: "p256" }, { header: { alg: "EdDSA" }, payload: "{}", key: "ed25519" }]) {
      const [h, p, s] = parts(tokenOf({ ...spec, corrupt_signature: true }));
      const sig = unb64u(s);
      const alg = spec.header.alg;
      if (alg === "HS256") {
        const [gh, gp, gs] = parts(tokenOf(spec));
        assert.equal(h, gh);
        assert.equal(p, gp);
        const orig = unb64u(gs);
        assert.deepEqual(sig.subarray(0, -1), orig.subarray(0, -1));
        assert.equal(sig.at(-1), orig.at(-1) ^ 0x01);
      } else {
        const hash = alg === "ES256" ? "sha256" : null;
        const k = alg === "ES256" ? { key: pub("p256"), dsaEncoding: "ieee-p1363" } : pub("ed25519");
        assert.equal(verify(hash, Buffer.from(`${h}.${p}`, "ascii"), k, sig), false, `${alg} no longer verifies`);
        sig[sig.length - 1] ^= 0x01;
        assert.ok(verify(hash, Buffer.from(`${h}.${p}`, "ascii"), k, sig), `${alg} un-flipped verifies`);
      }
    }
  });

  it('alg "none" gives an empty signature and takes no key (RFC 7519 §6.1)', () => {
    const token = tokenOf({ header: { alg: "none" }, payload: '{"iss":"joe"}' });
    const [h, p, s] = parts(token);
    assert.equal(s, "");
    assert.equal(unb64u(h).toString(), '{"alg":"none"}');
    assert.equal(unb64u(p).toString(), '{"iss":"joe"}');
    assert.throws(() => tokenOf({ header: { alg: "none" }, payload: "{}", key: "oct-32" }), /none/);
  });

  it("signature_b64u forges a signature verbatim", () => {
    const forged = b64u(Buffer.alloc(32, 7));
    assert.equal(parts(tokenOf({ header: { alg: "none" }, payload: "{}", signature_b64u: forged }))[2], forged);
    assert.throws(() => tokenOf({ ...good, signature_b64u: forged }), /signature_b64u/);
  });

  it("refuses a b64:false compact payload containing '.' (RFC 7797 §5.2)", () => {
    const header = { alg: "HS256", b64: false, crit: ["b64"] };
    assert.throws(() => tokenOf({ header, payload: "a.b", key: "oct-32" }), /RFC 7797 §5\.2/);
  });

  it("b64:false compact payload is the raw text and the MAC covers it (RFC 7797 §3)", () => {
    const header = { alg: "HS256", b64: false, crit: ["b64"] };
    const [h, p, s] = parts(tokenOf({ header, payload: '{"sub":"x"}', key: "oct-32" }));
    assert.equal(p, '{"sub":"x"}');
    assert.equal(s, hmacB64u("sha256", unb64u(KEYS["oct-32"].jwk.k), `${h}.${p}`));
  });

  it("replace_after_signing swaps the header or payload while keeping the signature", () => {
    const [gh, gp, gs] = parts(tokenOf(good));
    const [h1, p1, s1] = parts(tokenOf({ ...good, replace_after_signing: { payload: '{"sub":"y"}' } }));
    assert.equal(h1, gh);
    assert.equal(s1, gs);
    assert.equal(unb64u(p1).toString(), '{"sub":"y"}');
    const [h2, p2, s2] = parts(tokenOf({ ...good, replace_after_signing: { header: { alg: "HS256", typ: "at+jwt" } } }));
    assert.equal(p2, gp);
    assert.equal(s2, gs);
    assert.equal(unb64u(h2).toString(), '{"alg":"HS256","typ":"at+jwt"}');
    assert.throws(() => tokenOf({ ...good, replace_after_signing: { signature: "x" } }), /signature/);
  });

  it("rewraps the compact JWS as flattened JSON with a spec-given unprotected header (ADR 0049 §2)", () => {
    const compact = parts(tokenOf(good));
    const v = generate(
      entry(
        { jws: { ...good, serialization: "flattened", unprotected: { typ: "at+jwt" } } },
        { input: { token: "$token", now: 0 }, expect: { ok: false, error: "InvalidFormat", seen: "$token_json" } },
      ),
      keys,
    );
    const obj = JSON.parse(v.input.token);
    // RFC 7515 §7.2.2: payload, protected, header, signature.
    assert.deepEqual(Object.keys(obj), ["payload", "protected", "header", "signature"]);
    assert.equal(obj.protected, compact[0]);
    assert.equal(obj.payload, compact[1]);
    assert.equal(obj.signature, compact[2]);
    assert.deepEqual(obj.header, { typ: "at+jwt" });
    assert.deepEqual(v.expect.seen, obj);
    assert.equal(obj.signature, hmacB64u("sha256", unb64u(KEYS["oct-32"].jwk.k), `${obj.protected}.${obj.payload}`));
    assert.throws(() => tokenOf({ ...good, unprotected: { typ: "x" } }), /flattened/);
    assert.throws(() => generate(entry({ jws: good }, { input: { t: "$token_json" } }), keys), /JSON serialization/);
  });

  it("refuses RSA signing (ADR 0021), a wrong curve, and a short HMAC key (RFC 7518 §3.2)", () => {
    assert.throws(() => tokenOf({ header: { alg: "RS256" }, payload: "{}", key: "rsa-2048" }), /ADR 0021/);
    assert.throws(() => tokenOf({ header: { alg: "PS256" }, payload: "{}", key: "p256" }), /ADR 0021/);
    assert.throws(() => tokenOf({ header: { alg: "HS256" }, payload: "{}", key: "rsa-2048" }), /ADR 0021/);
    assert.throws(() => tokenOf({ header: { alg: "ES256" }, payload: "{}", key: "p384" }), /P-256/);
    assert.throws(() => tokenOf({ header: { alg: "HS256" }, payload: "{}", key: "oct-16" }), /RFC 7518 §3\.2/);
    assert.throws(() => tokenOf({ header: { alg: "ES256" }, payload: "{}", key: { $public: "p256" } }), /private/);
  });

  it("signs with `alg` when the header names none or another alg", () => {
    const [h, p, s] = parts(tokenOf({ header: { typ: "JWT" }, payload: "{}", key: "oct-32", alg: "HS256" }));
    assert.equal(s, hmacB64u("sha256", unb64u(KEYS["oct-32"].jwk.k), `${h}.${p}`));
  });
});

// ---------------------------------------------------------------------------
// Generator: nested JWT as a JWE (RFC 7519 §5.2, §11.2; RFC 7516)
// ---------------------------------------------------------------------------

/**
 * RFC 7518 §4.6.2 Concat KDF, written here independently of gen.mjs: one
 * SHA-256 round per 256 bits of output over
 * counter || Z || AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo.
 */
function concatKdfIndependent(z, algId, apu, apv, keyBits) {
  const field = (bytes) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(bytes.length, 0);
    return [len, bytes];
  };
  const supp = Buffer.alloc(4);
  supp.writeUInt32BE(keyBits, 0);
  const otherInfo = Buffer.concat([...field(Buffer.from(algId, "ascii")), ...field(apu), ...field(apv), supp]);
  const rounds = Math.ceil(keyBits / 256);
  const chunks = [];
  for (let counter = 1; counter <= rounds; counter += 1) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter, 0);
    chunks.push(createHash("sha256").update(c).update(z).update(otherInfo).digest());
  }
  return Buffer.concat(chunks).subarray(0, keyBits / 8);
}

const KW_IV = Buffer.alloc(8, 0xa6); // RFC 3394 §2.2.3.1 default IV

/** Decrypts a JWE independently: header, CEK recovery, AES-GCM with AAD = ASCII(protected b64u). */
function decryptIndependent({ protectedB64, ek, iv, ct, tag }, recipientName) {
  const header = JSON.parse(unb64u(protectedB64));
  const encBits = { A128GCM: 128, A192GCM: 192, A256GCM: 256 }[header.enc];
  assert.ok(encBits, `enc ${header.enc}`);
  const own = KEYS[recipientName].jwk;
  let cek;
  if (header.alg === "dir") {
    cek = unb64u(own.k);
    assert.equal(unb64u(ek).length, 0, "dir has an empty encrypted key (RFC 7518 §4.5)");
  } else if (/^A\d{3}KW$/.test(header.alg)) {
    const kek = unb64u(own.k);
    const d = createDecipheriv(`id-aes${kek.length * 8}-wrap`, kek, KW_IV);
    cek = Buffer.concat([d.update(unb64u(ek)), d.final()]);
  } else if (/^ECDH-ES\+A\d{3}KW$/.test(header.alg)) {
    const z = diffieHellman({
      privateKey: createPrivateKey({ key: own, format: "jwk" }),
      publicKey: createPublicKey({ key: header.epk, format: "jwk" }),
    });
    const bits = Number(header.alg.slice(9, 12));
    const apu = header.apu === undefined ? Buffer.alloc(0) : unb64u(header.apu);
    const apv = header.apv === undefined ? Buffer.alloc(0) : unb64u(header.apv);
    const kek = concatKdfIndependent(z, header.alg, apu, apv, bits);
    const d = createDecipheriv(`id-aes${bits}-wrap`, kek, KW_IV);
    cek = Buffer.concat([d.update(unb64u(ek)), d.final()]);
  } else {
    assert.fail(`alg ${header.alg}`);
  }
  assert.equal(cek.length * 8, encBits, "CEK size matches enc");
  const d = createDecipheriv(`aes-${encBits}-gcm`, cek, unb64u(iv), { authTagLength: 16 });
  d.setAAD(Buffer.from(protectedB64, "ascii"));
  d.setAuthTag(unb64u(tag));
  return { header, plaintext: Buffer.concat([d.update(unb64u(ct)), d.final()]).toString("utf8") };
}

const compactJwe = (token) => {
  const p = token.split(".");
  assert.equal(p.length, 5, "a compact JWE has five parts (RFC 7516 §7.1)");
  const [protectedB64, ek, iv, ct, tag] = p;
  return { protectedB64, ek, iv, ct, tag };
};

const INNER = { header: { alg: "ES256", typ: "JWT" }, payload: '{"iss":"joe","exp":1300819380}', key: "p256" };
const nested = (jwe, jws = INNER) => generate(entry({ jws, jwe }), keys).input.token;

function assertInnerEs256(plaintext) {
  const [h, p, s] = parts(plaintext);
  assert.equal(unb64u(p).toString(), INNER.payload);
  const ok = verify("sha256", Buffer.from(`${h}.${p}`, "ascii"), { key: pub("p256"), dsaEncoding: "ieee-p1363" }, unb64u(s));
  assert.ok(ok, "the inner ES256 JWS verifies");
}

describe("gen.mjs: nested JWE", () => {
  it("ECDH-ES+A128KW on P-256 decrypts with an independent diffieHellman + Concat KDF + id-aes128-wrap path", () => {
    const token = nested({ alg: "ECDH-ES+A128KW", enc: "A128GCM", key: "p256-ecdh" });
    const { header, plaintext } = decryptIndependent(compactJwe(token), "p256-ecdh");
    assert.equal(header.cty, "JWT", "RFC 7519 §5.2: cty JWT on the outer header");
    assert.equal(header.epk.kty, "EC");
    assert.equal(header.epk.crv, "P-256");
    assert.equal(header.epk.d, undefined);
    assertInnerEs256(plaintext);
  });

  it("uses apu and apv from the protected header in the Concat KDF (RFC 7518 §4.6.1.2–§4.6.1.3)", () => {
    const token = nested({
      alg: "ECDH-ES+A128KW",
      enc: "A256GCM",
      key: "p256-ecdh",
      header: { apu: b64u("Alice"), apv: b64u("Bob") },
    });
    const { header, plaintext } = decryptIndependent(compactJwe(token), "p256-ecdh");
    assert.equal(header.apu, b64u("Alice"));
    assertInnerEs256(plaintext);
  });

  it("dir + A256GCM uses the oct key as the CEK (RFC 7518 §4.5)", () => {
    const token = nested({ alg: "dir", enc: "A256GCM", key: "oct-32" });
    const { header, plaintext } = decryptIndependent(compactJwe(token), "oct-32");
    assert.deepEqual(Object.keys(header), ["alg", "enc", "cty"]);
    assertInnerEs256(plaintext);
  });

  it("A128KW + A128GCM wraps a random CEK (RFC 7518 §4.4)", () => {
    const token = nested({ alg: "A128KW", enc: "A128GCM", key: "oct-16" });
    assertInnerEs256(decryptIndependent(compactJwe(token), "oct-16").plaintext);
  });

  it("lets the spec override cty, drop it with null, and add members (iss replication)", () => {
    const lower = decryptIndependent(compactJwe(nested({ alg: "dir", enc: "A256GCM", key: "oct-32", header: { cty: "jwt" } })), "oct-32");
    assert.equal(lower.header.cty, "jwt");
    const none = decryptIndependent(compactJwe(nested({ alg: "dir", enc: "A256GCM", key: "oct-32", header: { cty: null } })), "oct-32");
    assert.equal("cty" in none.header, false);
    const iss = decryptIndependent(compactJwe(nested({ alg: "dir", enc: "A256GCM", key: "oct-32", header: { iss: "joe", kid: "k1" } })), "oct-32");
    assert.equal(iss.header.iss, "joe");
    assert.equal(iss.header.kid, "k1");
    for (const m of ["alg", "enc", "epk"]) {
      assert.throws(() => nested({ alg: "dir", enc: "A256GCM", key: "oct-32", header: { [m]: "x" } }), new RegExp(m));
    }
  });

  it("encrypts a given plaintext when there is no jws (encrypt-only, or a non-JWT inner)", () => {
    const v = generate(entry({ jwe: { alg: "dir", enc: "A256GCM", key: "oct-32", plaintext: '{"iss":"joe"}' } }), keys);
    assert.equal(decryptIndependent(compactJwe(v.input.token), "oct-32").plaintext, '{"iss":"joe"}');
    assert.throws(() => nested({ alg: "dir", enc: "A256GCM", key: "oct-32", plaintext: "x" }), /plaintext/);
  });

  it("applies an array of layers in order: a JWE inside a JWE", () => {
    const token = nested([
      { alg: "dir", enc: "A256GCM", key: "oct-32" },
      { alg: "A128KW", enc: "A128GCM", key: "oct-16" },
    ]);
    const outer = decryptIndependent(compactJwe(token), "oct-16");
    const inner = decryptIndependent(compactJwe(outer.plaintext), "oct-32");
    assertInnerEs256(inner.plaintext);
  });

  it("writes a flattened JWE with cty only in the shared unprotected header (ADR 0050 §3)", () => {
    const v = generate(
      entry(
        {
          jws: INNER,
          jwe: {
            alg: "ECDH-ES+A128KW",
            enc: "A128GCM",
            key: "p256-ecdh",
            serialization: "flattened",
            header: { cty: null },
            unprotected: { cty: "JWT" },
          },
        },
        { expect: { ok: false, error: "InvalidFormat", obj: "$token_json" } },
      ),
      keys,
    );
    const obj = JSON.parse(v.input.token);
    // RFC 7516 §7.2.2 members.
    assert.deepEqual(Object.keys(obj), ["protected", "unprotected", "encrypted_key", "iv", "ciphertext", "tag"]);
    assert.deepEqual(obj.unprotected, { cty: "JWT" });
    assert.deepEqual(v.expect.obj, obj);
    const { header, plaintext } = decryptIndependent(
      { protectedB64: obj.protected, ek: obj.encrypted_key, iv: obj.iv, ct: obj.ciphertext, tag: obj.tag },
      "p256-ecdh",
    );
    assert.equal("cty" in header, false);
    assertInnerEs256(plaintext);
    const dir = JSON.parse(nested({ alg: "dir", enc: "A256GCM", key: "oct-32", serialization: "flattened", recipient_header: { kid: "r" } }));
    assert.equal("encrypted_key" in dir, false, "RFC 7516 §7.2.1: an empty encrypted key is omitted");
    assert.deepEqual(dir.header, { kid: "r" });
    assert.throws(() => nested({ alg: "dir", enc: "A256GCM", key: "oct-32", unprotected: { cty: "JWT" } }), /flattened/);
  });

  it("corrupts the tag or the ciphertext so decryption fails", () => {
    for (const corrupt of ["tag", "ciphertext"]) {
      const token = nested({ alg: "dir", enc: "A256GCM", key: "oct-32", corrupt });
      assert.throws(() => decryptIndependent(compactJwe(token), "oct-32"), /authenticate/, corrupt);
    }
  });

  it("refuses mismatched keys and unsupported algorithms", () => {
    assert.throws(() => nested({ alg: "dir", enc: "A128GCM", key: "oct-32" }), /16/);
    assert.throws(() => nested({ alg: "A128KW", enc: "A128GCM", key: "oct-32" }), /16/);
    assert.throws(() => nested({ alg: "ECDH-ES+A128KW", enc: "A128GCM", key: "oct-32" }), /EC/);
    assert.throws(() => nested({ alg: "RSA-OAEP-256", enc: "A128GCM", key: "rsa-2048" }), /unsupported/);
    assert.throws(() => nested({ alg: "dir", enc: "A128CBC-HS256", key: "oct-32" }), /unsupported/);
  });
});
