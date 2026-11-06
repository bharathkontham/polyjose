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
