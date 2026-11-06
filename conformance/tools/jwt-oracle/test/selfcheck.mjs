// Self-check of the jwt-oracle generator: `node --test conformance/tools/jwt-oracle/test/`.
// Uses only node:test, node:assert, node:crypto, node:fs and node:path.
// Every check that needs an independent path re-derives the result here with
// node:crypto calls the generator does not use (see README.md, "Self-check").

import assert from "node:assert/strict";
import {
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  verify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

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
