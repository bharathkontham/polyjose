/**
 * [WASM-pkg-node] A polluted `Object.prototype` on the installed package: verified results hold
 * only what the token and the core produced (`bindings/js/BACKEND.md` "Results").
 *
 * - **Data pollution** (security audit 0006 M1, closed by 0013 F09). A pollution bug elsewhere in
 *   the app (a JSON deep-merge writing `__proto__`) leaves writable data members on
 *   `Object.prototype`. The adapter leaves absent optional members out, and the facade reads a
 *   backend result by its own members only (`Object.hasOwn`), so an inherited `kid` or
 *   `unprotectedHeader` never becomes an own, parsed member of a verified result. A facade
 *   without F09 read these members by name, picked up the inherited value, parsed it and copied it
 *   into its result as an own member: the audit's PoC (`p4b-own.mjs`) showed an own
 *   `kid: "attacker-kid"` from `jwtVerify` and an own `unprotectedHeader` `{ x5u: … }` from
 *   `jwsVerifyCompact` on the packed package before F09, and neither after it.
 * - **A planted accessor** (audit I2, review S1). The adapter builds its results with a null
 *   prototype, so a setter on `Object.prototype.payload`, `plaintext` or `claims` never receives
 *   the secret on its way out, and the result still owns the right value.
 *
 * Every test puts `Object.prototype` back exactly as it was, in a `finally`, before it asserts.
 */
import * as api from "@polyjose/wasm";
import { assert, test } from "./node.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Runs `run` with `members` defined on `Object.prototype`, then restores each one as it was. */
async function withPrototype<T>(members: Record<string, PropertyDescriptor>, run: () => Promise<T>): Promise<T> {
  const saved = new Map<string, PropertyDescriptor | undefined>();
  try {
    for (const [key, descriptor] of Object.entries(members)) {
      saved.set(key, Object.getOwnPropertyDescriptor(Object.prototype, key));
      Object.defineProperty(Object.prototype, key, descriptor);
    }
    return await run();
  } finally {
    for (const [key, previous] of saved) {
      if (previous === undefined) Reflect.deleteProperty(Object.prototype, key);
      else Object.defineProperty(Object.prototype, key, previous);
    }
    for (const [key, previous] of saved) {
      assert.equal(Object.hasOwn(Object.prototype, key), previous !== undefined, `Object.prototype.${key} is not as it was`);
    }
  }
}

/** A data member as a plain assignment (`Object.prototype[key] = value`) would create it. */
const polluted = (value: unknown): PropertyDescriptor => ({ value, writable: true, enumerable: true, configurable: true });

await test("data pollution: no injected kid from jwtVerify, no injected unprotectedHeader from jwsVerifyCompact (audit M1)", async () => {
  const key = await api.jwkGenerateOct(32);
  const jws = await api.jwsSignCompact(enc.encode("hi"), key, { protectedHeader: { alg: "HS256" } });
  const jwt = await api.jwtSign({ sub: "alice", exp: 9999999999 }, key, { alg: "HS256" });
  // A key with a `kid` (RFC 7517 §4.5): the result's `kid` is the verifying key's.
  const keyWithKid = { ...key, kid: "real-kid" };
  const jwtWithKid = await api.jwtSign({ sub: "alice", exp: 9999999999 }, keyWithKid, { alg: "HS256" });
  const jwe = await api.jweEncryptCompact(enc.encode("plaintext"), { enc: "A256GCM", recipients: [{ alg: "dir", key }] });

  const pollution = {
    kid: polluted("attacker-kid"),
    keyIndex: polluted(7),
    unprotectedHeader: polluted('{"x5u":"https://evil.example/"}'),
    protectedHeader: polluted('{"x5u":"https://evil.example/"}'),
    sharedUnprotectedHeader: polluted('{"x5u":"https://evil.example/"}'),
    recipientHeader: polluted('{"x5u":"https://evil.example/"}'),
    aad: polluted("attacker-aad"),
  };
  const [v, j, jk, d] = await withPrototype(pollution, async () => [
    await api.jwsVerifyCompact(jws, key, { allowedAlgs: ["HS256"] }),
    await api.jwtVerify(jwt, key, { allowedAlgs: ["HS256"] }),
    await api.jwtVerify(jwtWithKid, keyWithKid, { allowedAlgs: ["HS256"] }),
    await api.jweDecryptCompact(jwe, key, { allowedAlgs: ["dir"], allowedEnc: ["A256GCM"] }),
  ] as const);

  // RFC 7515 §7.1: a compact JWS has no unprotected header.
  assert.ok(!Object.hasOwn(v, "unprotectedHeader"), "jwsVerifyCompact: an injected own unprotectedHeader");
  assert.deepEqual(Object.keys(v).sort(), ["alg", "payload", "protectedHeader", "signatureIndex"]);
  assert.deepEqual({ ...v.protectedHeader }, { alg: "HS256" });
  assert.equal(dec.decode(v.payload), "hi");

  // A single key, not a JWK Set: no keyIndex (ADR 0029 §4); the token has no kid.
  for (const name of ["kid", "keyIndex"]) {
    assert.ok(!Object.hasOwn(j, name), `jwtVerify: an injected own ${name}`);
  }
  assert.deepEqual(Object.keys(j).sort(), ["alg", "claims", "header"]);
  assert.equal(j.claims["sub"], "alice");
  // The verifying key's own kid still comes through, not the polluted one.
  assert.ok(Object.hasOwn(jk, "kid"));
  assert.equal(jk.kid, "real-kid");

  // RFC 7516 §7.1: a compact JWE has no shared or per-recipient unprotected header and no aad.
  for (const name of ["sharedUnprotectedHeader", "recipientHeader", "aad"]) {
    assert.ok(!Object.hasOwn(d, name), `jweDecryptCompact: an injected own ${name}`);
  }
  assert.deepEqual(Object.keys(d).sort(), ["header", "plaintext", "protectedHeader", "recipientIndex"]);
  assert.equal(dec.decode(d.plaintext), "plaintext");
});

await test("a planted accessor on payload, plaintext and claims never receives the secret (audit I2)", async () => {
  const key = await api.jwkGenerateOct(32);
  const jws = await api.jwsSignCompact(enc.encode("secret payload"), key, { protectedHeader: { alg: "HS256" } });
  const jwe = await api.jweEncryptCompact(enc.encode("secret plaintext"), { enc: "A256GCM", recipients: [{ alg: "dir", key }] });
  const jwt = await api.jwtSign({ sub: "secret subject", exp: 9999999999 }, key, { alg: "HS256" });

  const received: [string, unknown][] = [];
  const accessor = (name: string): PropertyDescriptor => ({
    get: () => "planted",
    set: (value: unknown) => {
      received.push([name, value]);
    },
    configurable: true,
  });
  const [v, d, j] = await withPrototype(
    { payload: accessor("payload"), plaintext: accessor("plaintext"), claims: accessor("claims") },
    async () => [
      await api.jwsVerifyCompact(jws, key, { allowedAlgs: ["HS256"] }),
      await api.jweDecryptCompact(jwe, key, { allowedAlgs: ["dir"], allowedEnc: ["A256GCM"] }),
      await api.jwtVerify(jwt, key, { allowedAlgs: ["HS256"] }),
    ] as const,
  );

  assert.deepEqual(received.map(([name]) => name), [], "an Object.prototype setter received a result member");
  assert.ok(Object.hasOwn(v, "payload") && Object.hasOwn(d, "plaintext") && Object.hasOwn(j, "claims"));
  assert.equal(dec.decode(v.payload), "secret payload");
  assert.equal(dec.decode(d.plaintext), "secret plaintext");
  assert.equal(j.claims["sub"], "secret subject");
});
