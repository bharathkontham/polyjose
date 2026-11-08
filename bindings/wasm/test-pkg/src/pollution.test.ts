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
 * - **Accessor and read-only traps on the optional result members** (0013 F13, 0006 F08): `aad`,
 *   `kid`, `keyIndex`, `protectedHeader`, `unprotectedHeader`, `sharedUnprotectedHeader` and
 *   `recipientHeader`. The facade's result objects keep `Object.prototype`, and it creates each
 *   present optional member with `Object.defineProperty`, never an assignment: an assignment
 *   (ECMA-262 OrdinarySet, §10.1.9.2) to a member the object doesn't own calls an inherited
 *   setter with the value (the `aad` is secret, ADR 0050 §4) and leaves no own member, and an
 *   inherited non-writable member makes it a TypeError in strict code. A facade before F13
 *   (`put()` assigned `out[key] = value`) fails both kinds.
 * - **Index traps on `Array.prototype`** (0013 F13): `Array.prototype.push` stores the next
 *   element by assignment (ECMA-262 §23.1.3.23, `Set(O, len, E, true)`), so an accessor on
 *   `Array.prototype[0]` would receive a byte copy (the plaintext, payload, `aad`) or a
 *   `JwsSigner`/`JweRecipient` record with its key, and a read-only one would make the call a
 *   TypeError. The facade appends with `Object.defineProperty` at `length` instead. Checked on a
 *   multi-signer `jwsSignGeneral` (RFC 7515 §7.2.1) and a multi-recipient `jweEncryptJson`
 *   (RFC 7516 §7.2.1). A facade before F13 (`copies.push`, `out.push` in `list()`) fails both.
 *
 * Every test puts the prototypes back exactly as they were, in a `finally`, before it asserts.
 */
import * as api from "@polyjose/wasm";
import type { JweDecrypted, JwsVerified, JwtVerified } from "@polyjose/wasm";
import { assert, test } from "./node.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Defines `members` on `target`; the returned function restores each one as it was, and checks it. */
function plantOn(target: object, label: string, members: Record<string, PropertyDescriptor>): () => void {
  const saved = new Map<string, PropertyDescriptor | undefined>();
  const restore = (): void => {
    for (const [key, previous] of saved) {
      if (previous === undefined) Reflect.deleteProperty(target, key);
      else Object.defineProperty(target, key, previous);
    }
    for (const [key, previous] of saved) {
      assert.equal(Object.hasOwn(target, key), previous !== undefined, `${label}.${key} is not as it was`);
    }
  };
  try {
    for (const [key, descriptor] of Object.entries(members)) {
      saved.set(key, Object.getOwnPropertyDescriptor(target, key));
      Object.defineProperty(target, key, descriptor);
    }
  } catch (e) {
    restore();
    throw e;
  }
  return restore;
}

/** Runs `run` with `members` defined on `Object.prototype`, then restores each one as it was. */
async function withPrototype<T>(members: Record<string, PropertyDescriptor>, run: () => Promise<T>): Promise<T> {
  const restore = plantOn(Object.prototype, "Object.prototype", members);
  try {
    return await run();
  } finally {
    restore();
  }
}

/**
 * Starts `start` with `members` defined on `target` and restores them before anything is awaited.
 * The facade validates, copies and appends every argument synchronously, inside the call
 * (BACKEND.md "Inputs are taken at the call", 0013 B06), and once the module is instantiated it
 * also calls the adapter (and so the glue) before its first await, so the window covers all of
 * them while Node itself runs untouched.
 */
function startWith<T>(target: object, label: string, members: Record<string, PropertyDescriptor>, start: () => Promise<T>): Promise<T> {
  const restore = plantOn(target, label, members);
  try {
    return start();
  } finally {
    restore();
  }
}

/** Every write a trap's setter saw, kept without an array append (the traps may sit on `Array.prototype`). */
class Writes {
  readonly seen = new Map<number, [string, unknown]>();
  record(member: string, value: unknown): void {
    this.seen.set(this.seen.size, [member, value]);
  }
  members(): string[] {
    return Array.from(this.seen.values(), ([member]) => member);
  }
}

type TrapKind = "accessor" | "readonly";
const TRAP_KINDS: readonly TrapKind[] = ["accessor", "readonly"];

/** For each member, a setter that records what it receives (and stores nothing), or an inherited non-writable value. */
function traps(kind: TrapKind, members: readonly string[], writes: Writes, polluted: (member: string) => unknown): Record<string, PropertyDescriptor> {
  const out: Record<string, PropertyDescriptor> = {};
  for (const member of members) {
    const value = polluted(member);
    out[member] =
      kind === "accessor"
        ? { get: () => value, set: (v: unknown) => writes.record(member, v), enumerable: false, configurable: true }
        : { value, writable: false, enumerable: false, configurable: true };
  }
  return out;
}

/** `holder[member]` is an own, enumerable, writable, configurable data property; returns its value. */
function ownData(holder: object, member: string, label: string): unknown {
  const d = Object.getOwnPropertyDescriptor(holder, member);
  assert.ok(d !== undefined, `${label}: no own ${member}`);
  assert.ok("value" in d && d.get === undefined && d.set === undefined, `${label}: ${member} is not a data property`);
  assert.ok(d.enumerable === true && d.writable === true && d.configurable === true, `${label}: ${member} is not enumerable, writable and configurable`);
  return d.value;
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

/** The optional result members the facade creates only when the backend returns them (0013 F13). */
const OPTIONAL_MEMBERS = ["aad", "kid", "keyIndex", "protectedHeader", "unprotectedHeader", "sharedUnprotectedHeader", "recipientHeader"] as const;

for (const kind of TRAP_KINDS) {
  await test(`${kind} traps on Object.prototype for aad, kid, keyIndex and the optional headers: results own them as data, absent ones stay absent (F13)`, async () => {
    const keyNoKid = await api.jwkGenerateOct(32);
    const key = { ...keyNoKid, kid: "key-b" };
    const other = { ...(await api.jwkGenerateOct(32)), kid: "key-a" };
    const aad = enc.encode("secret aad");
    // RFC 7515 §7.2.2: a flattened JWS with a protected and an unprotected header (the `kid`
    // names the key, RFC 7515 §4.1.4).
    const jwsJson = await api.jwsSignFlattened(enc.encode("payload"), { key, protectedHeader: { alg: "HS256" }, unprotectedHeader: { kid: "key-b" } });
    // RFC 7516 §7.2.2: a flattened JWE with all three headers and an aad (§5.1 step 14).
    const jweJson = await api.jweEncryptJson(
      enc.encode("plaintext"),
      { enc: "A256GCM", recipients: [{ alg: "A256KW", key, header: { kid: "key-b" } }], protectedHeader: { cty: "text/plain" }, sharedUnprotectedHeader: { a: 1 }, aad },
      "flattened",
    );
    const jweJsonNoAad = await api.jweEncryptJson(enc.encode("plaintext"), { enc: "A256GCM", recipients: [{ alg: "dir", key }] }, "flattened");
    const jwsCompact = await api.jwsSignCompact(enc.encode("payload"), key, { protectedHeader: { alg: "HS256" } });
    const jweCompact = await api.jweEncryptCompact(enc.encode("plaintext"), { enc: "A256GCM", recipients: [{ alg: "dir", key }] });
    const jwt = await api.jwtSign({ sub: "alice", exp: 9999999999 }, key, { alg: "HS256" });
    const jwtNoKid = await api.jwtSign({ sub: "alice", exp: 9999999999 }, keyNoKid, { alg: "HS256" });
    // RFC 7517 §5: the verifying key is the second of the set, so `keyIndex` is 1 (ADR 0029 §4).
    const jwks = { keys: [other, key] };
    const verifyJws = { allowedAlgs: ["HS256"] };

    // name -> [the call, the optional members its result must have]. Each is run once clean and
    // once under the traps; the members must be equal.
    const cases: [string, () => Promise<object>, readonly string[]][] = [
      ["jwsVerifyJson (flattened)", () => api.jwsVerifyJson(jwsJson, key, verifyJws), ["protectedHeader", "unprotectedHeader"]],
      [
        "jweDecryptJson (flattened, aad)",
        () => api.jweDecryptJson(jweJson, key, { allowedAlgs: ["A256KW"], allowedEnc: ["A256GCM"] }),
        ["protectedHeader", "sharedUnprotectedHeader", "recipientHeader", "aad"],
      ],
      ["jwtVerifyWithJwks", () => api.jwtVerifyWithJwks(jwt, jwks, verifyJws), ["keyIndex", "kid"]],
      // Absent members: RFC 7515 §7.1 (no unprotected header), RFC 7516 §7.1 (no shared or
      // per-recipient header, no aad), a JWE JSON without aad, and one key without a kid (no
      // keyIndex, no kid; ADR 0029 §4).
      ["jwsVerifyCompact", () => api.jwsVerifyCompact(jwsCompact, key, verifyJws), ["protectedHeader"]],
      ["jweDecryptCompact", () => api.jweDecryptCompact(jweCompact, key, { allowedAlgs: ["dir"], allowedEnc: ["A256GCM"] }), ["protectedHeader"]],
      ["jweDecryptJson (no aad)", () => api.jweDecryptJson(jweJsonNoAad, key, { allowedAlgs: ["dir"], allowedEnc: ["A256GCM"] }), ["protectedHeader"]],
      ["jwtVerify (key without kid)", () => api.jwtVerify(jwtNoKid, keyNoKid, verifyJws), []],
    ];
    const clean: object[] = [];
    for (const [, call] of cases) clean.push(await call());

    const writes = new Writes();
    const got = await withPrototype(traps(kind, OPTIONAL_MEMBERS, writes, (m) => `polluted ${m}`), async () => {
      const out: object[] = [];
      for (const [, call] of cases) out.push(await call());
      return out;
    });

    assert.deepEqual(writes.members(), [], "an Object.prototype setter received a result member");
    cases.forEach(([name, , present], i) => {
      const want = clean[i] as Record<string, unknown>;
      const result = got[i] as Record<string, unknown>;
      for (const member of OPTIONAL_MEMBERS) {
        if (present.includes(member)) {
          assert.ok(Object.hasOwn(want, member), `${name}: the clean result has no ${member}`);
          assert.deepEqual(ownData(result, member, name), want[member], `${name}: ${member} differs from the clean result`);
        } else {
          assert.ok(!Object.hasOwn(want, member) && !Object.hasOwn(result, member), `${name}: an own ${member}, which should be absent`);
        }
      }
    });
    // The values themselves, not only their equality with the clean run.
    const [vj, dj, jk] = got as [JwsVerified, JweDecrypted, JwtVerified];
    assert.deepEqual({ ...vj.unprotectedHeader }, { kid: "key-b" });
    assert.deepEqual({ ...dj.recipientHeader }, { kid: "key-b" });
    assert.deepEqual({ ...dj.sharedUnprotectedHeader }, { a: 1 });
    assert.equal(dj.protectedHeader?.["cty"], "text/plain");
    assert.deepEqual(Array.from(dj.aad ?? []), Array.from(aad));
    assert.equal(jk.keyIndex, 1);
    assert.equal(jk.kid, "key-b");
  });
}

/** Index members 0..n-1, the keys `push` would write on a fresh array. */
const INDICES = Array.from({ length: 8 }, (_, i) => String(i));

for (const kind of TRAP_KINDS) {
  await test(`${kind} index traps on Array.prototype: no key or byte copy of a multi-signer jwsSignGeneral or a multi-recipient jweEncryptJson reaches them (F13)`, async () => {
    // One key per use (RFC 7518 §3.2: an HS512 key has at least 64 bytes; §4.4, §4.7: 32 for
    // A256KW and A256GCMKW), each with the `kid` its header names (RFC 7517 §4.5).
    const withKid = async (bytes: number, kid: string) => ({ ...(await api.jwkGenerateOct(bytes)), kid });
    const s1 = await withKid(32, "s1");
    const s2 = await withKid(64, "s2");
    const r1 = await withKid(32, "r1");
    const r2 = await withKid(32, "r2");
    const r3 = await withKid(32, "r3");
    const payload = enc.encode("secret payload");
    const plaintext = enc.encode("secret plaintext");
    const aad = enc.encode("secret aad");
    // RFC 7515 §7.2.1: two signers; RFC 7516 §7.2.1: three recipients, two key-wrap algorithms.
    const signers = [
      { key: s1, protectedHeader: { alg: "HS256" }, unprotectedHeader: { kid: "s1" } },
      { key: s2, protectedHeader: { alg: "HS512" }, unprotectedHeader: { kid: "s2" } },
    ];
    const recipients = [
      { alg: "A256KW", key: r1, header: { kid: "r1" } },
      { alg: "A256KW", key: r2, header: { kid: "r2" } },
      { alg: "A256GCMKW", key: r3, header: { kid: "r3" } },
    ];
    const encryptOptions = { enc: "A256GCM", recipients, aad, protectedHeader: { cty: "text/plain" } };
    // Warms the module, so each call below reaches the adapter and the glue inside the window.
    await api.version();

    const writes = new Writes();
    const pending = startWith(Array.prototype, "Array.prototype", traps(kind, INDICES, writes, () => "attacker"), () =>
      Promise.all([api.jwsSignGeneral(payload, signers), api.jweEncryptJson(plaintext, encryptOptions, "general")]),
    );
    const [jws, jwe] = await pending;

    // Nothing at all reached a setter, so no key, record or byte copy did.
    assert.deepEqual(writes.members(), [], "an Array.prototype index setter received an element");
    // RFC 7515 §5.2: each signature verifies with its own key.
    const sigs = (JSON.parse(jws) as { signatures: unknown[] }).signatures;
    assert.equal(sigs.length, 2);
    for (const [i, key, alg] of [[0, s1, "HS256"], [1, s2, "HS512"]] as const) {
      const v = await api.jwsVerifyJson(JSON.stringify({ payload: JSON.parse(jws).payload, ...(sigs[i] as object) }), key, { allowedAlgs: [alg] });
      assert.equal(dec.decode(v.payload), "secret payload", `signer ${i}`);
    }
    // RFC 7516 §5.2: each recipient decrypts the same plaintext and aad.
    assert.equal((JSON.parse(jwe) as { recipients: unknown[] }).recipients.length, 3);
    for (const [i, key, alg] of [[0, r1, "A256KW"], [1, r2, "A256KW"], [2, r3, "A256GCMKW"]] as const) {
      const d = await api.jweDecryptJson(jwe, key, { allowedAlgs: [alg], allowedEnc: ["A256GCM"] });
      assert.equal(dec.decode(d.plaintext), "secret plaintext", `recipient ${i}`);
      assert.equal(dec.decode(d.aad ?? new Uint8Array()), "secret aad", `recipient ${i}`);
    }
  });
}
