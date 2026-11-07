// JSON-valued inputs are plain data, serialised from the caller's own members only (0013 F09,
// security audit M1 follow-up; ADR 0030 §2: JS takes JSON text or a plain object).
//
// `JSON.stringify` consults `toJSON` through the prototype chain and reads array holes through
// `Array.prototype`, so a prototype-pollution bug elsewhere in the host app could replace the
// claims an app signs, the key it uses or a header it sets (`jwtSign({ sub: "alice" })` sent
// `{"sub":"admin"}`). Every JSON-valued argument and record member of every operation is checked
// here with `Object.prototype.toJSON`, `Array.prototype.toJSON` and array-index pollution, at the
// top level and nested: the backend must receive exactly the caller's data.
import { assert, test } from "../node/builtins.js";
import { createApi } from "../src/api.js";
import { fakeBackend, type Fake, type Operation } from "./fake-backend.js";

const KEY = '{"kty":"oct","k":"AAAA"}';
const JWKS = '{"keys":[]}';
const PAYLOAD = new Uint8Array([104, 105]);
const VERIFIED = { alg: "HS256", payload: new Uint8Array(), signatureIndex: 0 };
const DECRYPTED = { plaintext: new Uint8Array(), header: "{}", recipientIndex: 0 };
const JWT = { claims: "{}", header: "{}", alg: "HS256" };
const NESTED = { inner: JWT, outerHeader: "{}", recipientIndex: 0 };

type Loose = (...args: unknown[]) => Promise<unknown>;
type Api = Record<string, Loose>;

function setup(): { api: Api; fake: Fake } {
  const fake = fakeBackend({
    handlers: {
      jwkParse: () => KEY,
      jwkToPublic: () => KEY,
      jwkThumbprint: () => "t",
      jwkThumbprintUri: () => "urn:t",
      jwksSelect: () => KEY,
      jwkToPem: () => "pem",
      jwkToDer: () => new Uint8Array([1]),
      jwsSignCompact: () => "a.b.c",
      jwsSignFlattened: () => "{}",
      jwsSignGeneral: () => "{}",
      jwsVerifyCompact: () => VERIFIED,
      jwsVerifyJson: () => VERIFIED,
      jweEncryptCompact: () => "a.b.c.d.e",
      jweEncryptJson: () => "{}",
      jweDecryptCompact: () => DECRYPTED,
      jweDecryptJson: () => DECRYPTED,
      jwtSign: () => "a.b.c",
      jwtVerify: () => JWT,
      jwtVerifyWithJwks: () => JWT,
      jwtEncryptNested: () => "a.b.c.d.e",
      jwtDecryptNested: () => NESTED,
      jwtDecryptNestedWithJwks: () => NESTED,
    },
  });
  return { api: createApi(fake.backend) as unknown as Api, fake };
}

/**
 * A JSON object with nested objects and arrays at several depths (a JWK, a JWK Set, claims or a
 * header, as far as the facade is concerned: the fake backend does not validate). Built fresh for
 * each call so no test can see another's object.
 */
function deep(): Record<string, unknown> {
  return {
    kty: "oct",
    k: "AAAA",
    sub: "alice",
    keys: [{ kty: "oct", k: "AAAA" }, { kty: "oct", k: "BBBB", key_ops: ["sign", "verify"] }],
    aud: ["https://a.example", "https://b.example"],
    nested: { a: [1, { b: "c" }, []], d: null, e: true, f: -0.5, g: {} },
  };
}

/** What the backend must receive for {@link deep}, whatever the prototypes hold. */
const DEEP_TEXT =
  '{"kty":"oct","k":"AAAA","sub":"alice","keys":[{"kty":"oct","k":"AAAA"},{"kty":"oct","k":"BBBB","key_ops":["sign","verify"]}],' +
  '"aud":["https://a.example","https://b.example"],"nested":{"a":[1,{"b":"c"},[]],"d":null,"e":true,"f":-0.5,"g":{}}}';

/** One JSON-valued input: how to pass a value there, and where the backend receives its text. */
interface Site {
  readonly label: string;
  readonly op: Operation;
  readonly call: (api: Api, v: unknown) => Promise<unknown>;
  readonly text: (args: readonly unknown[]) => unknown;
}

const get = (v: unknown, ...keys: (string | number)[]): unknown => {
  let x = v;
  for (const p of keys) x = (x as Record<string | number, unknown>)[p];
  return x;
};

const DECRYPT = { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] };
const VERIFY = { allowedAlgs: ["HS256"] };
const enc = (v: unknown, where: "protectedHeader" | "sharedUnprotectedHeader" | "key" | "header"): Record<string, unknown> =>
  where === "key" || where === "header"
    ? { enc: "A128GCM", recipients: [{ alg: "A128KW", key: where === "key" ? v : KEY, ...(where === "header" ? { header: v } : {}) }] }
    : { enc: "A128GCM", recipients: [{ alg: "A128KW", key: KEY }], [where]: v };

/** Every JSON-valued argument and record member of the facade (BACKEND.md's operation table). */
const SITES: readonly Site[] = [
  { label: "jwkParse jwk", op: "jwkParse", call: (a, v) => a["jwkParse"]!(v), text: (x) => x[0] },
  { label: "jwkToPublic jwk", op: "jwkToPublic", call: (a, v) => a["jwkToPublic"]!(v), text: (x) => x[0] },
  { label: "jwkThumbprint jwk", op: "jwkThumbprint", call: (a, v) => a["jwkThumbprint"]!(v), text: (x) => x[0] },
  { label: "jwkThumbprintUri jwk", op: "jwkThumbprintUri", call: (a, v) => a["jwkThumbprintUri"]!(v), text: (x) => x[0] },
  { label: "jwksSelect jwks", op: "jwksSelect", call: (a, v) => a["jwksSelect"]!(v), text: (x) => x[0] },
  { label: "jwkToPem jwk", op: "jwkToPem", call: (a, v) => a["jwkToPem"]!(v, "pkcs8"), text: (x) => x[0] },
  { label: "jwkToDer jwk", op: "jwkToDer", call: (a, v) => a["jwkToDer"]!(v, "pkcs8"), text: (x) => x[0] },
  { label: "jwsSignCompact key", op: "jwsSignCompact", call: (a, v) => a["jwsSignCompact"]!(PAYLOAD, v, {}), text: (x) => x[1] },
  {
    label: "JwsSignOptions.protectedHeader",
    op: "jwsSignCompact",
    call: (a, v) => a["jwsSignCompact"]!(PAYLOAD, KEY, { protectedHeader: v }),
    text: (x) => get(x[2], "protectedHeader"),
  },
  { label: "JwsSigner.key (flattened)", op: "jwsSignFlattened", call: (a, v) => a["jwsSignFlattened"]!(PAYLOAD, { key: v }), text: (x) => get(x[1], "key") },
  {
    label: "JwsSigner.protectedHeader (flattened)",
    op: "jwsSignFlattened",
    call: (a, v) => a["jwsSignFlattened"]!(PAYLOAD, { key: KEY, protectedHeader: v }),
    text: (x) => get(x[1], "protectedHeader"),
  },
  {
    label: "JwsSigner.unprotectedHeader (flattened)",
    op: "jwsSignFlattened",
    call: (a, v) => a["jwsSignFlattened"]!(PAYLOAD, { key: KEY, unprotectedHeader: v }),
    text: (x) => get(x[1], "unprotectedHeader"),
  },
  { label: "JwsSigner.key (general)", op: "jwsSignGeneral", call: (a, v) => a["jwsSignGeneral"]!(PAYLOAD, [{ key: v }]), text: (x) => get(x[1], 0, "key") },
  {
    label: "JwsSigner.protectedHeader (general)",
    op: "jwsSignGeneral",
    call: (a, v) => a["jwsSignGeneral"]!(PAYLOAD, [{ key: KEY, protectedHeader: v }]),
    text: (x) => get(x[1], 0, "protectedHeader"),
  },
  {
    label: "JwsSigner.unprotectedHeader (general)",
    op: "jwsSignGeneral",
    call: (a, v) => a["jwsSignGeneral"]!(PAYLOAD, [{ key: KEY, unprotectedHeader: v }]),
    text: (x) => get(x[1], 0, "unprotectedHeader"),
  },
  { label: "jwsVerifyCompact key", op: "jwsVerifyCompact", call: (a, v) => a["jwsVerifyCompact"]!("a.b.c", v, VERIFY), text: (x) => x[1] },
  { label: "jwsVerifyJson jws", op: "jwsVerifyJson", call: (a, v) => a["jwsVerifyJson"]!(v, KEY, VERIFY), text: (x) => x[0] },
  { label: "jwsVerifyJson key", op: "jwsVerifyJson", call: (a, v) => a["jwsVerifyJson"]!("{}", v, VERIFY), text: (x) => x[1] },
  ...(["jweEncryptCompact", "jweEncryptJson", "jwtEncryptNested"] as const).flatMap((op): Site[] => {
    const call =
      op === "jweEncryptCompact"
        ? (a: Api, o: unknown) => a[op]!(PAYLOAD, o)
        : op === "jweEncryptJson"
          ? (a: Api, o: unknown) => a[op]!(PAYLOAD, o, "general")
          : (a: Api, o: unknown) => a[op]!("a.b.c", o);
    return [
      { label: `JweEncryptOptions.protectedHeader (${op})`, op, call: (a, v) => call(a, enc(v, "protectedHeader")), text: (x) => get(x[1], "protectedHeader") },
      {
        label: `JweEncryptOptions.sharedUnprotectedHeader (${op})`,
        op,
        call: (a, v) => call(a, enc(v, "sharedUnprotectedHeader")),
        text: (x) => get(x[1], "sharedUnprotectedHeader"),
      },
      { label: `JweRecipient.key (${op})`, op, call: (a, v) => call(a, enc(v, "key")), text: (x) => get(x[1], "recipients", 0, "key") },
      { label: `JweRecipient.header (${op})`, op, call: (a, v) => call(a, enc(v, "header")), text: (x) => get(x[1], "recipients", 0, "header") },
    ];
  }),
  { label: "jweDecryptCompact key", op: "jweDecryptCompact", call: (a, v) => a["jweDecryptCompact"]!("a.b.c.d.e", v, DECRYPT), text: (x) => x[1] },
  { label: "jweDecryptJson jwe", op: "jweDecryptJson", call: (a, v) => a["jweDecryptJson"]!(v, KEY, DECRYPT), text: (x) => x[0] },
  { label: "jweDecryptJson key", op: "jweDecryptJson", call: (a, v) => a["jweDecryptJson"]!("{}", v, DECRYPT), text: (x) => x[1] },
  { label: "jwtSign claims", op: "jwtSign", call: (a, v) => a["jwtSign"]!(v, KEY, { alg: "HS256" }), text: (x) => x[0] },
  { label: "jwtSign key", op: "jwtSign", call: (a, v) => a["jwtSign"]!({ sub: "x" }, v, { alg: "HS256" }), text: (x) => x[1] },
  { label: "JwtSignOptions.header", op: "jwtSign", call: (a, v) => a["jwtSign"]!({ sub: "x" }, KEY, { alg: "HS256", header: v }), text: (x) => get(x[2], "header") },
  { label: "jwtVerify key", op: "jwtVerify", call: (a, v) => a["jwtVerify"]!("a.b.c", v, VERIFY), text: (x) => x[1] },
  { label: "jwtVerifyWithJwks jwks", op: "jwtVerifyWithJwks", call: (a, v) => a["jwtVerifyWithJwks"]!("a.b.c", v, VERIFY), text: (x) => x[1] },
  { label: "jwtDecryptNested decryptKey", op: "jwtDecryptNested", call: (a, v) => a["jwtDecryptNested"]!("t", v, DECRYPT, KEY, VERIFY), text: (x) => x[1] },
  { label: "jwtDecryptNested key", op: "jwtDecryptNested", call: (a, v) => a["jwtDecryptNested"]!("t", KEY, DECRYPT, v, VERIFY), text: (x) => x[3] },
  {
    label: "jwtDecryptNestedWithJwks decryptKey",
    op: "jwtDecryptNestedWithJwks",
    call: (a, v) => a["jwtDecryptNestedWithJwks"]!("t", v, DECRYPT, JWKS, VERIFY),
    text: (x) => x[1],
  },
  {
    label: "jwtDecryptNestedWithJwks jwks",
    op: "jwtDecryptNestedWithJwks",
    call: (a, v) => a["jwtDecryptNestedWithJwks"]!("t", KEY, DECRYPT, v, VERIFY),
    text: (x) => x[3],
  },
];

/**
 * Every operation with a JSON-valued argument or record member, from BACKEND.md's table (jwk,
 * jwks, claims, header and JSON-serialization arguments, and the records' key and header members).
 */
const JSON_OPERATIONS: readonly Operation[] = [
  "jwkParse",
  "jwkToPublic",
  "jwkThumbprint",
  "jwkThumbprintUri",
  "jwksSelect",
  "jwkToPem",
  "jwkToDer",
  "jwsSignCompact",
  "jwsSignFlattened",
  "jwsSignGeneral",
  "jwsVerifyCompact",
  "jwsVerifyJson",
  "jweEncryptCompact",
  "jweEncryptJson",
  "jweDecryptCompact",
  "jweDecryptJson",
  "jwtSign",
  "jwtVerify",
  "jwtVerifyWithJwks",
  "jwtEncryptNested",
  "jwtDecryptNested",
  "jwtDecryptNestedWithJwks",
];

/**
 * Calls `site` with `target[member] = value` set as a pollution bug sets it (a plain, enumerable
 * assignment) only while the operation is called. The facade serialises every JSON input
 * synchronously at the call (0013 B06), so the pollution is removed before anything is awaited,
 * and the test runner never sees it.
 */
function callPolluted(target: object, member: PropertyKey, value: unknown, call: () => Promise<unknown>): Promise<unknown> {
  assert.ok(!Object.hasOwn(target, member), `${String(member)} is not already on the prototype`);
  (target as Record<PropertyKey, unknown>)[member] = value;
  try {
    return call();
  } finally {
    delete (target as Record<PropertyKey, unknown>)[member];
  }
}

/** Pollution that changes `JSON.stringify`'s output for plain data. */
const POLLUTIONS: readonly { label: string; target: object; member: PropertyKey; value: unknown }[] = [
  {
    label: "Object.prototype.toJSON",
    target: Object.prototype,
    member: "toJSON",
    value: function (): unknown {
      return { sub: "admin", kty: "oct", k: "QkJCQg", jku: "https://attacker.example/jwks.json" };
    },
  },
  {
    label: "Array.prototype.toJSON",
    target: Array.prototype,
    member: "toJSON",
    value: function (): unknown {
      return ["https://attacker.example"];
    },
  },
];

test("the JSON input sites cover every operation with a JSON-valued argument or member", () => {
  assert.deepEqual([...new Set(SITES.map((s) => s.op))].sort(), [...JSON_OPERATIONS].sort());
  for (const member of ["key", "protectedHeader", "unprotectedHeader", "sharedUnprotectedHeader", "header"]) {
    assert.ok(
      SITES.some((s) => s.label.includes(`.${member} `) || s.label.endsWith(`.${member}`)),
      `a site for the record member ${member}`,
    );
  }
});

test("unpolluted, every JSON input site sends the object's JSON.stringify text", async () => {
  assert.equal(JSON.stringify(deep()), DEEP_TEXT);
  for (const site of SITES) {
    const { api, fake } = setup();
    await site.call(api, deep());
    assert.equal(site.text(fake.of(site.op)[0]?.args ?? []), DEEP_TEXT, site.label);
  }
});

for (const p of POLLUTIONS) {
  test(`${p.label} never changes a JSON input, at the top level or nested`, async () => {
    for (const site of SITES) {
      const { api, fake } = setup();
      await callPolluted(p.target, p.member, p.value, () => site.call(api, deep()));
      assert.equal(site.text(fake.of(site.op)[0]?.args ?? []), DEEP_TEXT, `${site.label}: the caller's data, not the toJSON's`);
    }
  });
}

test("Object.prototype.toJSON and Array.prototype.toJSON polluted together change nothing", async () => {
  for (const site of SITES) {
    const { api, fake } = setup();
    const [o, a] = POLLUTIONS;
    await callPolluted(o!.target, o!.member, o!.value, () => callPolluted(a!.target, a!.member, a!.value, () => site.call(api, deep())));
    assert.equal(site.text(fake.of(site.op)[0]?.args ?? []), DEEP_TEXT, site.label);
  }
});

test("a toJSON on a null-prototype object's chain, or on a nested object's, is never called", async () => {
  // The audit's case: jwtSign({ sub: "alice" }) must send alice, never the polluted admin.
  const { api, fake } = setup();
  let called = 0;
  await callPolluted(
    Object.prototype,
    "toJSON",
    function (): unknown {
      called++;
      return { sub: "admin" };
    },
    () => api["jwtSign"]!({ sub: "alice", ctx: { roles: ["user"] } }, { kty: "oct", k: "AAAA" }, { alg: "HS256", header: { kid: "k1" } }),
  );
  assert.equal(called, 0, "no toJSON is called");
  const args = fake.of("jwtSign")[0]?.args ?? [];
  assert.equal(args[0], '{"sub":"alice","ctx":{"roles":["user"]}}');
  assert.equal(args[1], '{"kty":"oct","k":"AAAA"}');
  assert.equal(get(args[2], "header"), '{"kid":"k1"}');
});

test("an array hole is a TypeError, never read through Array.prototype, at any depth", async () => {
  const holey = (): Record<string, unknown> => ({ keys: [{ kty: "oct", k: "AAAA" }, , { kty: "oct", k: "CCCC" }], nested: { aud: ["a", , "c"] } });
  for (const site of SITES) {
    for (const pollute of [false, true]) {
      const { api, fake } = setup();
      const call = (): Promise<unknown> => site.call(api, holey());
      const p = pollute ? callPolluted(Array.prototype, 1, { kty: "oct", k: "QkJCQg" }, call) : call();
      await assert.rejects(p, TypeError, `${site.label} (polluted: ${pollute})`);
      assert.equal(fake.of(site.op).length, 0, `${site.label}: the backend is not called`);
    }
  }
});

test("an own toJSON member is not honoured: a function is not JSON data (TypeError)", async () => {
  const { api, fake } = setup();
  const own = { kty: "oct", k: "AAAA", toJSON: () => ({ kty: "oct", k: "QkJCQg" }) };
  await assert.rejects(api["jwkParse"]!(own), TypeError);
  await assert.rejects(api["jwkParse"]!({ kty: "oct", nested: { toJSON: () => "x" } }), TypeError);
  assert.equal(fake.calls.length, 0);
});

test("values that aren't JSON data are TypeErrors at any depth, even with a polluted toJSON", async () => {
  class Claims {
    sub = "alice";
  }
  const notData: readonly unknown[] = [
    new Date(0),
    new Map([["sub", "alice"]]),
    new Set(["a"]),
    new Claims(),
    new String("alice"),
    new Number(1),
    new Boolean(true),
    new Uint8Array([1]),
    /re/,
    Object.create({ inherited: true }) as object,
    () => "x",
    Symbol("s"),
    1n,
  ];
  for (const bad of notData) {
    for (const wrap of [(v: unknown) => ({ kty: "oct", v }), (v: unknown) => ({ kty: "oct", a: [v] }), (v: unknown) => ({ kty: "oct", o: { p: [{ v }] } })]) {
      const { api, fake } = setup();
      await assert.rejects(api["jwkParse"]!(wrap(bad)), TypeError, String(typeof bad));
      assert.equal(fake.calls.length, 0);
    }
  }
  // BigInt.prototype.toJSON would make JSON.stringify accept a BigInt; the facade never asks it.
  const { api, fake } = setup();
  await assert.rejects(
    callPolluted(BigInt.prototype, "toJSON", () => "AQAB", () => api["jwkParse"]!({ kty: "RSA", e: 65537n })),
    TypeError,
  );
  assert.equal(fake.calls.length, 0);
});

test("JSON data serialises exactly as JSON.stringify does when nothing is polluted", async () => {
  const fromText = JSON.parse('{"__proto__":{"a":1},"2":"two","1":"one","x":"y"}') as Record<string, unknown>;
  const values: readonly Record<string, unknown>[] = [
    {},
    { s: 'quote " backslash \\ newline \n tab \t nul \u0000 bell \u0007 del \u007f', u: "é ☃ 𝄞", lone: "\ud800 \udfff" },
    { n: [0, -0, 1, -1, 1.5, 1e21, 1e-7, 2 ** 53, Number.MAX_VALUE, Number.MIN_VALUE] },
    { nonFinite: [NaN, Infinity, -Infinity], also: NaN },
    { b: [true, false], z: null, e: [], o: {} },
    { undef: undefined, keep: 1, arr: [undefined, 1] },
    { "": "empty key", "a\"b": "escaped key", " ": "line separator" },
    fromText,
    Object.assign(Object.create(null) as object, { kty: "oct", nested: Object.assign(Object.create(null) as object, { a: [1] }) }) as Record<string, unknown>,
    { deep: [[[[[[[[[["x"]]]]]]]]]] },
  ];
  for (const v of values) {
    const { api, fake } = setup();
    await api["jwkParse"]!(v);
    assert.equal(fake.of("jwkParse")[0]?.args[0], JSON.stringify(v), JSON.stringify(v));
  }
});

test("a shared (acyclic) reference is fine; a cycle at any depth is a TypeError", async () => {
  const { api, fake } = setup();
  const shared = { kty: "oct" };
  await api["jwksSelect"]!({ keys: [shared, shared] });
  assert.equal(fake.of("jwksSelect")[0]?.args[0], '{"keys":[{"kty":"oct"},{"kty":"oct"}]}');
  const cyclic: Record<string, unknown> = { kty: "oct" };
  cyclic["inner"] = { list: [cyclic] };
  await assert.rejects(api["jwkParse"]!(cyclic), TypeError);
  const arr: unknown[] = [];
  arr.push(arr);
  await assert.rejects(api["jwkParse"]!({ a: arr }), TypeError);
});

test("a nesting too deep for the stack is a TypeError, not a RangeError", async () => {
  const { api } = setup();
  let v: unknown = "x";
  for (let i = 0; i < 200_000; i++) v = [v];
  await assert.rejects(api["jwkParse"]!({ v }), (e: unknown) => e instanceof TypeError);
});

test("each own member is read once, and a member deleted by an earlier getter is not read through the prototype", async () => {
  const { api, fake } = setup();
  let reads = 0;
  const v = {
    get a(): string {
      reads++;
      return reads === 1 ? "first" : "second";
    },
    b: "own",
  };
  await api["jwkParse"]!(v);
  assert.equal(reads, 1);
  assert.equal(fake.of("jwkParse")[0]?.args[0], '{"a":"first","b":"own"}');

  const sneaky: Record<string, unknown> = {
    get a(): string {
      delete sneaky["b"];
      return "x";
    },
    b: "own",
  };
  const { api: api2, fake: fake2 } = setup();
  await callPolluted(Object.prototype, "b", "https://attacker.example", () => api2["jwkParse"]!(sneaky));
  assert.equal(fake2.of("jwkParse")[0]?.args[0], '{"a":"x"}');
});

test("an error names the argument, never the value", async () => {
  const { api } = setup();
  await assert.rejects(api["jwtSign"]!({ secret: "s3cr3t-value", when: new Date(0) }, KEY, { alg: "HS256" }), (e: unknown) => {
    assert.ok(e instanceof TypeError);
    assert.match(e.message, /jwtSign: claims/);
    assert.doesNotMatch(e.message, /s3cr3t|secret|when/);
    return true;
  });
});
