// Backend results are read by their own members only (0013 F09, security audit M1 follow-up).
// BACKEND.md: an optional result field may be absent, `undefined` or `null`. An absent one must
// stay absent when a prototype-pollution bug elsewhere in the host app has put a member of that
// name on `Object.prototype`: otherwise a polluted `kid`, `keyIndex`, header or `aad` would come
// back to the caller as if the core had returned it. A required member the backend left out is a
// TypeError, never filled in from the prototype. Every result record and field is taken from
// bindings/api-inventory.txt.
import { assert, fs, path, process, test } from "../node/builtins.js";
import { createApi, PolyjoseError } from "../src/api.js";
import { coded, fakeBackend, type Operation } from "./fake-backend.js";
import { ownData, TRAP_KINDS, withTraps } from "./traps.js";

const KEY = '{"kty":"oct","k":"AAAA"}';
const JWKS = '{"keys":[]}';
const DECRYPT = { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] };
const VERIFY = { allowedAlgs: ["HS256"] };

type Loose = (...args: unknown[]) => Promise<unknown>;
type Api = Record<string, Loose>;

/** Result records and their fields from bindings/api-inventory.txt: name → [field, optional]. */
function inventoryResultRecords(): Map<string, { name: string; optional: boolean }[]> {
  const text = fs.readFileSync(path.resolve(process.cwd(), "../api-inventory.txt"), "utf8");
  const records = new Map<string, { name: string; optional: boolean }[]>();
  let current: { name: string; optional: boolean }[] | undefined;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    const rec = /^record (\w+)$/.exec(line);
    if (rec !== null) {
      const name = rec[1] ?? "";
      current = /(Verified|Decrypted)$/.test(name) ? [] : undefined;
      if (current !== undefined) records.set(name, current);
      continue;
    }
    if (/^(op|code) /.test(line)) current = undefined;
    const field = /^field (\w+)(\?)?/.exec(line);
    if (field !== null && current !== undefined) current.push({ name: field[1] ?? "", optional: field[2] === "?" });
  }
  return records;
}

/**
 * A valid backend value for each result field (JSON text for headers and claims, as the backend
 * returns them). The polluted value is the same type, so the facade's type checks would pass it.
 */
const BACKEND_VALUE: Readonly<Record<string, unknown>> = {
  alg: "HS256",
  payload: new Uint8Array([1]),
  signatureIndex: 0,
  protectedHeader: '{"alg":"HS256"}',
  unprotectedHeader: '{"kid":"k"}',
  plaintext: new Uint8Array([2]),
  header: '{"alg":"dir","enc":"A128GCM"}',
  sharedUnprotectedHeader: '{"jku":"x"}',
  recipientHeader: '{"kid":"r"}',
  aad: new Uint8Array([3]),
  recipientIndex: 0,
  claims: '{"sub":"alice"}',
  keyIndex: 0,
  kid: "k1",
  outerHeader: '{"alg":"dir","enc":"A128GCM","cty":"JWT"}',
};

const POLLUTED_VALUE: Readonly<Record<string, unknown>> = {
  alg: "none",
  payload: new Uint8Array([0xee]),
  signatureIndex: 3,
  protectedHeader: '{"alg":"none"}',
  unprotectedHeader: '{"jku":"https://attacker.example/jwks.json"}',
  plaintext: new Uint8Array([0xee]),
  header: '{"alg":"none"}',
  sharedUnprotectedHeader: '{"jku":"https://attacker.example/jwks.json"}',
  recipientHeader: '{"kid":"attacker-kid"}',
  aad: new Uint8Array([0xee]),
  recipientIndex: 3,
  claims: '{"sub":"admin"}',
  keyIndex: 3,
  kid: "attacker-kid",
  outerHeader: '{"alg":"none"}',
};

/** The operations returning each result record, and how to call them. */
const USES: Readonly<Record<string, readonly { op: Operation; call: (api: Api) => Promise<unknown> }[]>> = {
  JwsVerified: [
    { op: "jwsVerifyCompact", call: (a) => a["jwsVerifyCompact"]!("a.b.c", KEY, VERIFY) },
    { op: "jwsVerifyJson", call: (a) => a["jwsVerifyJson"]!("{}", KEY, VERIFY) },
  ],
  JweDecrypted: [
    { op: "jweDecryptCompact", call: (a) => a["jweDecryptCompact"]!("a.b.c.d.e", KEY, DECRYPT) },
    { op: "jweDecryptJson", call: (a) => a["jweDecryptJson"]!("{}", KEY, DECRYPT) },
  ],
  JwtVerified: [
    { op: "jwtVerify", call: (a) => a["jwtVerify"]!("a.b.c", KEY, VERIFY) },
    { op: "jwtVerifyWithJwks", call: (a) => a["jwtVerifyWithJwks"]!("a.b.c", JWKS, VERIFY) },
  ],
  JwtNestedVerified: [
    { op: "jwtDecryptNested", call: (a) => a["jwtDecryptNested"]!("t", KEY, DECRYPT, KEY, VERIFY) },
    { op: "jwtDecryptNestedWithJwks", call: (a) => a["jwtDecryptNestedWithJwks"]!("t", KEY, DECRYPT, JWKS, VERIFY) },
  ],
};

const RESULTS = inventoryResultRecords();

/** A backend result of `record` with every required field and the given optional ones. */
function result(record: string, optional: readonly string[], omit?: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of RESULTS.get(record) ?? []) {
    if (f.name === omit || (f.optional && !optional.includes(f.name))) continue;
    out[f.name] = f.name === "inner" ? result("JwtVerified", []) : BACKEND_VALUE[f.name];
  }
  return out;
}

function apiReturning(op: Operation, value: unknown): { api: Api } {
  const fake = fakeBackend({ handlers: { [op]: () => value } });
  return { api: createApi(fake.backend) as unknown as Api };
}

/** Runs `body` with `target[member] = value` set (an enumerable assignment), always removed after. */
async function polluted<T>(target: object, member: PropertyKey, value: unknown, body: () => Promise<T>): Promise<T> {
  assert.ok(!Object.hasOwn(target, member), `${String(member)} is not already on the prototype`);
  (target as Record<PropertyKey, unknown>)[member] = value;
  try {
    return await body();
  } finally {
    delete (target as Record<PropertyKey, unknown>)[member];
  }
}

/** The result's own members, recursively (`inner`), as plain data for comparison. */
function own(v: unknown): unknown {
  if (v instanceof Uint8Array || typeof v !== "object" || v === null) return v;
  if (Array.isArray(v)) return v.map(own);
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(v)) out[k] = own((v as Record<string, unknown>)[k]);
  return out;
}

test("the result sites cover every result record of bindings/api-inventory.txt, and every field has values", () => {
  assert.deepEqual([...RESULTS.keys()].sort(), Object.keys(USES).sort());
  for (const [record, fields] of RESULTS) {
    for (const f of fields) {
      if (f.name === "inner") continue;
      assert.ok(Object.hasOwn(BACKEND_VALUE, f.name) && Object.hasOwn(POLLUTED_VALUE, f.name), `${record}.${f.name} has values`);
    }
  }
  // The audit's fields are among the optional ones.
  const optional = [...RESULTS.values()].flat().filter((f) => f.optional).map((f) => f.name);
  for (const f of ["kid", "keyIndex", "protectedHeader", "unprotectedHeader", "aad", "recipientHeader", "sharedUnprotectedHeader"]) {
    assert.ok(optional.includes(f), f);
  }
});

for (const [record, fields] of RESULTS) {
  const optional = fields.filter((f) => f.optional).map((f) => f.name);
  // JwtNestedVerified has no optional field of its own; its `inner` is a JwtVerified.
  const inner = record === "JwtNestedVerified" ? (RESULTS.get("JwtVerified") ?? []).filter((f) => f.optional).map((f) => f.name) : [];

  test(`${record}: an absent optional field stays absent with Object.prototype polluted`, async () => {
    for (const use of USES[record] ?? []) {
      const clean = await use.call(apiReturning(use.op, result(record, [])).api);
      const want = own(clean);
      for (const field of [...optional, ...inner]) {
        for (const absent of ["missing", "undefined", "null"] as const) {
          const raw = result(record, []);
          if (absent !== "missing") {
            const holder = inner.includes(field) ? (raw["inner"] as Record<string, unknown>) : raw;
            holder[field] = absent === "null" ? null : undefined;
          }
          const { api } = apiReturning(use.op, raw);
          const got = await polluted(Object.prototype, field, POLLUTED_VALUE[field], () => use.call(api));
          const label = `${record}.${field} via ${use.op} (${absent})`;
          assert.deepEqual(own(got), want, `${label}: the result holds only what the backend returned`);
          const holder = inner.includes(field) ? (got as Record<string, unknown>)["inner"] : got;
          assert.ok(!Object.hasOwn(holder as object, field), `${label}: no own ${field}`);
        }
      }
    }
  });

  test(`${record}: every optional field polluted at once (the F04 PoC: kid, keyIndex) changes nothing`, async () => {
    for (const use of USES[record] ?? []) {
      const { api } = apiReturning(use.op, result(record, []));
      const members = [...new Set([...optional, ...inner])];
      for (const m of members) (Object.prototype as Record<string, unknown>)[m] = POLLUTED_VALUE[m];
      let got: unknown;
      try {
        got = await use.call(api);
      } finally {
        for (const m of members) delete (Object.prototype as Record<string, unknown>)[m];
      }
      const clean = await use.call(apiReturning(use.op, result(record, [])).api);
      assert.deepEqual(own(got), own(clean), `${record} via ${use.op}`);
      assert.equal(JSON.stringify(got), JSON.stringify(clean));
    }
  });

  test(`${record}: a present optional field is the backend's, not the prototype's`, async () => {
    for (const use of USES[record] ?? []) {
      for (const field of optional) {
        const { api } = apiReturning(use.op, result(record, [field]));
        const got = (await polluted(Object.prototype, field, POLLUTED_VALUE[field], () => use.call(api))) as Record<string, unknown>;
        const v = BACKEND_VALUE[field];
        assert.deepEqual(got[field], typeof v === "string" && v.startsWith("{") ? JSON.parse(v) : v, `${record}.${field} via ${use.op}`);
      }
    }
  });

  test(`${record}: a required field the backend left out is a TypeError, never the prototype's`, async () => {
    for (const use of USES[record] ?? []) {
      for (const f of fields.filter((x) => !x.optional)) {
        const { api } = apiReturning(use.op, result(record, [], f.name));
        const value = f.name === "inner" ? result("JwtVerified", []) : POLLUTED_VALUE[f.name];
        await assert.rejects(
          polluted(Object.prototype, f.name, value, () => use.call(api)),
          (e: unknown) => e instanceof TypeError && !(e instanceof PolyjoseError),
          `${record}.${f.name} via ${use.op}`,
        );
      }
    }
  });
}

// --- writes: every result member is an own data property (0013 F13) ------------------------
// The facade builds each result itself. A member it created by assignment (`out[key] = value`)
// would run a setter a pollution bug put on `Object.prototype` (the secret `aad`, a `kid`, a
// header handed to attacker code, and the result left without the member), or fail on a
// non-writable inherited member. Each record and field comes from bindings/api-inventory.txt, so a
// new result member is covered without editing this file.

/** A backend result of `record` with every field, optional ones included (and a full `inner`). */
function full(record: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of RESULTS.get(record) ?? []) out[f.name] = f.name === "inner" ? full("JwtVerified") : BACKEND_VALUE[f.name];
  return out;
}

/** Every member of `record`'s result, as [holder path, field]: its own fields, and `inner`'s. */
function members(record: string): { inner: boolean; name: string }[] {
  const own = (RESULTS.get(record) ?? []).map((f) => ({ inner: false, name: f.name }));
  const inner = own.some((f) => f.name === "inner") ? (RESULTS.get("JwtVerified") ?? []).map((f) => ({ inner: true, name: f.name })) : [];
  return [...own, ...inner];
}

/** The polluted value planted for a member: the same type as the backend's, so type checks pass. */
const pollutedFor = (m: PropertyKey): unknown => (m === "inner" ? full("JwtVerified") : POLLUTED_VALUE[String(m)]);

test("every result record has write-side cases, and every member of each has a polluted value", () => {
  for (const record of RESULTS.keys()) {
    assert.ok((USES[record] ?? []).length > 0, `${record} is returned by an operation under test`);
    for (const m of members(record)) assert.ok(m.name === "inner" || Object.hasOwn(POLLUTED_VALUE, m.name), `${record}.${m.name}`);
  }
  // The members the 0006 lead named are among them.
  const all = [...RESULTS.keys()].flatMap((r) => members(r).map((m) => m.name));
  for (const f of ["aad", "kid", "keyIndex", "protectedHeader", "unprotectedHeader", "sharedUnprotectedHeader", "recipientHeader"]) {
    assert.ok(all.includes(f), f);
  }
});

for (const record of RESULTS.keys()) {
  for (const kind of TRAP_KINDS) {
    test(`${record}: with ${kind === "accessor" ? "an accessor" : "a read-only"} member on Object.prototype, each result member is an own data property with the backend's value`, async () => {
      for (const use of USES[record] ?? []) {
        const want = own(await use.call(apiReturning(use.op, full(record)).api));
        for (const m of members(record)) {
          const { api } = apiReturning(use.op, full(record));
          const label = `${record}.${m.inner ? "inner." : ""}${m.name} via ${use.op} (${kind})`;
          const { value: got, writes } = await withTraps(Object.prototype, [m.name], kind, pollutedFor, () => use.call(api));
          assert.deepEqual(writes, [], `${label}: no setter ran, so no value reached it`);
          const holder = m.inner ? ownData(got, "inner", label) : got;
          ownData(holder, m.name, label);
          assert.deepEqual(own(got), want, `${label}: the result holds exactly the backend's values`);
        }
      }
    });
  }

  test(`${record}: every member trapped at once, setters then read-only members, changes nothing`, async () => {
    for (const use of USES[record] ?? []) {
      const want = own(await use.call(apiReturning(use.op, full(record)).api));
      const names = members(record).map((m) => m.name);
      for (const kind of TRAP_KINDS) {
        const { api } = apiReturning(use.op, full(record));
        const { value: got, writes } = await withTraps(Object.prototype, names, kind, pollutedFor, () => use.call(api));
        assert.deepEqual(writes, [], `${record} via ${use.op} (${kind}): no setter ran`);
        for (const m of members(record)) ownData(m.inner ? ownData(got, "inner", record) : got, m.name, `${record}.${m.name} (${kind})`);
        assert.deepEqual(own(got), want, `${record} via ${use.op} (${kind})`);
      }
    }
  });
}

test("results are still ordinary objects: Object.prototype, as callers expect (F09)", async () => {
  for (const [record, uses] of Object.entries(USES)) {
    for (const use of uses) {
      const got = await use.call(apiReturning(use.op, full(record)).api);
      assert.equal(Object.getPrototypeOf(got), Object.prototype, `${record} via ${use.op}`);
      if (record === "JwtNestedVerified") assert.equal(Object.getPrototypeOf((got as Record<string, unknown>)["inner"]), Object.prototype);
    }
  }
});

test("descriptor members on Object.prototype (get, set, value, writable, ...) don't change how result members are made", async () => {
  // Object.defineProperty reads its descriptor through the descriptor's prototype chain
  // (ECMA-262 ToPropertyDescriptor): an inherited `get` or `set` would make a plain-object
  // descriptor invalid (a TypeError), and an inherited `writable: false` would weaken it.
  const planted: Record<string, unknown> = {
    get: () => "attacker",
    set: () => undefined,
    writable: false,
    enumerable: false,
    configurable: false,
    value: "attacker",
  };
  for (const [record, uses] of Object.entries(USES)) {
    for (const use of uses) {
      const want = own(await use.call(apiReturning(use.op, full(record)).api));
      const { api } = apiReturning(use.op, full(record));
      for (const [k, v] of Object.entries(planted)) {
        // A prototype-less descriptor: the members planted before this one are inherited otherwise.
        const d = Object.assign(Object.create(null) as PropertyDescriptor, { value: v, writable: true, enumerable: false, configurable: true });
        Object.defineProperty(Object.prototype, k, d);
      }
      let got: unknown;
      try {
        got = await use.call(api);
      } finally {
        for (const k of Object.keys(planted)) delete (Object.prototype as Record<string, unknown>)[k];
      }
      for (const m of members(record)) ownData(m.inner ? ownData(got, "inner", record) : got, m.name, `${record}.${m.name}`);
      assert.deepEqual(own(got), want, `${record} via ${use.op}`);
    }
  }
});

test("a JwtNestedVerified inner result missing a required field is a TypeError under pollution", async () => {
  for (const f of (RESULTS.get("JwtVerified") ?? []).filter((x) => !x.optional)) {
    const raw = result("JwtNestedVerified", []);
    raw["inner"] = result("JwtVerified", [], f.name);
    const { api } = apiReturning("jwtDecryptNested", raw);
    await assert.rejects(
      polluted(Object.prototype, f.name, POLLUTED_VALUE[f.name], () => (USES["JwtNestedVerified"]?.[0]?.call ?? (() => Promise.resolve()))(api)),
      TypeError,
      f.name,
    );
  }
});

test("a result with a null prototype is read as usual", async () => {
  const raw = Object.assign(Object.create(null) as object, result("JwtVerified", ["kid", "keyIndex"]));
  const { api } = apiReturning("jwtVerify", raw);
  assert.deepEqual(own(await api["jwtVerify"]!("a.b.c", KEY, VERIFY)), {
    claims: { sub: "alice" },
    header: { alg: "dir", enc: "A128GCM" },
    alg: "HS256",
    keyIndex: 0,
    kid: "k1",
  });
});

// --- errorCodes(): a list result, read by own index only -----------------------------------

test("errorCodes(): a hole in the backend's list is a TypeError, never read through Array.prototype", async () => {
  // The handler returns the holey array itself (the fake's default would spread it into a dense one).
  const holey = ["InvalidJson", , "InvalidKey"];
  const fake = fakeBackend({ handlers: { errorCodes: () => holey } });
  const api = createApi(fake.backend);
  await assert.rejects(
    polluted(Array.prototype, 1, "InvalidSignature", () => api.errorCodes()),
    (e: unknown) => e instanceof TypeError && /errorCodes\[1\]/.test(e.message),
  );
});

test("a backend error's code is mapped only from the backend's own errorCodes() entries", async () => {
  // A hole in errorCodes() must not let Array.prototype[1] add a code to the mapping set.
  const holey = ["InvalidJson", , "InvalidKey"];
  const unlisted = coded("InvalidSignature", "x");
  const fake = fakeBackend({
    handlers: {
      errorCodes: () => holey,
      jwkParse: () => {
        throw unlisted;
      },
    },
  });
  const api = createApi(fake.backend);
  // An unlisted code is not a PolyjoseError; it is passed through unchanged (0013 F12).
  await assert.rejects(
    polluted(Array.prototype, 1, "InvalidSignature", () => api.jwkParse(KEY)),
    (e: unknown) => e === unlisted && !(e instanceof PolyjoseError),
  );
});
