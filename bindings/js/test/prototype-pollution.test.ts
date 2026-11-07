// Prototype pollution can't widen policy or inject members (0013 F04: review S2, security audit
// M1). ADR 0030 §3: an absent option is the core default, and no facade code writes one. With
// `Object.prototype` (or `Array.prototype`) polluted by a bug elsewhere in the host app, the
// facade must still pass the backend exactly the caller's own members: every option and record
// member of every record type is polluted in turn, with a value of the right type, and the
// backend's arguments must equal the unpolluted call's, with no inherited member visible through
// `in` on any record it receives. An inherited required member never stands in for a missing one.
import { assert, fs, path, process, test } from "../node/builtins.js";
import { createApi } from "../src/api.js";
import { fakeBackend, type Fake, type Operation } from "./fake-backend.js";

const KEY = '{"kty":"oct","k":"AAAA"}';
const JWKS = '{"keys":[]}';
const PAYLOAD = new Uint8Array([104, 105]);
const POLLUTED_NOW = 7;
// Every optional result member is set (null = absent), so a polluted prototype can't reach the
// facade's result reading in these tests: they are about inputs.
const VERIFIED = { alg: "HS256", payload: new Uint8Array(), signatureIndex: 0, protectedHeader: null, unprotectedHeader: null };
const DECRYPTED = {
  plaintext: new Uint8Array(),
  header: "{}",
  recipientIndex: 0,
  protectedHeader: null,
  sharedUnprotectedHeader: null,
  recipientHeader: null,
  aad: null,
};
const JWT = { claims: "{}", header: "{}", alg: "HS256", keyIndex: null, kid: null };
const NESTED = { inner: JWT, outerHeader: "{}", recipientIndex: 0 };

/** A facade function called with arbitrary JS values, as an untyped caller does. */
type Loose = (...args: unknown[]) => Promise<unknown>;
type Api = Record<string, Loose>;

function setup(): { api: Api; fake: Fake } {
  const fake = fakeBackend({
    handlers: {
      jwksSelect: () => KEY,
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
 * The value each member name is polluted with: the right type for the member, so it would pass
 * the facade's type checks, and each one loosens policy, widens a limit or injects data if it
 * reaches the backend (the audit's PoC values where it gave one).
 */
const POLLUTION: Readonly<Record<string, unknown>> = {
  // JwsSignOptions, JwsSigner
  protectedHeader: { alg: "none" },
  protectedB64u: "eyJhbGciOiJub25lIn0",
  detached: true,
  key: '{"kty":"oct","k":"QkJCQg"}',
  unprotectedHeader: { jku: "https://attacker.example/jwks.json" },
  // JwsVerifyOptions
  allowedAlgs: ["none", "HS256", "PBES2-HS256+A128KW", "dir"],
  detachedPayload: new Uint8Array([1, 2, 3]),
  maxInputLen: 0xffff_ffff,
  maxSignatures: 0xffff_ffff,
  // JweEncryptOptions, JweRecipient
  enc: "A128GCM",
  recipients: [{ alg: "dir", key: '{"kty":"oct","k":"QkJCQg"}' }],
  sharedUnprotectedHeader: { jku: "https://attacker.example/jwks.json" },
  aad: new Uint8Array([4, 5, 6]),
  compress: true,
  alg: "dir",
  header: { jku: "https://attacker.example/jwks.json" },
  apu: new Uint8Array([7]),
  apv: new Uint8Array([8]),
  p2c: 1000,
  p2sLen: 8,
  // JweDecryptOptions
  allowedEnc: ["A128GCM"],
  maxPbes2Count: 0xffff_ffff,
  maxDecompressedLen: 0xffff_ffff,
  maxRecipients: 0xffff_ffff,
  understoodCrit: ["exp"],
  // JwtSignOptions
  typ: "JWT",
  omitTyp: true,
  accessToken: true,
  // JwtVerifyOptions
  now: POLLUTED_NOW,
  issuers: ["https://attacker.example"],
  audiences: ["https://attacker.example"],
  subject: "attacker",
  leeway: 600,
  maxAge: 0xffff_ffff,
  requiredClaims: ["sub"],
  allowMissingExp: true,
  ignoreAudience: true,
  anyTyp: true,
  profile: "access_token",
  maxKeyCandidates: 0xffff_ffff,
  // JwkSelector
  kid: "attacker",
  keyUse: "sig",
};

/** One operation taking the record, and where the backend receives it. */
interface Use {
  readonly op: Operation;
  readonly call: (api: Api, rec: unknown) => Promise<unknown>;
  /** Every record object the backend received in this call (for the `in` check). */
  readonly records: (received: readonly unknown[]) => unknown[];
}

interface Site {
  /** The record type (types.ts, bindings/api-inventory.txt). */
  readonly record: string;
  /** Every member of the record. */
  readonly members: readonly string[];
  /** The caller's own members: the smallest valid record. */
  readonly base: Readonly<Record<string, unknown>>;
  readonly uses: readonly Use[];
}

const at = (v: unknown, ...keys: (string | number)[]): unknown => {
  let x = v;
  for (const p of keys) x = (x as Record<string | number, unknown>)[p];
  return x;
};

/** The records of a call: the arguments that are objects, and the lists' records. */
function recordsOf(received: readonly unknown[]): unknown[] {
  const out: unknown[] = [];
  const walk = (v: unknown): void => {
    if (v instanceof Uint8Array || typeof v !== "object" || v === null) return;
    if (Array.isArray(v)) {
      for (const x of v) walk(x);
      return;
    }
    out.push(v);
    for (const x of Object.values(v)) walk(x);
  };
  for (const a of received) walk(a);
  return out;
}

const NESTED_DECRYPT = { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] };
const NESTED_VERIFY = { allowedAlgs: ["HS256"] };

const SITES: readonly Site[] = [
  {
    record: "JwkSelector",
    members: ["kid", "alg", "keyUse"],
    base: {},
    uses: [{ op: "jwksSelect", call: (api, rec) => api["jwksSelect"]!(JWKS, rec), records: recordsOf }],
  },
  {
    record: "JwsSignOptions",
    members: ["protectedHeader", "protectedB64u", "detached"],
    base: {},
    uses: [{ op: "jwsSignCompact", call: (api, rec) => api["jwsSignCompact"]!(PAYLOAD, KEY, rec), records: recordsOf }],
  },
  {
    record: "JwsSigner",
    members: ["key", "protectedHeader", "protectedB64u", "unprotectedHeader"],
    base: { key: KEY },
    uses: [
      { op: "jwsSignFlattened", call: (api, rec) => api["jwsSignFlattened"]!(PAYLOAD, rec), records: recordsOf },
      { op: "jwsSignGeneral", call: (api, rec) => api["jwsSignGeneral"]!(PAYLOAD, [rec]), records: recordsOf },
    ],
  },
  {
    record: "JwsVerifyOptions",
    members: ["allowedAlgs", "detachedPayload", "maxInputLen", "maxSignatures"],
    base: {},
    uses: [
      { op: "jwsVerifyCompact", call: (api, rec) => api["jwsVerifyCompact"]!("a.b.c", KEY, rec), records: recordsOf },
      { op: "jwsVerifyJson", call: (api, rec) => api["jwsVerifyJson"]!("{}", KEY, rec), records: recordsOf },
    ],
  },
  {
    record: "JweEncryptOptions",
    members: ["enc", "recipients", "protectedHeader", "sharedUnprotectedHeader", "aad", "compress"],
    base: { enc: "A256GCM", recipients: [{ alg: "A128KW", key: KEY }] },
    uses: [
      { op: "jweEncryptCompact", call: (api, rec) => api["jweEncryptCompact"]!(PAYLOAD, rec), records: recordsOf },
      { op: "jweEncryptJson", call: (api, rec) => api["jweEncryptJson"]!(PAYLOAD, rec, "general"), records: recordsOf },
      { op: "jwtEncryptNested", call: (api, rec) => api["jwtEncryptNested"]!("a.b.c", rec), records: recordsOf },
    ],
  },
  {
    record: "JweRecipient",
    members: ["alg", "key", "header", "apu", "apv", "p2c", "p2sLen"],
    base: { alg: "PBES2-HS256+A128KW", key: KEY },
    uses: [
      { op: "jweEncryptCompact", call: (api, rec) => api["jweEncryptCompact"]!(PAYLOAD, { enc: "A256GCM", recipients: [rec] }), records: recordsOf },
      { op: "jweEncryptJson", call: (api, rec) => api["jweEncryptJson"]!(PAYLOAD, { enc: "A256GCM", recipients: [rec] }, "general"), records: recordsOf },
      { op: "jwtEncryptNested", call: (api, rec) => api["jwtEncryptNested"]!("a.b.c", { enc: "A256GCM", recipients: [rec] }), records: recordsOf },
    ],
  },
  {
    record: "JweDecryptOptions",
    members: ["allowedAlgs", "allowedEnc", "maxPbes2Count", "maxDecompressedLen", "maxInputLen", "maxRecipients", "understoodCrit"],
    base: {},
    uses: [
      { op: "jweDecryptCompact", call: (api, rec) => api["jweDecryptCompact"]!("a.b.c.d.e", KEY, rec), records: recordsOf },
      { op: "jweDecryptJson", call: (api, rec) => api["jweDecryptJson"]!("{}", KEY, rec), records: recordsOf },
      { op: "jwtDecryptNested", call: (api, rec) => api["jwtDecryptNested"]!("t", KEY, rec, KEY, NESTED_VERIFY), records: recordsOf },
      { op: "jwtDecryptNestedWithJwks", call: (api, rec) => api["jwtDecryptNestedWithJwks"]!("t", KEY, rec, JWKS, NESTED_VERIFY), records: recordsOf },
    ],
  },
  {
    record: "JwtSignOptions",
    members: ["alg", "typ", "omitTyp", "accessToken", "header"],
    base: { alg: "HS256" },
    uses: [{ op: "jwtSign", call: (api, rec) => api["jwtSign"]!({ sub: "x" }, KEY, rec), records: recordsOf }],
  },
  {
    record: "JwtVerifyOptions",
    members: [
      "allowedAlgs",
      "now",
      "issuers",
      "audiences",
      "subject",
      "leeway",
      "maxAge",
      "requiredClaims",
      "allowMissingExp",
      "ignoreAudience",
      "typ",
      "anyTyp",
      "profile",
      "maxKeyCandidates",
      "maxInputLen",
    ],
    base: {},
    uses: [
      { op: "jwtVerify", call: (api, rec) => api["jwtVerify"]!("a.b.c", KEY, rec), records: recordsOf },
      { op: "jwtVerifyWithJwks", call: (api, rec) => api["jwtVerifyWithJwks"]!("a.b.c", JWKS, rec), records: recordsOf },
      { op: "jwtDecryptNested", call: (api, rec) => api["jwtDecryptNested"]!("t", KEY, NESTED_DECRYPT, KEY, rec), records: recordsOf },
      { op: "jwtDecryptNestedWithJwks", call: (api, rec) => api["jwtDecryptNestedWithJwks"]!("t", KEY, NESTED_DECRYPT, JWKS, rec), records: recordsOf },
    ],
  },
];

/** Input records and their fields, read from bindings/api-inventory.txt (results excluded). */
function inventoryInputRecords(): Map<string, string[]> {
  const text = fs.readFileSync(path.resolve(process.cwd(), "../api-inventory.txt"), "utf8");
  const records = new Map<string, string[]>();
  let current: string[] | undefined;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    const rec = /^record (\w+)$/.exec(line);
    if (rec !== null) {
      const name = rec[1] ?? "";
      current = /(Verified|Decrypted)$/.test(name) ? undefined : [];
      if (current !== undefined) records.set(name, current);
      continue;
    }
    if (/^(op|code) /.test(line)) current = undefined;
    const field = /^field (\w+)/.exec(line);
    if (field !== null && current !== undefined) current.push(field[1] ?? "");
  }
  return records;
}

/**
 * The backend's arguments as compared: deep copies of what it received, with `now` (a clock
 * reading when the caller gave none) checked and removed. `now` must never be the polluted value.
 */
function comparable(args: readonly unknown[]): unknown[] {
  const strip = (v: unknown): unknown => {
    if (v instanceof Uint8Array || typeof v !== "object" || v === null) return v;
    if (Array.isArray(v)) return v.map(strip);
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      if (k === "now") {
        assert.equal(typeof x, "number", "now is a number");
        assert.notEqual(x, POLLUTED_NOW, "now is the caller's or the clock's, never an inherited one");
        continue;
      }
      out[k] = strip(x);
    }
    return out;
  };
  return args.map(strip);
}

/** No record the backend received shows a member it does not own (a backend may read with `in`). */
function assertNoInherited(fake: Fake, use: Use, member: string, label: string): void {
  const call = fake.of(use.op).at(-1);
  assert.ok(call !== undefined, `${label}: the backend was called`);
  for (const rec of use.records(call.received)) {
    if (member in (rec as object)) {
      assert.ok(Object.hasOwn(rec as object, member), `${label}: the backend sees an inherited ${member}`);
    }
  }
}

type Outcome = { ok: true } | { ok: false; error: unknown };

async function outcome(p: Promise<unknown>): Promise<Outcome> {
  try {
    await p;
    return { ok: true };
  } catch (error) {
    return { ok: false, error };
  }
}

/**
 * Runs `body` with `Object.prototype[member]` set as a pollution bug would set it (a plain,
 * enumerable assignment), and always removes it again.
 */
async function polluted<T>(target: object, member: string | number, value: unknown, body: () => Promise<T>): Promise<T> {
  assert.ok(!Object.hasOwn(target, member), `${String(member)} is not already on the prototype`);
  (target as Record<string | number, unknown>)[member] = value;
  try {
    return await body();
  } finally {
    delete (target as Record<string | number, unknown>)[member];
  }
}

test("the pollution sites cover every input record and member of bindings/api-inventory.txt", () => {
  const inventory = inventoryInputRecords();
  assert.deepEqual(
    [...inventory.keys()].sort(),
    SITES.map((s) => s.record).sort(),
    "every options/input record has a pollution site",
  );
  for (const site of SITES) {
    assert.deepEqual([...site.members].sort(), [...(inventory.get(site.record) ?? [])].sort(), `${site.record}: every member`);
    for (const m of site.members) assert.ok(Object.hasOwn(POLLUTION, m), `${site.record}.${m} has a pollution value`);
  }
});

for (const site of SITES) {
  test(`${site.record}: an inherited member never reaches the backend; the default holds`, async () => {
    for (const use of site.uses) {
      // The unpolluted call: what the backend must receive however the prototype is polluted.
      const clean = setup();
      const cleanOutcome = await outcome(use.call(clean.api, { ...site.base }));
      assert.ok(cleanOutcome.ok, `${use.op}: the clean call resolves`);
      const want = comparable(clean.fake.of(use.op)[0]?.args ?? []);

      for (const member of site.members) {
        const label = `${site.record}.${member} via ${use.op}`;
        const own = Object.hasOwn(site.base, member);

        // 1. The caller's record without the member (or, for a required member, with its own
        //    value): the backend gets exactly the clean call's arguments.
        {
          const { api, fake } = setup();
          const got = await polluted(Object.prototype, member, POLLUTION[member], async () => {
            const result = await outcome(use.call(api, { ...site.base }));
            if (result.ok) assertNoInherited(fake, use, member, label);
            return result;
          });
          assert.ok(got.ok, `${label}: resolves (${got.ok ? "" : String(got.error)})`);
          assert.deepEqual(comparable(fake.of(use.op)[0]?.args ?? []), want, `${label}: the backend got only the caller's own members`);
        }

        // 2. A required member the caller left out is a TypeError before the backend: an
        //    inherited value never stands in for it (ADR 0030 §3).
        if (own) {
          const { api, fake } = setup();
          const rest: Record<string, unknown> = { ...site.base };
          delete rest[member];
          const got = await polluted(Object.prototype, member, POLLUTION[member], () => outcome(use.call(api, rest)));
          assert.ok(!got.ok && got.error instanceof TypeError, `${label}: a missing required member is a TypeError`);
          assert.equal(fake.calls.length, 0, `${label}: the backend is not called`);
        }

        // 3. An absent record (undefined, null) is `{}` for the backend, never the prototype.
        if (Object.keys(site.base).length === 0) {
          for (const absent of [undefined, null]) {
            const { api, fake } = setup();
            const got = await polluted(Object.prototype, member, POLLUTION[member], async () => {
              const result = await outcome(use.call(api, absent));
              if (result.ok) assertNoInherited(fake, use, member, `${label} (${String(absent)} record)`);
              return result;
            });
            assert.ok(got.ok, `${label} (${String(absent)} record): resolves`);
            assert.deepEqual(comparable(fake.of(use.op)[0]?.args ?? []), want, `${label} (${String(absent)} record): the core defaults`);
          }
        }
      }
    }
  });
}

test("every member polluted at once: each operation's backend arguments equal the clean call's (audit M1 PoC)", async () => {
  for (const site of SITES) {
    for (const use of site.uses) {
      const clean = setup();
      assert.ok((await outcome(use.call(clean.api, { ...site.base }))).ok);
      const want = comparable(clean.fake.of(use.op)[0]?.args ?? []);
      const { api, fake } = setup();
      const members = Object.keys(POLLUTION);
      for (const m of members) assert.ok(!Object.hasOwn(Object.prototype, m));
      for (const m of members) (Object.prototype as Record<string, unknown>)[m] = POLLUTION[m];
      let got: Outcome;
      try {
        got = await outcome(use.call(api, { ...site.base }));
        if (got.ok) for (const m of members) assertNoInherited(fake, use, m, `${site.record} via ${use.op}`);
      } finally {
        for (const m of members) delete (Object.prototype as Record<string, unknown>)[m];
      }
      assert.ok(got.ok, `${site.record} via ${use.op}: resolves`);
      assert.deepEqual(comparable(fake.of(use.op)[0]?.args ?? []), want, `${site.record} via ${use.op}`);
    }
  }
});

test("an own non-enumerable member is not read: only own enumerable members are the caller's", async () => {
  const { api, fake } = setup();
  const options = { allowedAlgs: ["HS256"] };
  Object.defineProperty(options, "ignoreAudience", { value: true, enumerable: false });
  Object.defineProperty(options, "allowMissingExp", { value: true, enumerable: false });
  await api["jwtVerify"]!("a.b.c", KEY, options);
  const received = at(fake.of("jwtVerify")[0]?.received, 2) as object;
  assert.ok(!("ignoreAudience" in received));
  assert.ok(!("allowMissingExp" in received));
});

test("a member is read once: a getter can't pass the check with one value and reach the backend with another", async () => {
  const { api, fake } = setup();
  let reads = 0;
  const options = {
    allowedAlgs: ["HS256"],
    get leeway(): unknown {
      reads++;
      return reads === 1 ? 30 : "600";
    },
  };
  await api["jwtVerify"]!("a.b.c", KEY, options);
  assert.equal(reads, 1);
  assert.equal(at(fake.of("jwtVerify")[0]?.args, 2, "leeway"), 30);
});

// --- lists: holes are TypeErrors, never read through Array.prototype ----------------------

const HOLE_CASES: readonly { label: string; op: Operation; call: (api: Api) => Promise<unknown>; value: unknown }[] = [
  {
    label: "JwsVerifyOptions.allowedAlgs",
    op: "jwsVerifyCompact",
    call: (api) => api["jwsVerifyCompact"]!("a.b.c", KEY, { allowedAlgs: ["HS256", , "ES256"] }),
    value: "none",
  },
  {
    label: "JweDecryptOptions.allowedEnc",
    op: "jweDecryptCompact",
    call: (api) => api["jweDecryptCompact"]!("a.b.c.d.e", KEY, { allowedAlgs: ["dir"], allowedEnc: ["A256GCM", , "A128GCM"] }),
    value: "A128CBC-HS256",
  },
  {
    label: "JwtVerifyOptions.audiences",
    op: "jwtVerify",
    call: (api) => api["jwtVerify"]!("a.b.c", KEY, { allowedAlgs: ["HS256"], audiences: ["a", , "c"] }),
    value: "https://attacker.example",
  },
  {
    label: "JweEncryptOptions.recipients",
    op: "jweEncryptCompact",
    call: (api) => api["jweEncryptCompact"]!(PAYLOAD, { enc: "A256GCM", recipients: [{ alg: "A128KW", key: KEY }, , { alg: "A128KW", key: KEY }] }),
    value: { alg: "dir", key: '{"kty":"oct","k":"QkJCQg"}' },
  },
  {
    label: "jwsSignGeneral signers",
    op: "jwsSignGeneral",
    call: (api) => api["jwsSignGeneral"]!(PAYLOAD, [{ key: KEY }, , { key: KEY }]),
    value: { key: '{"kty":"oct","k":"QkJCQg"}' },
  },
];

for (const c of HOLE_CASES) {
  test(`${c.label}: a hole in a list is a TypeError naming the index, with or without Array.prototype[1]`, async () => {
    for (const pollute of [false, true]) {
      const { api, fake } = setup();
      const run = (): Promise<Outcome> => outcome(c.call(api));
      const got = pollute ? await polluted(Array.prototype, 1, c.value, run) : await run();
      assert.ok(!got.ok && got.error instanceof TypeError, `${c.label} (polluted: ${pollute}): a TypeError`);
      assert.match((got.error as TypeError).message, /\[1\]/, `${c.label}: the message names the index`);
      assert.equal(fake.calls.length, 0, `${c.label} (polluted: ${pollute}): the backend is not called`);
    }
  });
}

test("a dense list is copied element by element, and Array.prototype pollution past its end is not read", async () => {
  const { api, fake } = setup();
  await polluted(Array.prototype, 1, "none", () => api["jwsVerifyCompact"]!("a.b.c", KEY, { allowedAlgs: ["HS256"] }));
  assert.deepEqual(at(fake.of("jwsVerifyCompact")[0]?.args, 2, "allowedAlgs"), ["HS256"]);
});
