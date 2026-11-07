// Inputs are taken at the call, not after `ready()` (ADR 0030 §2, §7; ADR 0031 §3; 0013 B06).
// The first call of a process starts while the backend's lazy `ready()` is still pending (WASM
// instantiation). Everything the caller passed must be validated and captured synchronously,
// before that wait: byte inputs as fresh copies, JSON objects as text, the JWT clock as a
// reading. Mutating the caller's arrays or objects afterwards must not change what is signed or
// encrypted. The copies are wiped with fill(0) once the backend call settles, whatever the
// outcome, and the caller's own arrays are never wiped.
import { assert, test } from "../node/builtins.js";
import { createApi, PolyjoseError, type JsonObject, type JwkObject, type PolyjoseApi } from "../src/api.js";
import { coded, fakeBackend, type Call, type Fake, type Handler, type Operation } from "./fake-backend.js";

const KEY_TEXT = '{"kty":"oct","k":"AAAA"}';
const VERIFIED = { alg: "HS256", payload: new Uint8Array([9]), signatureIndex: 0 };
const JWT = { claims: "{}", header: "{}", alg: "HS256" };
const NESTED = { inner: JWT, outerHeader: "{}", recipientIndex: 0 };
const DEC = { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] };


/** A distinct, non-zero byte pattern per input, so a wiped or swapped input is visible. */
function original(i: number): number[] {
  return [1, 2, 3, 4, 5, 6, 7, 8].map((b) => b + 16 * i);
}

/** A backend whose `ready()` stays pending until `release()`: the first call of a cold process. */
function cold(handlers: Partial<Record<Operation, Handler>>): { fake: Fake; api: PolyjoseApi; release: () => void } {
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const fake = fakeBackend({ ready: () => gate, handlers });
  return { fake, api: createApi(fake.backend), release };
}

/** Lets every queued microtask run, so a call that is waiting stays visibly waiting. */
async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) await Promise.resolve();
}

/** One operation with byte inputs. */
interface Case {
  readonly op: Operation;
  /** How many byte inputs `start` uses. */
  readonly inputs: number;
  /** What the backend returns on success. */
  readonly result: unknown;
  /** Starts the call with the caller's arrays and a caller's JWK object. */
  start(api: PolyjoseApi, bytes: readonly Uint8Array[], key: JwkObject): Promise<unknown>;
  /** The byte inputs among the backend's arguments, in `start`'s order. */
  bytesOf(args: readonly unknown[]): unknown[];
  /** The JWK text among the backend's arguments, if the operation takes a JWK. */
  keyOf?(args: readonly unknown[]): unknown;
}

const at = (v: unknown, ...path: (string | number)[]): unknown =>
  path.reduce<unknown>((x, k) => (x as Record<string | number, unknown> | undefined)?.[k], v);

const nth = (bytes: readonly Uint8Array[], i: number): Uint8Array => {
  const b = bytes[i];
  if (b === undefined) throw new Error(`test: byte input ${i} missing`);
  return b;
};

/** The JWE encrypt options with all three byte members (`aad`, `apu`, `apv`) and a JWK object. */
const encryptOptions = (bytes: readonly Uint8Array[], key: JwkObject) => ({
  enc: "A128GCM",
  recipients: [{ alg: "ECDH-ES+A128KW", key, apu: nth(bytes, 2), apv: nth(bytes, 3) }],
  aad: nth(bytes, 1),
});
const encryptBytes = (o: unknown): unknown[] => [at(o, "aad"), at(o, "recipients", 0, "apu"), at(o, "recipients", 0, "apv")];

const CASES: readonly Case[] = [
  {
    op: "base64urlEncode",
    inputs: 1,
    result: "AQ",
    start: (api, b) => api.base64urlEncode(nth(b, 0)),
    bytesOf: (a) => [a[0]],
  },
  {
    op: "jwkFromDer",
    inputs: 1,
    result: KEY_TEXT,
    start: (api, b) => api.jwkFromDer(nth(b, 0), "spki"),
    bytesOf: (a) => [a[0]],
  },
  {
    op: "jwsSignCompact",
    inputs: 1,
    result: "a.b.c",
    start: (api, b, key) => api.jwsSignCompact(nth(b, 0), key, { protectedHeader: { alg: "HS256" } }),
    bytesOf: (a) => [a[0]],
    keyOf: (a) => a[1],
  },
  {
    op: "jwsSignFlattened",
    inputs: 1,
    result: "{}",
    start: (api, b, key) => api.jwsSignFlattened(nth(b, 0), { key, protectedB64u: "e30" }, false),
    bytesOf: (a) => [a[0]],
    keyOf: (a) => at(a[1], "key"),
  },
  {
    op: "jwsSignGeneral",
    inputs: 1,
    result: "{}",
    start: (api, b, key) => api.jwsSignGeneral(nth(b, 0), [{ key, protectedB64u: "e30" }], true),
    bytesOf: (a) => [a[0]],
    keyOf: (a) => at(a[1], 0, "key"),
  },
  {
    op: "jwsVerifyCompact",
    inputs: 1,
    result: VERIFIED,
    start: (api, b, key) => api.jwsVerifyCompact("a..c", key, { allowedAlgs: ["HS256"], detachedPayload: nth(b, 0) }),
    bytesOf: (a) => [at(a[2], "detachedPayload")],
    keyOf: (a) => a[1],
  },
  {
    op: "jwsVerifyJson",
    inputs: 1,
    result: VERIFIED,
    start: (api, b, key) => api.jwsVerifyJson({ signature: "" }, key, { allowedAlgs: ["HS256"], detachedPayload: nth(b, 0) }),
    bytesOf: (a) => [at(a[2], "detachedPayload")],
    keyOf: (a) => a[1],
  },
  {
    op: "jweEncryptCompact",
    inputs: 4,
    result: "a.b.c.d.e",
    start: (api, b, key) => api.jweEncryptCompact(nth(b, 0), encryptOptions(b, key)),
    bytesOf: (a) => [a[0], ...encryptBytes(a[1])],
    keyOf: (a) => at(a[1], "recipients", 0, "key"),
  },
  {
    op: "jweEncryptJson",
    inputs: 4,
    result: "{}",
    start: (api, b, key) => api.jweEncryptJson(nth(b, 0), encryptOptions(b, key), "general"),
    bytesOf: (a) => [a[0], ...encryptBytes(a[1])],
    keyOf: (a) => at(a[1], "recipients", 0, "key"),
  },
  {
    op: "jwtEncryptNested",
    // aad, apu and apv: the nested JWT's own input is a string.
    inputs: 4,
    result: "1.2.3.4.5",
    start: (api, b, key) => api.jwtEncryptNested("h.p.s", encryptOptions(b, key)),
    bytesOf: (a) => encryptBytes(a[1]),
    keyOf: (a) => at(a[1], "recipients", 0, "key"),
  },
];

function inputsFor(c: Case): Uint8Array[] {
  return Array.from({ length: c.inputs }, (_, i) => new Uint8Array(original(i)));
}

/** The byte inputs `c` passed in `call`, as received (live) or as they were at the call. */
function passed(c: Case, call: Call | undefined, which: "args" | "received"): Uint8Array[] {
  assert.ok(call !== undefined, `${c.op} was called`);
  const got = c.bytesOf(call[which]);
  // jwtEncryptNested takes no payload array: its inputs are aad, apu and apv only.
  const want = c.op === "jwtEncryptNested" ? c.inputs - 1 : c.inputs;
  assert.equal(got.length, want, `${c.op}: every byte input reached the backend`);
  return got.map((b, i) => {
    assert.ok(b instanceof Uint8Array, `${c.op}: byte input ${i} is a Uint8Array`);
    return b;
  });
}

/** The caller's arrays `c` hands the backend: for jwtEncryptNested input 0 is unused. */
function used(c: Case, bytes: readonly Uint8Array[]): Uint8Array[] {
  return c.op === "jwtEncryptNested" ? bytes.slice(1) : [...bytes];
}

function zeroed(b: Uint8Array): boolean {
  return b.length > 0 && b.every((x) => x === 0);
}

// --- the cold first call ------------------------------------------------------------------

for (const c of CASES) {
  test(`${c.op}: mutating the caller's bytes and JWK object while ready() is pending changes nothing`, async () => {
    const { fake, api, release } = cold({ [c.op]: () => c.result });
    const bytes = inputsFor(c);
    const key: JwkObject = { kty: "oct", k: "AAAA" };
    const pending = c.start(api, bytes, key);
    // The caller reuses its buffer and object right after starting the call.
    for (const b of bytes) b.fill(0xee);
    key["k"] = "MUTATED";
    key["alg"] = "none";
    await settle();
    assert.equal(fake.of(c.op).length, 0, "the backend waits for ready()");
    release();
    await pending;
    const call = fake.of(c.op)[0];
    const want = used(c, inputsFor(c)).map((b) => Array.from(b));
    assert.deepEqual(
      passed(c, call, "args").map((b) => Array.from(b)),
      want,
      "the backend received the bytes as they were when the call started",
    );
    if (c.keyOf !== undefined && call !== undefined) assert.equal(c.keyOf(call.args), KEY_TEXT, "the JWK as it was when the call started");
  });
}

// --- the copies: fresh, wiped once the call settles, never the caller's arrays -------------

type Outcome = "sync success" | "sync failure" | "async success" | "async failure";
const OUTCOMES: readonly Outcome[] = ["sync success", "sync failure", "async success", "async failure"];

for (const c of CASES) {
  for (const outcome of OUTCOMES) {
    test(`${c.op}: the backend gets fresh copies, wiped after ${outcome}; the caller's arrays are untouched`, async () => {
      let finish: () => void = () => {};
      const handler: Handler = () => {
        const failure = coded("InvalidKey", "invalid key");
        switch (outcome) {
          case "sync success":
            return c.result;
          case "sync failure":
            throw failure;
          case "async success":
          case "async failure":
            return new Promise((resolve, reject) => {
              finish = () => (outcome === "async success" ? resolve(c.result) : reject(failure));
            });
        }
      };
      const { fake, api, release } = cold({ [c.op]: handler });
      const bytes = inputsFor(c);
      const pending = c.start(api, bytes, { kty: "oct", k: "AAAA" });
      release();
      await settle();
      const received = passed(c, fake.of(c.op)[0], "received");
      for (const [i, copy] of received.entries()) {
        const mine = used(c, bytes)[i];
        assert.ok(copy !== mine, `input ${i} is a copy, not the caller's array`);
        assert.ok(copy.buffer !== mine?.buffer, `input ${i} shares no memory with the caller's array`);
      }
      if (outcome.startsWith("async")) {
        // napi's AsyncTask still runs: the copies must stay intact until it settles.
        assert.deepEqual(
          received.map((b) => Array.from(b)),
          used(c, inputsFor(c)).map((b) => Array.from(b)),
          "not wiped before the backend's Promise settles",
        );
        finish();
      }
      if (outcome.endsWith("success")) await pending;
      else await assert.rejects(pending, (e: unknown) => e instanceof PolyjoseError && e.code === "InvalidKey");
      for (const [i, copy] of received.entries()) assert.ok(zeroed(copy), `copy ${i} is wiped with fill(0)`);
      assert.deepEqual(
        bytes.map((b) => Array.from(b)),
        inputsFor(c).map((b) => Array.from(b)),
        "the caller's own arrays are never wiped",
      );
    });
  }
}

test("a subarray view and a Node Buffer are copied byte for byte; the parent memory is untouched", async () => {
  const fake = fakeBackend({ handlers: { jwsSignCompact: () => "a.b.c" } });
  const api = createApi(fake.backend);
  const parent = new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17]);
  const NodeBuffer = (globalThis as unknown as { Buffer: { from(a: number[]): Uint8Array } }).Buffer;
  const buf = NodeBuffer.from([20, 21, 22]);
  await api.base64urlEncode(parent.subarray(2, 6));
  await api.jwsSignCompact(buf, KEY_TEXT, {});
  const [view] = fake.of("base64urlEncode").map((c) => c.args[0]);
  assert.deepEqual(Array.from(view as Uint8Array), [12, 13, 14, 15], "exactly the view's bytes");
  const copy = fake.of("jwsSignCompact")[0]?.received[0];
  assert.ok(copy instanceof Uint8Array && zeroed(copy));
  assert.deepEqual(Array.from(parent), [10, 11, 12, 13, 14, 15, 16, 17]);
  assert.deepEqual(Array.from(buf), [20, 21, 22]);
});

test("a later call's copies are its own: wiping one call's copies leaves a concurrent call's intact", async () => {
  const finishers: (() => void)[] = [];
  const fake = fakeBackend({ handlers: { jwsSignCompact: () => new Promise((resolve) => finishers.push(() => resolve("a.b.c"))) } });
  const api = createApi(fake.backend);
  const payload = new Uint8Array([1, 2, 3]);
  const first = api.jwsSignCompact(payload, KEY_TEXT, {});
  const second = api.jwsSignCompact(payload, KEY_TEXT, {});
  await settle();
  const [a, b] = fake.of("jwsSignCompact").map((c) => c.received[0] as Uint8Array);
  assert.ok(a !== undefined && b !== undefined && a !== b, "one copy per call");
  finishers[0]?.();
  await first;
  assert.ok(zeroed(a));
  assert.deepEqual(Array.from(b), [1, 2, 3], "the pending call's copy is not wiped");
  finishers[1]?.();
  await second;
  assert.ok(zeroed(b));
});

// --- JSON-only inputs, records, the clock and argument errors on a cold call ---------------

test("JSON objects and records are captured at the call too (claims, header, allow-list)", async () => {
  const { fake, api, release } = cold({ jwtSign: () => "h.p.s", jwsVerifyCompact: () => VERIFIED });
  const claims: JsonObject = { sub: "alice", exp: 1 };
  const header: JsonObject = { kid: "k1" };
  const signing = api.jwtSign(claims, KEY_TEXT, { alg: "HS256", header });
  const allowedAlgs = ["HS256"];
  const options: { allowedAlgs: string[]; maxInputLen?: number } = { allowedAlgs };
  const verifying = api.jwsVerifyCompact("a.b.c", KEY_TEXT, options);
  claims["sub"] = "mallory";
  claims["exp"] = 9_999_999_999;
  header["kid"] = "other";
  allowedAlgs.push("none");
  options["maxInputLen"] = 1;
  release();
  await signing;
  await verifying;
  assert.deepEqual(fake.of("jwtSign")[0]?.args, ['{"sub":"alice","exp":1}', KEY_TEXT, { alg: "HS256", header: '{"kid":"k1"}' }]);
  assert.deepEqual(fake.of("jwsVerifyCompact")[0]?.args, ["a.b.c", KEY_TEXT, { allowedAlgs: ["HS256"] }]);
});

test("the JWT clock is read at the call, not after ready() resolves", async () => {
  const { fake, api, release } = cold({
    jwtVerify: () => JWT,
    jwtVerifyWithJwks: () => JWT,
    jwtDecryptNested: () => NESTED,
    jwtDecryptNestedWithJwks: () => NESTED,
  });
  const real = Date.now;
  let calls: Promise<unknown>[];
  try {
    Date.now = () => 1_300_819_380_999;
    calls = [
      api.jwtVerify("t", KEY_TEXT, { allowedAlgs: ["HS256"] }),
      api.jwtVerifyWithJwks("t", '{"keys":[]}', { allowedAlgs: ["HS256"] }),
      api.jwtDecryptNested("t", KEY_TEXT, DEC, KEY_TEXT, { allowedAlgs: ["HS256"] }),
      api.jwtDecryptNestedWithJwks("t", KEY_TEXT, DEC, '{"keys":[]}', { allowedAlgs: ["HS256"] }),
    ];
    // The clock moves on while the backend initialises.
    Date.now = () => 1_400_000_000_000;
    release();
    await Promise.all(calls);
  } finally {
    Date.now = real;
  }
  const nows = fake.calls
    .filter((c) => c.op.startsWith("jwt"))
    .map((c) => at(c.args[c.op.startsWith("jwtDecrypt") ? 4 : 2], "now"));
  assert.deepEqual(nows, [1_300_819_380, 1_300_819_380, 1_300_819_380, 1_300_819_380]);
});

test("an argument error on a cold call rejects with a TypeError at once: no ready(), no backend call", async () => {
  let readies = 0;
  const fake = fakeBackend({
    ready: () => {
      readies += 1;
      return new Promise<void>(() => {});
    },
  });
  const api = createApi(fake.backend);
  const loose = api as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
  const payload = new Uint8Array([1, 2, 3]);
  const bad: [string, unknown[]][] = [
    ["jwsSignCompact", [payload, 42, {}]],
    ["jweEncryptCompact", [payload, { enc: "A128GCM", recipients: [{ alg: "dir", key: KEY_TEXT, apu: "not bytes" }] }]],
    ["jwsVerifyCompact", ["t", KEY_TEXT, { allowedAlgs: ["HS256"], detachedPayload: [1] }]],
    ["base64urlEncode", ["text"]],
  ];
  for (const [name, args] of bad) {
    await assert.rejects(loose[name]?.(...args) ?? Promise.resolve(), (e: unknown) => e instanceof TypeError && !(e instanceof PolyjoseError), name);
  }
  assert.equal(readies, 0, "ready() is not started for a call that fails its argument checks");
  assert.equal(fake.calls.length, 0);
  assert.deepEqual(Array.from(payload), [1, 2, 3], "the caller's array is never wiped");
});

test("a detached Uint8Array is a TypeError before the backend is called", async () => {
  const fake = fakeBackend();
  const api = createApi(fake.backend);
  const view = new Uint8Array(new ArrayBuffer(4));
  // Transferring the buffer detaches it (Node's structuredClone; not in the ES2022 lib).
  const clone = (globalThis as unknown as { structuredClone(v: unknown, o: { transfer: unknown[] }): unknown }).structuredClone;
  clone(view.buffer, { transfer: [view.buffer] });
  assert.equal(view.length, 0, "detached");
  await assert.rejects(api.base64urlEncode(view), (e: unknown) => e instanceof TypeError && /base64urlEncode: bytes/.test(e.message));
  assert.equal(fake.calls.length, 0);
});
