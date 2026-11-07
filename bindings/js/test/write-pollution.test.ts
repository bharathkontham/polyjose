// The facade's own arrays are written by index as own data properties, never with `push` or an
// assignment (0013 F13, security audit M1 follow-up). `Array.prototype.push` stores the next
// element with an ordinary assignment (ECMA-262 Array.prototype.push, Set(O, len, E, true)), so a
// pollution bug elsewhere in the host app that put an accessor on `Array.prototype[0]` (or on
// `Object.prototype[0]`, which arrays inherit too) would receive the element, and a non-writable
// one would make the push a TypeError. The arrays at stake:
// - the byte copies of a call (`bytes()`): plaintext, payload, `aad`, `apu`, `apv`, DER, all
//   secret-bearing (ADR 0030 §7); a copy the setter took is also never wiped (0013 B06);
// - every list argument (`list()`): allow-lists and claims lists, and the `JwsSigner` and
//   `JweRecipient` records, which hold keys;
// - the `errorCodes()` result.
// And the error the facade makes: `PolyjoseError.code` is an own data property (a class field).
//
// The backend here is a minimal hand-written one, not the recording fake: the fake records calls
// with `push`, which the traps would intercept.
import { assert, test } from "../node/builtins.js";
import type { Backend } from "../src/backend.js";
import { createApi, ERROR_CODES, PolyjoseError, type PolyjoseApi } from "../src/api.js";
import { outList, outStr } from "../src/normalize.js";
import { coded } from "./fake-backend.js";
import { ownData, plant, TRAP_KINDS, withTraps, type TrapKind } from "./traps.js";

const KEY = '{"kty":"oct","k":"c2VjcmV0LWtleQ"}';
const KEY2 = '{"kty":"oct","k":"b3RoZXIta2V5"}';

/** The two prototypes an array element write can consult. */
const TARGETS: readonly { name: string; target: object }[] = [
  { name: "Array.prototype", target: Array.prototype },
  { name: "Object.prototype", target: Object.prototype },
];

/** Index members 0..n-1, as the string keys `push` writes. */
const indices = (n: number): string[] => Array.from({ length: n }, (_, i) => String(i));

/** A value of each kind that is visibly not the caller's. */
const pollutedElement = (): unknown => "attacker";

interface Seen {
  args: unknown[] | undefined;
}

/** A backend that answers `op` with `result` and keeps the arguments it received. */
function backendFor(op: string, result: unknown, seen: Seen): Backend {
  const b: Record<string, unknown> = {
    version: () => "0.1.0",
    errorCodes: () => [...ERROR_CODES],
  };
  b[op] = (...args: unknown[]) => {
    seen.args = args;
    return result;
  };
  return b as unknown as Backend;
}

const zeroed = (v: unknown): boolean => v instanceof Uint8Array && v.every((x) => x === 0);

/** Starts `call` with traps planted and removes them before anything is awaited. */
async function startTrapped<T>(target: object, members: readonly string[], kind: TrapKind, call: () => Promise<T>): Promise<{ value: T; writes: unknown[] }> {
  const traps = plant(target, members, kind, pollutedElement);
  let pending: Promise<T>;
  try {
    // The facade validates, copies and calls the backend synchronously, inside this call (B06).
    pending = call();
  } finally {
    traps.remove();
  }
  return { value: await pending, writes: traps.writes };
}

interface ByteCase {
  readonly name: string;
  readonly op: string;
  readonly result: unknown;
  /** The caller's byte inputs, in the order the facade copies them. */
  readonly inputs: readonly Uint8Array[];
  start(api: PolyjoseApi, inputs: readonly Uint8Array[]): Promise<unknown>;
  /** The byte inputs among the backend's arguments, in `inputs` order. */
  bytesOf(args: readonly unknown[]): unknown[];
}

const at = (v: unknown, ...path: (string | number)[]): unknown =>
  path.reduce<unknown>((x, k) => (x as Record<string | number, unknown> | undefined)?.[k], v);
const nth = (inputs: readonly Uint8Array[], i: number): Uint8Array => inputs[i] ?? new Uint8Array();
const secret = (i: number): Uint8Array => Uint8Array.from([0x51, 0x52, 0x53, 0x54], (b) => b + 16 * i);

const BYTE_CASES: readonly ByteCase[] = [
  {
    name: "jweEncryptCompact: plaintext, aad, apu, apv",
    op: "jweEncryptCompact",
    result: "a.b.c.d.e",
    inputs: [secret(0), secret(1), secret(2), secret(3)],
    start: (api, b) =>
      api.jweEncryptCompact(nth(b, 0), {
        enc: "A128GCM",
        recipients: [{ alg: "ECDH-ES", key: KEY, apu: nth(b, 2), apv: nth(b, 3) }],
        aad: nth(b, 1),
      }),
    bytesOf: (a) => [a[0], at(a[1], "aad"), at(a[1], "recipients", 0, "apu"), at(a[1], "recipients", 0, "apv")],
  },
  {
    name: "jwsVerifyCompact: detachedPayload",
    op: "jwsVerifyCompact",
    result: { alg: "HS256", payload: new Uint8Array([1]), signatureIndex: 0 },
    inputs: [secret(4)],
    start: (api, b) => api.jwsVerifyCompact("a..c", KEY, { allowedAlgs: ["HS256"], detachedPayload: nth(b, 0) }),
    bytesOf: (a) => [at(a[2], "detachedPayload")],
  },
  {
    name: "jwsSignCompact: payload",
    op: "jwsSignCompact",
    result: "a.b.c",
    inputs: [secret(5)],
    start: (api, b) => api.jwsSignCompact(nth(b, 0), KEY, { protectedHeader: '{"alg":"HS256"}' }),
    bytesOf: (a) => [a[0]],
  },
  {
    name: "jwkFromDer: der",
    op: "jwkFromDer",
    result: '{"kty":"EC"}',
    inputs: [secret(6)],
    start: (api, b) => api.jwkFromDer(nth(b, 0), "pkcs8"),
    bytesOf: (a) => [a[0]],
  },
  {
    name: "base64urlEncode: bytes",
    op: "base64urlEncode",
    result: "AAAA",
    inputs: [secret(7)],
    start: (api, b) => api.base64urlEncode(nth(b, 0)),
    bytesOf: (a) => [a[0]],
  },
];

for (const { name: where, target } of TARGETS) {
  for (const kind of TRAP_KINDS) {
    test(`byte copies under ${kind} index members on ${where}: no setter sees a copy, the backend gets the bytes, every copy is wiped`, async () => {
      for (const c of BYTE_CASES) {
        const seen: Seen = { args: undefined };
        const api = createApi(backendFor(c.op, c.result, seen));
        const inputs = c.inputs.map((b) => Uint8Array.from(b));
        const label = `${c.name} (${kind} on ${where})`;
        let snapshot: number[][] = [];
        const { writes } = await startTrapped(target, indices(8), kind, () => {
          const p = c.start(api, inputs);
          // What the backend received, as it was during the call (the copies are wiped after).
          snapshot = c.bytesOf(seen.args ?? []).map((b) => (b instanceof Uint8Array ? Array.from(b) : []));
          return p;
        });
        assert.deepEqual(writes, [], `${label}: no setter ran`);
        assert.deepEqual(snapshot, c.inputs.map((b) => Array.from(b)), `${label}: the backend received the caller's bytes`);
        const received = c.bytesOf(seen.args ?? []);
        for (const [i, copy] of received.entries()) {
          assert.ok(zeroed(copy), `${label}: copy ${i} is wiped once the call settles`);
          assert.notEqual(copy, inputs[i], `${label}: copy ${i} is not the caller's array`);
        }
        assert.deepEqual(inputs.map((b) => Array.from(b)), c.inputs.map((b) => Array.from(b)), `${label}: the caller's arrays are untouched`);
      }
    });
  }
}

interface ListCase {
  readonly name: string;
  readonly op: string;
  readonly result: unknown;
  start(api: PolyjoseApi): Promise<unknown>;
  /** The lists the backend received, and what each must hold. */
  check(args: readonly unknown[]): { got: unknown; want: unknown }[];
}

const VERIFIED_JWT = { claims: "{}", header: "{}", alg: "HS256" };

const LIST_CASES: readonly ListCase[] = [
  {
    name: "jwsSignGeneral: signers (each holds a key)",
    op: "jwsSignGeneral",
    result: "{}",
    start: (api) =>
      api.jwsSignGeneral(new Uint8Array([1]), [
        { key: KEY, protectedHeader: '{"alg":"HS256"}' },
        { key: KEY2, protectedHeader: '{"alg":"HS384"}' },
      ]),
    check: (a) => [
      { got: Array.isArray(a[1]) ? a[1].length : -1, want: 2 },
      { got: at(a[1], 0, "key"), want: KEY },
      { got: at(a[1], 1, "key"), want: KEY2 },
    ],
  },
  {
    name: "jweEncryptJson: recipients (each holds a key)",
    op: "jweEncryptJson",
    result: "{}",
    start: (api) =>
      api.jweEncryptJson(new Uint8Array([1]), { enc: "A128GCM", recipients: [{ alg: "dir", key: KEY }, { alg: "A128KW", key: KEY2 }] }, "general"),
    check: (a) => [
      { got: Array.isArray(at(a[1], "recipients")) ? (at(a[1], "recipients") as unknown[]).length : -1, want: 2 },
      { got: at(a[1], "recipients", 0, "key"), want: KEY },
      { got: at(a[1], "recipients", 1, "key"), want: KEY2 },
    ],
  },
  {
    name: "jwtVerify: allowedAlgs, issuers, audiences, requiredClaims",
    op: "jwtVerify",
    result: VERIFIED_JWT,
    start: (api) =>
      api.jwtVerify("a.b.c", KEY, {
        allowedAlgs: ["HS256", "HS384"],
        issuers: ["https://issuer"],
        audiences: ["aud-1", "aud-2"],
        requiredClaims: ["exp", "sub"],
      }),
    check: (a) => [
      { got: at(a[2], "allowedAlgs"), want: ["HS256", "HS384"] },
      { got: at(a[2], "issuers"), want: ["https://issuer"] },
      { got: at(a[2], "audiences"), want: ["aud-1", "aud-2"] },
      { got: at(a[2], "requiredClaims"), want: ["exp", "sub"] },
    ],
  },
  {
    name: "jweDecryptCompact: allowedAlgs, allowedEnc, understoodCrit",
    op: "jweDecryptCompact",
    result: { plaintext: new Uint8Array([1]), header: "{}", recipientIndex: 0 },
    start: (api) => api.jweDecryptCompact("a.b.c.d.e", KEY, { allowedAlgs: ["dir"], allowedEnc: ["A128GCM", "A256GCM"], understoodCrit: ["exp"] }),
    check: (a) => [
      { got: at(a[2], "allowedAlgs"), want: ["dir"] },
      { got: at(a[2], "allowedEnc"), want: ["A128GCM", "A256GCM"] },
      { got: at(a[2], "understoodCrit"), want: ["exp"] },
    ],
  },
];

/** Plain data of `v`, read by own members (for comparing a list the backend received). */
function plain(v: unknown): unknown {
  if (Array.isArray(v)) return Array.from({ length: v.length }, (_, i) => (Object.hasOwn(v, i) ? plain(v[i]) : "<hole>"));
  return v;
}

for (const { name: where, target } of TARGETS) {
  for (const kind of TRAP_KINDS) {
    test(`list arguments under ${kind} index members on ${where}: no setter sees an element, the backend gets every element`, async () => {
      for (const c of LIST_CASES) {
        const seen: Seen = { args: undefined };
        const api = createApi(backendFor(c.op, c.result, seen));
        const label = `${c.name} (${kind} on ${where})`;
        const { writes } = await startTrapped(target, indices(4), kind, () => c.start(api));
        assert.deepEqual(writes, [], `${label}: no setter ran, so no key or list element reached it`);
        for (const { got, want } of c.check(seen.args ?? [])) assert.deepEqual(plain(got), want, label);
      }
    });
  }
}

// The `errorCodes()` result is written after the backend answers, across an `await`; traps on
// every array index that stay planted that long break Node's own streams. So the result builder,
// `outList` (what `errorCodes()` returns, F13 refactor), is run synchronously under the traps,
// and `errorCodes()` itself is checked to return that builder's array shape.
for (const { name: where, target } of TARGETS) {
  for (const kind of TRAP_KINDS) {
    test(`errorCodes() result under ${kind} index members on ${where}: every code is an own element`, async () => {
      const listed = [...ERROR_CODES];
      const traps = plant(target, indices(listed.length + 1), kind, pollutedElement);
      let got: string[] | undefined;
      let failure: unknown;
      try {
        got = outList(listed, "errorCodes", outStr);
      } catch (e) {
        failure = e;
      } finally {
        traps.remove();
      }
      assert.equal(failure, undefined, "outList did not throw");
      assert.deepEqual(traps.writes, [], "no setter ran");
      assert.equal(got?.length, ERROR_CODES.length);
      for (const [i, code] of ERROR_CODES.entries()) assert.equal(ownData(got, i, `errorCodes[${i}]`), code);
      // The API returns exactly that list.
      assert.deepEqual(await createApi(backendFor("jwkParse", "{}", { args: undefined })).errorCodes(), listed);
    });
  }
}

test("PolyjoseError's code and name are own data properties under traps on Object.prototype", async () => {
  for (const kind of TRAP_KINDS) {
    const thrown = coded("InvalidSignature", "bad signature");
    const b = backendFor("jwkParse", undefined, { args: undefined }) as unknown as Record<string, unknown>;
    b["jwkParse"] = () => {
      throw thrown;
    };
    const api = createApi(b as unknown as Backend);
    const polluted = (m: PropertyKey): unknown => (m === "code" ? "NoMatchingKey" : "attacker");
    const { value: e, writes } = await withTraps(Object.prototype, ["code", "name", "message"], kind, polluted, () =>
      api.jwkParse(KEY).then(
        () => undefined,
        (err: unknown) => err,
      ),
    );
    assert.deepEqual(writes, [], `${kind}: no setter ran`);
    assert.ok(e instanceof PolyjoseError, kind);
    assert.equal(ownData(e, "code", kind), "InvalidSignature");
    assert.equal(ownData(e, "name", kind), "PolyjoseError");
    assert.equal(Object.getOwnPropertyDescriptor(e, "message")?.value, "bad signature", kind);
  }
});
