// The facade's error mapping over the real napi backend (feature 0007 F06; ADR 0061, which
// supersedes ADR 0031 §1 "Errors" in part; ADR 0030 §5; bindings/js/BACKEND.md "Errors"). The
// shared facade tests (bindings/js/test/error-passthrough.test.ts) use a fake backend; these use
// the errors the built addon really throws, so a napi-rs bump that renames a Status, or stops
// setting `code` as an own data property, fails here:
//   1. a core failure                          → PolyjoseError, code in errorCodes();
//   2. a napi argument-conversion Status       → TypeError with the original message;
//   3. anything else (another napi Status, an
//      unknown code, an exception the addon
//      propagates, a non-Error value)          → re-thrown unchanged: the same value.
import { assert, test } from "../../js/dist/node/builtins.js";
import { backend } from "../backend.js";
import { createApi, ERROR_CODES, PolyjoseError } from "../facade/api.js";
import type { Backend } from "../facade/backend.js";

const OCT = { kty: "oct", k: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } as const;
const KEY = JSON.stringify(OCT);
const HS256 = '{"alg":"HS256"}';

/** What `call` threw or rejected with; it must fail. */
async function failure(call: () => unknown): Promise<unknown> {
  try {
    await call();
  } catch (e) {
    return e;
  }
  return assert.fail("the call did not fail");
}

/** `e`'s own data member `name`, as the facade reads it (ADR 0061 "Own members only"). */
function ownData(e: unknown, name: string): unknown {
  assert.ok(typeof e === "object" && e !== null, "an object");
  const d = Object.getOwnPropertyDescriptor(e, name);
  assert.ok(d !== undefined && "value" in d, `${name} is an own data property`);
  return d.value;
}

/** The real backend, with `jwkParse` replaced: the facade's jwkParse reaches only that. */
function withJwkParse(jwkParse: () => unknown): Backend {
  return { ...backend, jwkParse: jwkParse as Backend["jwkParse"] };
}

// --- 1. core failures (ADR 0061 rule 1) ------------------------------------------------------------

test("a core failure of the real backend becomes a PolyjoseError with its code and message", async () => {
  const codes = backend.errorCodes();
  const api = createApi(backend);
  const cases: [string, () => unknown, () => Promise<unknown>, string][] = [
    ["base64urlDecode", () => backend.base64urlDecode("a="), () => api.base64urlDecode("a="), "InvalidBase64"],
    ["jwkParse", () => backend.jwkParse("{}"), () => api.jwkParse("{}"), "InvalidKey"],
    [
      "jwsSignCompact",
      () => backend.jwsSignCompact(new Uint8Array(1), KEY, {}),
      () => api.jwsSignCompact(new Uint8Array(1), OCT, {}),
      "InvalidHeader",
    ],
  ];
  for (const [what, raw, mapped, code] of cases) {
    const native = await failure(raw);
    assert.equal(ownData(native, "code"), code, `${what}: napi sets the core code as an own data property`);
    const message = ownData(native, "message");
    assert.equal(typeof message, "string", `${what}: and the core message`);

    const e = await failure(mapped);
    assert.ok(e instanceof PolyjoseError, `${what}: a PolyjoseError`);
    assert.equal(e.code, code, what);
    assert.ok(codes.includes(e.code) && (ERROR_CODES as readonly string[]).includes(e.code), `${what}: a code in both lists`);
    assert.equal(e.message, message, `${what}: the core's own message`);
  }
});

// --- 2. napi argument statuses (ADR 0061 rule 2) ---------------------------------------------------

/** Raw calls the addon refuses while converting an argument, with the napi-rs Status each gives. */
const ARGUMENT_FAILURES: [string, () => unknown][] = [
  ["StringExpected", () => backend.jwkParse(42 as unknown as string)],
  ["InvalidArg", () => backend.base64urlEncode("x" as unknown as Uint8Array)],
  ["BooleanExpected", () => backend.jwsSignCompact(new Uint8Array(1), KEY, { protectedHeader: HS256, detached: "x" as unknown as boolean })],
  ["ArrayExpected", () => backend.jwsSignGeneral(new Uint8Array(1), 42 as never, false)],
  [
    "NumberExpected",
    () => backend.jwsVerifyCompact("a.b.c", KEY, { allowedAlgs: ["HS256"], maxInputLen: "x" as unknown as number }),
  ],
];

test("each napi argument Status the real backend throws becomes a TypeError with the original message", async () => {
  const codes = backend.errorCodes();
  for (const [status, raw] of ARGUMENT_FAILURES) {
    const native = await failure(raw);
    assert.ok(native instanceof Error && !(native instanceof TypeError), `${status}: napi throws a plain Error`);
    assert.equal(ownData(native, "code"), status, `${status}: as an own data code`);
    assert.ok(!codes.includes(status), `${status} is not a polyjose code`);
    const message = ownData(native, "message");

    const e = await failure(() => createApi(withJwkParse(raw)).jwkParse(OCT));
    assert.ok(e instanceof TypeError, `${status}: a TypeError`);
    assert.ok(!(e instanceof PolyjoseError), `${status}: never a PolyjoseError`);
    assert.equal(e.message, message, `${status}: napi's own message`);
  }
});

// --- 3. everything else passes through (ADR 0061 rule 3) -------------------------------------------

test("a non-argument napi Status or an unknown code from a wrapped backend function is re-thrown unchanged", async () => {
  for (const code of ["GenericFailure", "PendingException", "Cancelled", "Unknown", "NotAPolyjoseCode"]) {
    for (const how of ["sync", "async"] as const) {
      const thrown = Object.assign(new Error(`the backend failed (${code})`), { code });
      const e = await failure(() =>
        createApi(
          withJwkParse(() => {
            if (how === "async") return Promise.reject(thrown);
            throw thrown;
          }),
        ).jwkParse(OCT),
      );
      assert.equal(e, thrown, `${code} (${how}): the same object`);
      assert.equal(ownData(e, "code"), code, `${code} (${how}): the same code`);
      assert.ok(!(e instanceof TypeError) && !(e instanceof PolyjoseError), `${code} (${how}): neither class`);
    }
  }
});

test("an exception the real backend propagates from argument conversion is re-thrown unchanged", async () => {
  // A getter that throws while napi reads a record: napi-rs sees napi_pending_exception and leaves
  // the getter's own value pending, so the Promise is never made and the call throws that value.
  const coded = Object.assign(new RangeError("the getter refused"), { code: "GenericFailure" });
  const plain = { reason: "not an Error" };
  for (const value of [coded, plain]) {
    const options = {
      get protectedHeader(): string {
        throw value;
      },
    };
    const raw = (): unknown => backend.jwsSignCompact(new Uint8Array(1), KEY, options);
    assert.equal(await failure(raw), value, "the addon throws the getter's value");
    const api = createApi({ ...backend, jwsSignCompact: raw as Backend["jwsSignCompact"] });
    const e = await failure(() => api.jwsSignCompact(new Uint8Array(1), OCT, { protectedHeader: { alg: "HS256" } }));
    assert.equal(e, value, "the facade re-throws the same value");
    assert.ok(!(e instanceof TypeError) && !(e instanceof PolyjoseError), "neither class");
  }
});

test("a non-core failure never consults errorCodes(): a refusing errorCodes() does not hide it", async () => {
  const thrown = Object.assign(new Error("the backend is unusable"), { code: "GenericFailure" });
  const refusing: Backend = {
    ...withJwkParse(() => Promise.reject(thrown)),
    errorCodes: () => {
      throw new Error("errorCodes() refused");
    },
  };
  assert.equal(await failure(() => createApi(refusing).jwkParse(OCT)), thrown, "the backend's own error, not the facade's");
});
