// How the facade reports a backend failure (0013 F12; ADR 0030 §5, ADR 0031 §1, BACKEND.md
// "Errors"), against the fake backend:
//   - an own `code` in both errorCodes() and ERROR_CODES       → PolyjoseError (F04 N2);
//   - a host argument error (a TypeError, or an Error whose own
//     `code` is a napi-rs argument-conversion Status)          → TypeError, original message;
//   - anything else (a WebAssembly trap, a "backend unusable"
//     refusal, another napi status, an uncoded Error)          → re-thrown unchanged.
// `code` and `message` are own data members only: a polluted prototype never makes a
// PolyjoseError or changes a message.
import { assert, test } from "../node/builtins.js";
import { createApi, ERROR_CODES, PolyjoseError } from "../src/api.js";
import { coded, fakeBackend } from "./fake-backend.js";

const KEY = '{"kty":"oct","k":"AAAA"}';

/** `WebAssembly.RuntimeError`, reached through globalThis: lib is ES2022 only (tsconfig). */
const RuntimeError = (globalThis as unknown as { WebAssembly: { RuntimeError: new (message: string) => Error } }).WebAssembly.RuntimeError;

/**
 * napi-rs 3.16's argument-conversion `Status` names (napi-3.16.1 `src/status.rs`, the
 * `AsRef<str>` the JS error's `code` comes from), copied here rather than from src/.
 */
const NAPI_ARGUMENT_STATUSES = [
  "InvalidArg",
  "ObjectExpected",
  "StringExpected",
  "NameExpected",
  "FunctionExpected",
  "NumberExpected",
  "BooleanExpected",
  "ArrayExpected",
  "BigintExpected",
  "DateExpected",
  "ArrayBufferExpected",
  "DetachableArraybufferExpected",
] as const;

/** napi-rs 3.16 statuses that are not about a caller's argument. */
const NAPI_OTHER_STATUSES = ["GenericFailure", "PendingException", "Cancelled", "EscapeCalledTwice", "HandleScopeMismatch", "CallbackScopeMismatch", "QueueFull", "Closing", "WouldDeadlock", "NoExternalBuffersAllowed", "Unknown"] as const;

type How = "sync" | "async";
const HOWS: readonly How[] = ["sync", "async"];

/** A handler that throws `e` synchronously, or returns a Promise rejected with it. */
function failing(e: unknown, how: How): () => unknown {
  return () => {
    if (how === "async") return Promise.reject(e);
    throw e;
  };
}

/** What the call rejected with (it must reject). */
async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  assert.fail("the call resolved");
}

test("a WebAssembly.RuntimeError reaches the caller as that same object, thrown or rejected", async () => {
  for (const how of HOWS) {
    const trap = new RuntimeError("unreachable");
    const fake = fakeBackend({ handlers: { jwkParse: failing(trap, how), base64urlDecode: failing(trap, how) } });
    const api = createApi(fake.backend);
    // Both an operation that copies bytes (run) and a JSON one: the same object, untouched.
    for (const p of [api.jwkParse(KEY), api.base64urlDecode("AAAA")]) {
      const got = await rejection(p);
      assert.equal(got, trap, `${how}: the same object`);
      assert.ok(!(got instanceof TypeError), `${how}: not a TypeError`);
      assert.ok(!(got instanceof PolyjoseError), `${how}: not a PolyjoseError`);
      assert.equal((got as Error).message, "unreachable");
    }
  }
});

test("after a trap, a backend's own 'module poisoned, reload it' refusal is passed through unchanged", async () => {
  for (const how of HOWS) {
    const trap = new RuntimeError("unreachable");
    const poisoned = new Error("polyjose: the WASM module trapped earlier and is unusable; reload it");
    let trapped = false;
    const fake = fakeBackend({
      handlers: {
        jwsVerifyCompact: () => {
          if (trapped) return failing(poisoned, how)();
          trapped = true;
          return failing(trap, how)();
        },
        // A poisoned backend refuses errorCodes() too: a refusal without a core code must
        // not need it, so the caller still sees the refusal, not an "errorCodes() failed".
        errorCodes: () => {
          if (trapped) throw poisoned;
          return [...ERROR_CODES];
        },
      },
    });
    const api = createApi(fake.backend);
    const verify = () => api.jwsVerifyCompact("a.b.c", KEY, { allowedAlgs: ["HS256"] });
    assert.equal(await rejection(verify()), trap, `${how}: the trap first`);
    for (let i = 0; i < 2; i++) assert.equal(await rejection(verify()), poisoned, `${how}: then the refusal, unchanged`);
  }
});

test("an Error whose own code is a napi-rs argument-conversion status is a TypeError with the original message", async () => {
  for (const code of NAPI_ARGUMENT_STATUSES) {
    for (const how of HOWS) {
      const message = `Failed to convert JavaScript value (${code}, ${how})`;
      const fake = fakeBackend({ handlers: { jwkParse: failing(coded(code, message), how) } });
      const got = await rejection(createApi(fake.backend).jwkParse(KEY));
      assert.ok(got instanceof TypeError, `${code} ${how}: a TypeError`);
      assert.ok(!(got instanceof PolyjoseError), `${code} ${how}: not a PolyjoseError`);
      assert.equal(got.message, message, `${code} ${how}: the original message`);
    }
  }
});

test("a napi-rs status that is not about an argument is passed through unchanged, never a TypeError", async () => {
  for (const code of NAPI_OTHER_STATUSES) {
    for (const how of HOWS) {
      const e = coded(code, `napi ${code}`);
      const fake = fakeBackend({ handlers: { jwkParse: failing(e, how) } });
      const got = await rejection(createApi(fake.backend).jwkParse(KEY));
      assert.equal(got, e, `${code} ${how}: the same object`);
      assert.ok(!(got instanceof TypeError), `${code} ${how}: not a TypeError`);
    }
  }
});

test("an argument-status code on something that is not an Error is passed through unchanged", async () => {
  const plain = { code: "InvalidArg", message: "not an Error" };
  const fake = fakeBackend({ handlers: { jwkParse: failing(plain, "sync") } });
  assert.equal(await rejection(createApi(fake.backend).jwkParse(KEY)), plain);
});

test("a TypeError from the backend (a wasm reader) reaches the caller as a TypeError with its message", async () => {
  for (const how of HOWS) {
    const e = new TypeError(`jwsVerifyCompact: options.allowedAlgs is not an array (${how})`);
    const fake = fakeBackend({ handlers: { jwkParse: failing(e, how) } });
    const got = await rejection(createApi(fake.backend).jwkParse(KEY));
    assert.ok(got instanceof TypeError, `${how}: a TypeError`);
    assert.equal(got.message, e.message, `${how}: the original message`);
  }
});

test("an own core code is a PolyjoseError, thrown or rejected (F04 N2 unchanged)", async () => {
  for (const how of HOWS) {
    const fake = fakeBackend({ handlers: { jwkParse: failing(coded("InvalidKey", "invalid JWK"), how) } });
    const got = await rejection(createApi(fake.backend).jwkParse(KEY));
    assert.ok(got instanceof PolyjoseError, `${how}: a PolyjoseError`);
    assert.equal(got.code, "InvalidKey");
    assert.equal(got.message, "invalid JWK");
  }
});

test("a code or message only on a polluted prototype never makes a PolyjoseError", async () => {
  for (const proto of [Object.prototype, Error.prototype]) {
    for (const how of HOWS) {
      const inheritedCode = new RuntimeError("unreachable");
      const uncoded = new Error("uncoded");
      const fake = fakeBackend({
        handlers: {
          jwkParse: failing(inheritedCode, how),
          jwkToPublic: failing(uncoded, how),
        },
      });
      const api = createApi(fake.backend);
      (proto as Record<string, unknown>)["code"] = "InvalidKey";
      try {
        for (const [p, e] of [[api.jwkParse(KEY), inheritedCode], [api.jwkToPublic(KEY), uncoded]] as const) {
          const got = await rejection(p);
          assert.ok(!(got instanceof PolyjoseError), `${how}: an inherited code is not a PolyjoseError`);
          assert.equal(got, e, `${how}: passed through unchanged`);
        }
      } finally {
        delete (proto as Record<string, unknown>)["code"];
      }
    }
  }
});

test("an own accessor code is never run or read as the code", async () => {
  let getterCalls = 0;
  const accessor = new Error("accessor");
  Object.defineProperty(accessor, "code", {
    get: () => {
      getterCalls++;
      return "InvalidKey";
    },
  });
  const fake = fakeBackend({ handlers: { jwkParse: failing(accessor, "sync") } });
  const got = await rejection(createApi(fake.backend).jwkParse(KEY));
  assert.ok(!(got instanceof PolyjoseError), "an accessor code is not a PolyjoseError");
  assert.equal(got, accessor);
  assert.equal(getterCalls, 0, "the getter is never run");
});

test("an own core code with its message only on a polluted prototype does not take that message", async () => {
  for (const proto of [Object.prototype, Error.prototype]) {
    const e = Object.create(Error.prototype) as Record<string, unknown>;
    e["code"] = "InvalidKey"; // own code, no own message
    const napi = Object.create(Error.prototype) as Record<string, unknown>;
    napi["code"] = "InvalidArg";
    const fake = fakeBackend({ handlers: { jwkParse: failing(e, "sync"), jwkToPublic: failing(napi, "async") } });
    const api = createApi(fake.backend);
    const original = Object.getOwnPropertyDescriptor(proto, "message");
    Object.defineProperty(proto, "message", { value: "polluted", writable: true, configurable: true, enumerable: true });
    try {
      const core = await rejection(api.jwkParse(KEY));
      assert.ok(core instanceof PolyjoseError);
      assert.equal(core.code, "InvalidKey");
      assert.ok(!core.message.includes("polluted"), `core: ${core.message}`);
      const arg = await rejection(api.jwkToPublic(KEY));
      assert.ok(arg instanceof TypeError);
      assert.ok(!arg.message.includes("polluted"), `arg: ${arg.message}`);
    } finally {
      if (original === undefined) delete (proto as Record<string, unknown>)["message"];
      else Object.defineProperty(proto, "message", original);
    }
  }
});
