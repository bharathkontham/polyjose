// Tester additions for 0013 F12: hostile thrown values through mapError, and how the
// conformance runner reports a passed-through backend failure (always a per-vector fail).
import { assert, fs, path, process, test } from "../node/builtins.js";
import { createApi, ERROR_CODES, PolyjoseError } from "../src/api.js";
import { runVectors, type VectorFile } from "../conformance/runner.js";
import { coded, fakeBackend } from "./fake-backend.js";
import { toyBackend } from "./toy-backend.js";

const KEY = '{"kty":"oct","k":"AAAA"}';
type How = "sync" | "async";
const HOWS: readonly How[] = ["sync", "async"];

function failing(e: unknown, how: How): () => unknown {
  return () => {
    if (how === "async") return Promise.reject(e);
    throw e;
  };
}

/** What the call rejected with, boxed: returning a hostile Proxy from an async function would read its `then`. */
async function rejected(p: Promise<unknown>): Promise<{ value: unknown }> {
  try {
    await p;
  } catch (e) {
    return { value: e };
  }
  assert.fail("the call resolved");
}
const rejection = async (p: Promise<unknown>): Promise<unknown> => (await rejected(p)).value;

test("a Proxy error whose every trap throws is passed through, never a PolyjoseError or a crash", async () => {
  const boom = () => {
    throw new Error("trap ran");
  };
  const hostile = new Proxy(new Error("x"), { getOwnPropertyDescriptor: boom, getPrototypeOf: boom, get: boom, has: boom, ownKeys: boom });
  for (const how of HOWS) {
    const fake = fakeBackend({ handlers: { jwkParse: failing(hostile, how) } });
    const got = (await rejected(createApi(fake.backend).jwkParse(KEY))).value;
    assert.ok(Object.is(got, hostile), `${how}: the same Proxy`);
  }
});

test("a Proxy that reports a core code only through get/has is not a PolyjoseError", async () => {
  const sneaky = new Proxy(new Error("x"), { get: (_t, k) => (k === "code" ? "InvalidKey" : undefined) });
  const fake = fakeBackend({ handlers: { jwkParse: failing(sneaky, "sync") } });
  const got = (await rejected(createApi(fake.backend).jwkParse(KEY))).value;
  assert.ok(!(got instanceof PolyjoseError));
  assert.ok(Object.is(got, sneaky));
});

test("thrown primitives, null, undefined, symbols and null-prototype objects pass through; Object.prototype pollution changes nothing", async () => {
  const values: unknown[] = ["text", 7, null, undefined, Symbol("s"), Object.create(null), { message: "m" }, 12n];
  const op = Object.prototype as unknown as Record<string, unknown>;
  op["code"] = "InvalidKey";
  try {
    for (const v of values) {
      for (const how of HOWS) {
        const fake = fakeBackend({ handlers: { jwkParse: failing(v, how) } });
        const got = await rejection(createApi(fake.backend).jwkParse(KEY));
        assert.ok(Object.is(got, v), `${how}: ${String(typeof v)} unchanged`);
      }
    }
  } finally {
    delete op["code"];
  }
});

test("an own core code is still a PolyjoseError while Object.prototype.code is polluted with something else", async () => {
  const op = Object.prototype as unknown as Record<string, unknown>;
  op["code"] = "InvalidArg";
  try {
    const fake = fakeBackend({ handlers: { jwkParse: failing(coded("InvalidKey", "k"), "sync") } });
    const got = await rejection(createApi(fake.backend).jwkParse(KEY));
    assert.ok(got instanceof PolyjoseError && got.code === "InvalidKey");
    // and no PolyjoseError ever carries a code outside ERROR_CODES
    assert.ok((ERROR_CODES as readonly string[]).includes((got as PolyjoseError).code));
  } finally {
    delete op["code"];
  }
});

test("a core code with errorCodes() refusing is still loud, even for a prototype-less coded error", async () => {
  const e = Object.create(null) as Record<string, unknown>;
  e["code"] = "InvalidKey";
  e["message"] = "k";
  const fake = fakeBackend({
    handlers: {
      errorCodes: () => {
        throw new Error("nope");
      },
      jwkParse: failing(e, "sync"),
    },
  });
  const got = (await rejection(createApi(fake.backend).jwkParse(KEY))) as Error;
  assert.ok(got instanceof Error && !(got instanceof PolyjoseError) && /errorCodes\(\)/.test(got.message));
});

const RuntimeError = (globalThis as unknown as { WebAssembly: { RuntimeError: new (m: string) => Error } }).WebAssembly.RuntimeError;

async function runnerResult(thrown: unknown) {
  const dir = path.resolve(process.cwd(), "test/fixtures/vectors");
  const vf: VectorFile = { path: "jws/verify-json-reject.json", json: fs.readFileSync(path.join(dir, "jws/verify-json-reject.json"), "utf8") };
  const schema = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), "../../conformance/schema.json"), "utf8")) as unknown;
  const fake = toyBackend({ jwsVerifyJson: () => { throw thrown; } });
  const [r] = await runVectors(createApi(fake.backend), [vf], { schema, features: [] });
  assert.ok(r !== undefined);
  return r;
}

test("conformance runner: a passed-through WebAssembly trap or thrown string is a per-vector fail, never an outcome", async () => {
  for (const thrown of [new RuntimeError("unreachable"), "a string", 7, { message: "m" }]) {
    const r = await runnerResult(thrown);
    assert.equal(r.status, "fail");
    assert.equal(r.actual, undefined);
  }
});
