// The JS clock for JWT validation (ADR 0028 §4, ADR 0030 §4): when the caller gives no `now`,
// every JWT verify/decrypt call passes Math.floor(Date.now() / 1000); a caller's integer is
// passed unchanged; anything else is a TypeError. Date.now is stubbed: no wall-clock assertion.
import { assert, test } from "../node/builtins.js";
import { createApi } from "../src/api.js";
import { fakeBackend } from "./fake-backend.js";

const KEY = '{"kty":"oct","k":"AAAA"}';
const JWT = { claims: "{}", header: "{}", alg: "HS256" };
const NESTED = { inner: JWT, outerHeader: "{}", recipientIndex: 0 };
const DEC = { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] };

function withStubbedNow<T>(ms: number, body: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => ms;
  return body().finally(() => {
    Date.now = real;
  });
}

function setup() {
  const fake = fakeBackend({
    handlers: {
      jwtVerify: () => JWT,
      jwtVerifyWithJwks: () => JWT,
      jwtDecryptNested: () => NESTED,
      jwtDecryptNestedWithJwks: () => NESTED,
    },
  });
  return { fake, api: createApi(fake.backend) };
}

/** The `now` each JWT verify/decrypt operation passed, in call order. */
function nows(fake: ReturnType<typeof setup>["fake"]): unknown[] {
  return fake.calls
    .filter((c) => c.op.startsWith("jwtVerify") || c.op.startsWith("jwtDecryptNested"))
    .map((c) => (c.args[c.op.startsWith("jwtDecrypt") ? 4 : 2] as { now?: unknown }).now);
}

test("without now, every JWT verify/decrypt call passes floor(Date.now() / 1000)", async () => {
  const { fake, api } = setup();
  await withStubbedNow(1_300_819_380_999, async () => {
    await api.jwtVerify("t", KEY, { allowedAlgs: ["HS256"] });
    await api.jwtVerifyWithJwks("t", '{"keys":[]}', { allowedAlgs: ["HS256"], now: null as unknown as undefined });
    await api.jwtDecryptNested("t", KEY, DEC, KEY, { allowedAlgs: ["HS256"], now: undefined });
    await api.jwtDecryptNestedWithJwks("t", KEY, DEC, '{"keys":[]}', { allowedAlgs: ["HS256"] });
  });
  assert.deepEqual(nows(fake), [1_300_819_380, 1_300_819_380, 1_300_819_380, 1_300_819_380]);
});

test("the clock is read at each call, not once", async () => {
  const { fake, api } = setup();
  await withStubbedNow(1_000, () => api.jwtVerify("t", KEY, { allowedAlgs: [] }));
  await withStubbedNow(61_500, () => api.jwtVerify("t", KEY, { allowedAlgs: [] }));
  assert.deepEqual(nows(fake), [1, 61]);
});

test("floor, not round, and correct before 1970", async () => {
  const { fake, api } = setup();
  await withStubbedNow(-1_500, () => api.jwtVerify("t", KEY, { allowedAlgs: [] }));
  assert.deepEqual(nows(fake), [-2]);
});

test("a caller's now is passed unchanged, and the clock is not read", async () => {
  const { fake, api } = setup();
  const real = Date.now;
  Date.now = () => assert.fail("Date.now must not be read when now is given");
  try {
    await api.jwtVerify("t", KEY, { allowedAlgs: [], now: 0 });
    await api.jwtVerifyWithJwks("t", '{"keys":[]}', { allowedAlgs: [], now: -100 });
    await api.jwtDecryptNested("t", KEY, DEC, KEY, { allowedAlgs: [], now: Number.MAX_SAFE_INTEGER });
    await api.jwtDecryptNestedWithJwks("t", KEY, DEC, '{"keys":[]}', { allowedAlgs: [], now: Number.MIN_SAFE_INTEGER });
  } finally {
    Date.now = real;
  }
  assert.deepEqual(nows(fake), [0, -100, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]);
});

test("a non-integer or unsafe-integer now is a TypeError before the backend is called", async () => {
  const { fake, api } = setup();
  const loose = api.jwtVerify as (t: string, k: string, o: unknown) => Promise<unknown>;
  for (const bad of [1.5, Number.NaN, Infinity, 2 ** 53, -(2 ** 53), "1300819380", 1300819380n, true, {}]) {
    await assert.rejects(loose("t", KEY, { allowedAlgs: [], now: bad }), TypeError);
  }
  assert.equal(fake.of("jwtVerify").length, 0);
});

test("the decrypt options of a nested JWT get no now", async () => {
  const { fake, api } = setup();
  await withStubbedNow(5_000, () => api.jwtDecryptNested("t", KEY, DEC, KEY, { allowedAlgs: [] }));
  assert.deepEqual(fake.of("jwtDecryptNested")[0]?.args[2], DEC);
});
