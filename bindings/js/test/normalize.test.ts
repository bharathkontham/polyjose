// Input normalisation, idiom only (ADR 0030 §2, ADR 0031 §1): JSON as text or plain object,
// bytes as Uint8Array, null as undefined, a missing allow-list as [], and a TypeError (never a
// PolyjoseError) before the backend is called for anything else.
import { assert, test } from "../node/builtins.js";
import { createApi, PolyjoseError } from "../src/api.js";
import { fakeBackend } from "./fake-backend.js";

const KEY = '{"kty":"oct","k":"AAAA"}';
const VERIFIED = { alg: "HS256", payload: new Uint8Array(), signatureIndex: 0 };
const DECRYPTED = { plaintext: new Uint8Array(), header: "{}", recipientIndex: 0 };
const JWT = { claims: "{}", header: "{}", alg: "HS256" };

/** Any facade function, called with arbitrary JS values (as untyped callers do). */
type Loose = (...args: unknown[]) => Promise<unknown>;

function setup() {
  const fake = fakeBackend({
    handlers: {
      jwkParse: () => KEY,
      jwkThumbprint: () => "t",
      jwkThumbprintUri: () => "u",
      jwksSelect: () => KEY,
      jwkGenerateOct: () => KEY,
      jwkFromDer: () => KEY,
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
      jwtDecryptNested: () => ({ inner: JWT, outerHeader: "{}", recipientIndex: 0 }),
    },
  });
  const api = createApi(fake.backend) as unknown as Record<string, Loose>;
  const fn = (name: string): Loose => {
    const f = api[name];
    assert.ok(f !== undefined, name);
    return f;
  };
  return { fake, fn };
}

/** Rejects with a TypeError (not a PolyjoseError) and never reaches the backend operation. */
async function rejectsType(fake: ReturnType<typeof setup>["fake"], call: Promise<unknown>, op: string): Promise<void> {
  const before = fake.calls.filter((c) => c.op === op).length;
  await assert.rejects(call, (e: unknown) => e instanceof TypeError && !(e instanceof PolyjoseError));
  assert.equal(fake.calls.filter((c) => c.op === op).length, before, `${op} must not be called`);
}

test("a JSON string is passed through unchanged; a plain object is JSON.stringify'd", async () => {
  const { fake, fn } = setup();
  const odd = '{ "kty" : "oct",  "k":"AAAA" }';
  await fn("jwkParse")(odd);
  await fn("jwkParse")({ kty: "oct", k: "AAAA" });
  await fn("jwkParse")(Object.assign(Object.create(null) as object, { kty: "oct" }));
  assert.deepEqual(fake.of("jwkParse").map((c) => c.args[0]), [odd, '{"kty":"oct","k":"AAAA"}', '{"kty":"oct"}']);
});

test("JSON-valued arguments of other types are TypeErrors", async () => {
  const { fake, fn } = setup();
  class NotPlain {
    kty = "oct";
  }
  for (const bad of [42, true, [], [KEY], new NotPlain(), new Date(0), undefined, null, () => KEY, Symbol("k")]) {
    await rejectsType(fake, fn("jwkParse")(bad), "jwkParse");
  }
  // A plain object whose JSON.stringify fails (cycle, BigInt) is a TypeError too.
  const cyclic: Record<string, unknown> = { kty: "oct" };
  cyclic["self"] = cyclic;
  await rejectsType(fake, fn("jwkParse")(cyclic), "jwkParse");
  await rejectsType(fake, fn("jwkParse")({ kty: "oct", n: 1n }), "jwkParse");
});

test("bytes accept Uint8Array and Buffer, and nothing else", async () => {
  const { fake, fn } = setup();
  const u8 = new Uint8Array([1, 2]);
  const NodeBuffer = (globalThis as unknown as { Buffer: { from(a: number[]): Uint8Array } }).Buffer;
  const buf = NodeBuffer.from([3]);
  await fn("base64urlEncode")(u8);
  await fn("base64urlEncode")(buf);
  const passed = fake.of("base64urlEncode").map((c) => c.args[0]);
  assert.equal(passed[0], u8, "passed as given, not copied");
  assert.equal(passed[1], buf);
  for (const bad of ["AQI", [1, 2], new ArrayBuffer(2), new DataView(new ArrayBuffer(2)), new Uint16Array(2), new Int8Array(2), null, undefined, { length: 0 }]) {
    await rejectsType(fake, fn("base64urlEncode")(bad), "base64urlEncode");
  }
  // A fake with Uint8Array's toStringTag is not a Uint8Array.
  await rejectsType(fake, fn("base64urlEncode")({ [Symbol.toStringTag]: "Uint8Array", length: 0 }), "base64urlEncode");
});

test("strings are checked", async () => {
  const { fake, fn } = setup();
  for (const bad of [1, null, undefined, {}, new String("x")]) {
    await rejectsType(fake, fn("base64urlDecode")(bad), "base64urlDecode");
  }
  // The thumbprint hash is optional (ADR 0054 §9), so only null and undefined may be left out.
  for (const bad of [1, {}, new String("x"), ["SHA-256"]]) {
    await rejectsType(fake, fn("jwkThumbprint")(KEY, bad), "jwkThumbprint");
    await rejectsType(fake, fn("jwkThumbprintUri")(KEY, bad), "jwkThumbprintUri");
  }
});

test("an absent thumbprint hash (omitted, undefined or null) reaches the backend as undefined", async () => {
  // ADR 0054 §9: absent is the core default, SHA-256; the facade writes no default of its own.
  const { fake, fn } = setup();
  for (const op of ["jwkThumbprint", "jwkThumbprintUri"] as const) {
    await fn(op)(KEY);
    await fn(op)(KEY, undefined);
    await fn(op)(KEY, null);
    await fn(op)(KEY, "sha256");
    await fn(op)(KEY, "Sha-256");
    const passed = fake.of(op).map((c) => c.args);
    assert.deepEqual(passed, [
      [KEY, undefined],
      [KEY, undefined],
      [KEY, undefined],
      // A name is passed as given: the core parses it (ADR 0054 §8.2) and rejects what it must.
      [KEY, "sha256"],
      [KEY, "Sha-256"],
    ]);
    for (const args of passed) assert.equal(args.length, 2, `${op} gets (jwk, hash)`);
  }
});

test("null is undefined: null options and fields are left out, never passed to the backend", async () => {
  const { fake, fn } = setup();
  await fn("jwsVerifyCompact")("t", KEY, { allowedAlgs: ["HS256"], detachedPayload: null, maxInputLen: null, maxSignatures: undefined });
  assert.deepEqual(fake.of("jwsVerifyCompact")[0]?.args[2], { allowedAlgs: ["HS256"] });
  await fn("jwsSignCompact")(new Uint8Array(), KEY, null);
  assert.deepEqual(fake.of("jwsSignCompact")[0]?.args[2], {});
  await fn("jwksSelect")(KEY, null);
  assert.deepEqual(fake.of("jwksSelect")[0]?.args[1], {});
  await fn("jwtSign")({}, KEY, { alg: "HS256", typ: null, header: null });
  assert.deepEqual(fake.of("jwtSign")[0]?.args[2], { alg: "HS256" });
  await fn("jweEncryptCompact")(new Uint8Array(), { enc: "A128GCM", recipients: [{ alg: "dir", key: KEY, header: null, p2c: null }], aad: null });
  assert.deepEqual(fake.of("jweEncryptCompact")[0]?.args[1], { enc: "A128GCM", recipients: [{ alg: "dir", key: KEY }] });
});

test("a missing allowedAlgs or allowedEnc is passed as [] (the core answers AlgorithmNotAllowed)", async () => {
  const { fake, fn } = setup();
  await fn("jwsVerifyCompact")("t", KEY);
  await fn("jwsVerifyJson")("{}", KEY, {});
  await fn("jwsVerifyCompact")("t", KEY, { allowedAlgs: null });
  assert.deepEqual(fake.of("jwsVerifyCompact").map((c) => c.args[2]), [{ allowedAlgs: [] }, { allowedAlgs: [] }]);
  assert.deepEqual(fake.of("jwsVerifyJson")[0]?.args[2], { allowedAlgs: [] });
  await fn("jweDecryptCompact")("t", KEY);
  await fn("jweDecryptJson")("{}", KEY, { allowedAlgs: ["dir"] });
  assert.deepEqual(fake.of("jweDecryptCompact")[0]?.args[2], { allowedAlgs: [], allowedEnc: [] });
  assert.deepEqual(fake.of("jweDecryptJson")[0]?.args[2], { allowedAlgs: ["dir"], allowedEnc: [] });
  await fn("jwtVerify")("t", KEY, { now: 1 });
  assert.deepEqual(fake.of("jwtVerify")[0]?.args[2], { allowedAlgs: [], now: 1 });
});

test("lists: a non-array, a non-string element or a hole is a TypeError; arrays are copied", async () => {
  const { fake, fn } = setup();
  const list = ["HS256"];
  await fn("jwsVerifyCompact")("t", KEY, { allowedAlgs: list });
  const passed = fake.of("jwsVerifyCompact")[0]?.args[2] as { allowedAlgs: string[] };
  assert.notEqual(passed.allowedAlgs, list, "copied, so later mutation can't change the call");
  const sparse: string[] = [];
  sparse[1] = "HS256";
  for (const bad of ["HS256", { 0: "HS256", length: 1 }, [1], ["HS256", null], sparse, new Set(["HS256"])]) {
    await rejectsType(fake, fn("jwsVerifyCompact")("t", KEY, { allowedAlgs: bad }), "jwsVerifyCompact");
    await rejectsType(fake, fn("jweDecryptCompact")("t", KEY, { allowedAlgs: ["dir"], allowedEnc: bad }), "jweDecryptCompact");
    await rejectsType(fake, fn("jwtVerify")("t", KEY, { allowedAlgs: ["HS256"], issuers: bad }), "jwtVerify");
  }
});

test("sizes and counts must be integers in 0..=2^32-1", async () => {
  const { fake, fn } = setup();
  await fn("jwsVerifyCompact")("t", KEY, { allowedAlgs: [], maxInputLen: 0, maxSignatures: 2 ** 32 - 1 });
  assert.deepEqual(fake.of("jwsVerifyCompact")[0]?.args[2], { allowedAlgs: [], maxInputLen: 0, maxSignatures: 4294967295 });
  for (const bad of [-1, 1.5, 2 ** 32, Number.NaN, Infinity, "5", 5n, true, -0.5]) {
    await rejectsType(fake, fn("jwsVerifyCompact")("t", KEY, { allowedAlgs: [], maxInputLen: bad }), "jwsVerifyCompact");
    await rejectsType(fake, fn("jwkGenerateOct")(bad), "jwkGenerateOct");
    await rejectsType(fake, fn("jweDecryptCompact")("t", KEY, { allowedAlgs: [], allowedEnc: [], maxPbes2Count: bad }), "jweDecryptCompact");
    await rejectsType(fake, fn("jweEncryptCompact")(new Uint8Array(), { enc: "A128GCM", recipients: [{ alg: "PBES2-HS256+A128KW", key: KEY, p2c: bad }] }), "jweEncryptCompact");
    await rejectsType(fake, fn("jwtVerify")("t", KEY, { allowedAlgs: [], now: 0, leeway: bad }), "jwtVerify");
  }
});

test("booleans are checked", async () => {
  const { fake, fn } = setup();
  for (const bad of [0, 1, "true", {}]) {
    await rejectsType(fake, fn("jwsSignFlattened")(new Uint8Array(), { key: KEY }, bad), "jwsSignFlattened");
    await rejectsType(fake, fn("jwsSignCompact")(new Uint8Array(), KEY, { detached: bad }), "jwsSignCompact");
    await rejectsType(fake, fn("jwtVerify")("t", KEY, { allowedAlgs: [], now: 0, allowMissingExp: bad }), "jwtVerify");
  }
});

test("records must be plain objects without unknown members", async () => {
  const { fake, fn } = setup();
  // A misspelled member must not silently drop a check (issuers vs issuer).
  await rejectsType(fake, fn("jwtVerify")("t", KEY, { allowedAlgs: ["HS256"], now: 0, issuer: "joe" }), "jwtVerify");
  await rejectsType(fake, fn("jwsVerifyCompact")("t", KEY, { allowedAlg: ["HS256"] }), "jwsVerifyCompact");
  await rejectsType(fake, fn("jwsVerifyCompact")("t", KEY, ["HS256"]), "jwsVerifyCompact");
  await rejectsType(fake, fn("jwsVerifyCompact")("t", KEY, "HS256"), "jwsVerifyCompact");
  await rejectsType(fake, fn("jwsSignGeneral")(new Uint8Array(), [{ key: KEY, protectedB64u: "e30", extra: 1 }], false), "jwsSignGeneral");
  await rejectsType(fake, fn("jwsSignGeneral")(new Uint8Array(), { key: KEY }, false), "jwsSignGeneral");
  await rejectsType(fake, fn("jwsSignGeneral")(new Uint8Array(), [null], false), "jwsSignGeneral");
  await rejectsType(fake, fn("jweEncryptCompact")(new Uint8Array(), { enc: "A128GCM" }), "jweEncryptCompact");
  await rejectsType(fake, fn("jweEncryptCompact")(new Uint8Array(), { recipients: [] }), "jweEncryptCompact");
  await rejectsType(fake, fn("jweEncryptJson")(new Uint8Array(), { enc: "A128GCM", recipients: [] }, 3), "jweEncryptJson");
  await rejectsType(fake, fn("jwtSign")({}, KEY, {}), "jwtSign");
  await rejectsType(fake, fn("jwtSign")({}, KEY), "jwtSign");
});

test("every record field is passed under its camelCase name, JSON fields as text", async () => {
  const { fake, fn } = setup();
  const payload = new Uint8Array([1]);
  await fn("jwsSignCompact")(payload, { kty: "oct", k: "AAAA" }, { protectedHeader: { alg: "HS256" }, detached: true });
  assert.deepEqual(fake.of("jwsSignCompact")[0]?.args, [payload, KEY, { protectedHeader: '{"alg":"HS256"}', detached: true }]);
  await fn("jwsSignFlattened")(payload, { key: KEY, unprotectedHeader: { alg: "HS256" } }, false);
  assert.deepEqual(fake.of("jwsSignFlattened")[0]?.args, [payload, { key: KEY, unprotectedHeader: '{"alg":"HS256"}' }, false]);
  await fn("jwsSignGeneral")(payload, [{ key: KEY, protectedB64u: "e30", unprotectedHeader: '{"kid":"1"}' }], true);
  assert.deepEqual(fake.of("jwsSignGeneral")[0]?.args, [payload, [{ key: KEY, protectedB64u: "e30", unprotectedHeader: '{"kid":"1"}' }], true]);
  await fn("jwsVerifyJson")({ payload: "", signature: "" }, KEY, { allowedAlgs: ["HS256"], detachedPayload: payload, maxSignatures: 3 });
  assert.deepEqual(fake.of("jwsVerifyJson")[0]?.args, ['{"payload":"","signature":""}', KEY, { allowedAlgs: ["HS256"], detachedPayload: payload, maxSignatures: 3 }]);
  await fn("jwksSelect")({ keys: [] }, { kid: "a", alg: "ES256", keyUse: "sig" });
  assert.deepEqual(fake.of("jwksSelect")[0]?.args, ['{"keys":[]}', { kid: "a", alg: "ES256", keyUse: "sig" }]);
  await fn("jwkFromDer")(payload, "spki");
  assert.deepEqual(fake.of("jwkFromDer")[0]?.args, [payload, "spki"]);
  const apu = new Uint8Array([2]);
  const aad = new Uint8Array([3]);
  const enc = {
    enc: "A128GCM",
    recipients: [{ alg: "ECDH-ES+A128KW", key: KEY, header: { kid: "r" }, apu, apv: apu, p2c: 1, p2sLen: 16 }],
    protectedHeader: { cty: "x" },
    sharedUnprotectedHeader: '{"jku":"u"}',
    aad,
    compress: false,
  };
  await fn("jweEncryptJson")(payload, enc, "flattened");
  assert.deepEqual(fake.of("jweEncryptJson")[0]?.args, [
    payload,
    {
      enc: "A128GCM",
      recipients: [{ alg: "ECDH-ES+A128KW", key: KEY, header: '{"kid":"r"}', apu, apv: apu, p2c: 1, p2sLen: 16 }],
      protectedHeader: '{"cty":"x"}',
      sharedUnprotectedHeader: '{"jku":"u"}',
      aad,
      compress: false,
    },
    "flattened",
  ]);
  const decrypt = { allowedAlgs: ["A128KW"], allowedEnc: ["A128GCM"], maxPbes2Count: 1, maxDecompressedLen: 2, maxInputLen: 3, maxRecipients: 4, understoodCrit: ["b64"] };
  await fn("jweDecryptJson")({ ciphertext: "" }, KEY, decrypt);
  assert.deepEqual(fake.of("jweDecryptJson")[0]?.args, ['{"ciphertext":""}', KEY, decrypt]);
  await fn("jwtSign")('{"sub":"x","1":2}', KEY, { alg: "HS256", typ: "at+jwt", omitTyp: false, accessToken: true, header: { kid: "k" } });
  assert.deepEqual(fake.of("jwtSign")[0]?.args, ['{"sub":"x","1":2}', KEY, { alg: "HS256", typ: "at+jwt", omitTyp: false, accessToken: true, header: '{"kid":"k"}' }]);
  const verify = {
    allowedAlgs: ["HS256"],
    now: -5,
    issuers: ["joe"],
    audiences: ["a"],
    subject: "s",
    leeway: 10,
    maxAge: 20,
    requiredClaims: ["jti"],
    allowMissingExp: true,
    ignoreAudience: false,
    typ: "JWT",
    anyTyp: false,
    profile: "access_token",
    maxKeyCandidates: 2,
    maxInputLen: 99,
  };
  await fn("jwtVerifyWithJwks")("t", { keys: [] }, verify);
  assert.deepEqual(fake.of("jwtVerifyWithJwks")[0]?.args, ["t", '{"keys":[]}', verify]);
});

test("TypeError messages name the argument, never its value", async () => {
  const { fn } = setup();
  const marker = "SECRET-MARKER-9d1c";
  const checks: Promise<unknown>[] = [
    fn("jwsVerifyCompact")("t", { kty: "oct", k: marker, n: 1n }, { allowedAlgs: [] }),
    fn("jwsVerifyCompact")(marker, KEY, { allowedAlgs: [marker, 1] }),
    fn("jwsVerifyCompact")("t", KEY, { allowedAlgs: [], [marker]: 1 }),
    fn("jwtVerify")("t", KEY, { allowedAlgs: [], now: 0.5, subject: marker }),
    fn("base64urlEncode")(marker),
  ];
  for (const check of checks) {
    await assert.rejects(check, (e: unknown) => {
      assert.ok(e instanceof TypeError);
      assert.doesNotMatch(e.message, new RegExp(marker));
      assert.doesNotMatch(String(e), new RegExp(marker));
      return true;
    });
  }
});
