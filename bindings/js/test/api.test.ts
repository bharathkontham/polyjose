// createApi's shape, PolyjoseError, output normalisation, error mapping and lazy
// initialisation (ADR 0030 §2, §5; ADR 0031 §1), against the fake backend.
import { assert, test } from "../node/builtins.js";
import { createApi, ERROR_CODES, PolyjoseError } from "../src/api.js";
import { coded, fakeBackend, OPERATIONS } from "./fake-backend.js";

const KEY = '{"kty":"oct","k":"AAAA"}';
const VERIFY = { allowedAlgs: ["HS256"] };

test("createApi returns every ADR 0030 operation, camelCase, plus PolyjoseError", () => {
  const api = createApi(fakeBackend().backend);
  assert.deepEqual(Object.keys(api).sort(), [...OPERATIONS, "PolyjoseError"].sort());
  assert.equal(api.PolyjoseError, PolyjoseError);
});

test("every operation is async: it returns a Promise, even version and errorCodes", async () => {
  const api = createApi(fakeBackend().backend);
  const v = api.version();
  const c = api.errorCodes();
  assert.ok(v instanceof Promise);
  assert.ok(c instanceof Promise);
  assert.equal(await v, "0.1.2");
  assert.deepEqual(await c, [...ERROR_CODES]);
  // An operation whose arguments are wrong rejects rather than throwing synchronously.
  const bad = (api.base64urlEncode as (x: unknown) => Promise<string>)(42);
  assert.ok(bad instanceof Promise);
  await assert.rejects(bad, TypeError);
});

test("PolyjoseError extends Error with name, code and message, and no cause", () => {
  const e = new PolyjoseError("InvalidKey", "invalid key");
  assert.ok(e instanceof Error);
  assert.equal(e.name, "PolyjoseError");
  assert.equal(e.code, "InvalidKey");
  assert.equal(e.message, "invalid key");
  assert.ok(!("cause" in e));
  assert.match(String(e), /^PolyjoseError: invalid key$/);
});

// --- outputs ---------------------------------------------------------------------------

test("JWK results are parsed objects", async () => {
  const jwk = '{"kty":"EC","crv":"P-256","x":"a","y":"b"}';
  const fake = fakeBackend({
    handlers: {
      jwkParse: () => jwk,
      jwkToPublic: () => jwk,
      jwksSelect: () => jwk,
      jwkGenerateOct: () => '{"kty":"oct","k":"AAAA"}',
      jwkGenerateEc: () => jwk,
      jwkGenerateOkp: () => '{"kty":"OKP","crv":"Ed25519","x":"a","d":"b"}',
      jwkGenerateForAlg: () => jwk,
      jwkFromPem: () => jwk,
      jwkFromDer: () => jwk,
    },
  });
  const api = createApi(fake.backend);
  const want = { kty: "EC", crv: "P-256", x: "a", y: "b" };
  assert.deepEqual(await api.jwkParse(jwk), want);
  assert.deepEqual(await api.jwkToPublic(jwk), want);
  assert.deepEqual(await api.jwksSelect('{"keys":[]}', { kid: "1" }), want);
  assert.deepEqual(await api.jwkGenerateOct(16), { kty: "oct", k: "AAAA" });
  assert.deepEqual(await api.jwkGenerateEc("P-256"), want);
  assert.deepEqual((await api.jwkGenerateOkp("Ed25519")).crv, "Ed25519");
  assert.deepEqual(await api.jwkGenerateForAlg("ES256"), want);
  assert.deepEqual(await api.jwkFromPem("-----BEGIN PUBLIC KEY-----"), want);
  assert.deepEqual(await api.jwkFromDer(new Uint8Array([48]), "spki"), want);
});

test("strings stay strings and bytes are Uint8Array", async () => {
  const fake = fakeBackend({
    handlers: {
      jwkThumbprint: () => "tp",
      jwkThumbprintUri: () => "urn:ietf:params:oauth:jwk-thumbprint:sha-256:tp",
      jwkToPem: () => "PEM",
      jwkToDer: () => new Uint8Array([1, 2]),
      jwsSignCompact: () => "a.b.c",
      jwsSignFlattened: () => '{"payload":"","signature":""}',
      jwsSignGeneral: () => '{"payload":"","signatures":[]}',
      jweEncryptCompact: () => "a.b.c.d.e",
      jweEncryptJson: () => '{"ciphertext":""}',
      jwtSign: () => "h.p.s",
      jwtEncryptNested: () => "1.2.3.4.5",
    },
  });
  const api = createApi(fake.backend);
  assert.equal(await api.base64urlEncode(new Uint8Array([0xfb])), "-w");
  assert.deepEqual(await api.base64urlDecode("-w"), new Uint8Array([0xfb]));
  assert.equal(await api.jwkThumbprint(KEY, "SHA-256"), "tp");
  assert.equal(await api.jwkThumbprintUri(KEY, "SHA-256"), "urn:ietf:params:oauth:jwk-thumbprint:sha-256:tp");
  assert.equal(await api.jwkThumbprint(KEY), "tp");
  assert.equal(await api.jwkThumbprintUri(KEY), "urn:ietf:params:oauth:jwk-thumbprint:sha-256:tp");
  assert.equal(await api.jwkToPem(KEY, "pkcs8"), "PEM");
  assert.deepEqual(await api.jwkToDer(KEY, "pkcs8"), new Uint8Array([1, 2]));
  assert.equal(await api.jwsSignCompact(new Uint8Array(), KEY, { protectedB64u: "e30" }), "a.b.c");
  assert.equal(await api.jwsSignFlattened(new Uint8Array(), { key: KEY, protectedB64u: "e30" }, false), '{"payload":"","signature":""}');
  assert.equal(await api.jwsSignGeneral(new Uint8Array(), [{ key: KEY, protectedB64u: "e30" }], false), '{"payload":"","signatures":[]}');
  const enc = { enc: "A128GCM", recipients: [{ alg: "dir", key: KEY }] };
  assert.equal(await api.jweEncryptCompact(new Uint8Array(), enc), "a.b.c.d.e");
  assert.equal(await api.jweEncryptJson(new Uint8Array(), enc, "general"), '{"ciphertext":""}');
  assert.equal(await api.jwtSign({ sub: "x" }, KEY, { alg: "HS256" }), "h.p.s");
  assert.equal(await api.jwtEncryptNested("h.p.s", enc), "1.2.3.4.5");
});

test("JwsVerified: headers parsed, payload bytes, absent headers left out", async () => {
  const payload = new Uint8Array([1]);
  const fake = fakeBackend({
    handlers: {
      jwsVerifyCompact: () => ({ alg: "HS256", payload, protectedHeader: '{"alg":"HS256"}', signatureIndex: 0 }),
      jwsVerifyJson: () => ({ alg: "HS256", payload, protectedHeader: null, unprotectedHeader: '{"kid":"1"}', signatureIndex: 2 }),
    },
  });
  const api = createApi(fake.backend);
  const compact = await api.jwsVerifyCompact("t", KEY, VERIFY);
  assert.deepEqual(compact, { alg: "HS256", payload, protectedHeader: { alg: "HS256" }, signatureIndex: 0 });
  assert.ok(!("unprotectedHeader" in compact));
  const json = await api.jwsVerifyJson({ payload: "" }, KEY, VERIFY);
  assert.deepEqual(json, { alg: "HS256", payload, unprotectedHeader: { kid: "1" }, signatureIndex: 2 });
});

test("JweDecrypted: headers parsed, bytes kept, absent members left out", async () => {
  const plaintext = new Uint8Array([7]);
  const aad = new Uint8Array([8]);
  const fake = fakeBackend({
    handlers: {
      jweDecryptCompact: () => ({ plaintext, header: '{"alg":"dir","enc":"A128GCM"}', protectedHeader: '{"alg":"dir","enc":"A128GCM"}', recipientIndex: 0 }),
      jweDecryptJson: () => ({
        plaintext,
        header: '{"alg":"A128KW"}',
        sharedUnprotectedHeader: '{"jku":"x"}',
        recipientHeader: '{"alg":"A128KW"}',
        aad,
        recipientIndex: 1,
      }),
    },
  });
  const api = createApi(fake.backend);
  const opts = { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] };
  assert.deepEqual(await api.jweDecryptCompact("t", KEY, opts), {
    plaintext,
    header: { alg: "dir", enc: "A128GCM" },
    protectedHeader: { alg: "dir", enc: "A128GCM" },
    recipientIndex: 0,
  });
  assert.deepEqual(await api.jweDecryptJson('{"ciphertext":""}', KEY, opts), {
    plaintext,
    header: { alg: "A128KW" },
    sharedUnprotectedHeader: { jku: "x" },
    recipientHeader: { alg: "A128KW" },
    aad,
    recipientIndex: 1,
  });
});

test("JwtVerified: claims and header parsed; keyIndex 0 kept, absent keyIndex left out", async () => {
  const fake = fakeBackend({
    handlers: {
      jwtVerify: () => ({ claims: '{"iss":"joe","exp":1300819380}', header: '{"alg":"HS256"}', alg: "HS256" }),
      jwtVerifyWithJwks: () => ({ claims: "{}", header: '{"alg":"HS256","kid":"a"}', alg: "HS256", keyIndex: 0, kid: "a" }),
      jwtDecryptNested: () => ({
        inner: { claims: '{"sub":"x"}', header: '{"alg":"HS256","cty":"JWT"}', alg: "HS256", keyIndex: null },
        outerHeader: '{"alg":"dir","enc":"A128GCM","cty":"JWT"}',
        recipientIndex: 0,
      }),
      jwtDecryptNestedWithJwks: () => ({
        inner: { claims: "{}", header: "{}", alg: "ES256", keyIndex: 3 },
        outerHeader: "{}",
        recipientIndex: 0,
      }),
    },
  });
  const api = createApi(fake.backend);
  const one = await api.jwtVerify("t", KEY, { ...VERIFY, now: 0 });
  assert.deepEqual(one, { claims: { iss: "joe", exp: 1300819380 }, header: { alg: "HS256" }, alg: "HS256" });
  assert.ok(!("keyIndex" in one) && !("kid" in one));
  const set = await api.jwtVerifyWithJwks("t", { keys: [] }, { ...VERIFY, now: 0 });
  assert.equal(set.keyIndex, 0);
  assert.equal(set.kid, "a");
  const dec = { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] };
  const nested = await api.jwtDecryptNested("t", KEY, dec, KEY, { ...VERIFY, now: 0 });
  assert.deepEqual(nested, {
    inner: { claims: { sub: "x" }, header: { alg: "HS256", cty: "JWT" }, alg: "HS256" },
    outerHeader: { alg: "dir", enc: "A128GCM", cty: "JWT" },
    recipientIndex: 0,
  });
  const nestedSet = await api.jwtDecryptNestedWithJwks("t", KEY, dec, '{"keys":[]}', { ...VERIFY, now: 0 });
  assert.equal(nestedSet.inner.keyIndex, 3);
});

test("a backend result of the wrong type is a TypeError, not a silent pass", async () => {
  const fake = fakeBackend({ handlers: { jwkParse: () => 42, jwkToDer: () => "not bytes", jwkToPublic: () => "[1]" } });
  const api = createApi(fake.backend);
  await assert.rejects(api.jwkParse(KEY), TypeError);
  await assert.rejects(api.jwkToDer(KEY, "spki"), TypeError);
  await assert.rejects(api.jwkToPublic(KEY), TypeError);
});

// --- errors ----------------------------------------------------------------------------

test("a thrown coded error becomes a PolyjoseError with the code and the backend message", async () => {
  const fake = fakeBackend({ handlers: { jwkParse: () => { throw coded("InvalidKey", "invalid JWK: bad member"); } } });
  const api = createApi(fake.backend);
  const err = await api.jwkParse(KEY).then(
    () => assert.fail("expected a rejection"),
    (e: unknown) => e,
  );
  assert.ok(err instanceof PolyjoseError);
  assert.ok(err instanceof Error);
  assert.equal(err.code, "InvalidKey");
  assert.equal(err.message, "invalid JWK: bad member");
  assert.equal(err.name, "PolyjoseError");
  assert.ok(!("cause" in err));
});

test("a rejected Promise with a coded error becomes a PolyjoseError too", async () => {
  const fake = fakeBackend({ handlers: { jwsVerifyCompact: () => Promise.reject(coded("InvalidSignature", "signature mismatch")) } });
  const api = createApi(fake.backend);
  await assert.rejects(api.jwsVerifyCompact("a.b.c", KEY, VERIFY), (e: unknown) => {
    assert.ok(e instanceof PolyjoseError);
    assert.equal(e.code, "InvalidSignature");
    assert.equal(e.message, "signature mismatch");
    return true;
  });
});

test("a plain coded object (wasm-bindgen style) maps the same way", async () => {
  const fake = fakeBackend({ handlers: { base64urlDecode: () => { throw { code: "InvalidBase64", message: "bad" }; } } });
  await assert.rejects(createApi(fake.backend).base64urlDecode("x"), (e: unknown) => e instanceof PolyjoseError && e.code === "InvalidBase64" && e.message === "bad");
});

test("every core code maps to PolyjoseError", async () => {
  for (const code of ERROR_CODES) {
    const fake = fakeBackend({ handlers: { jwkParse: () => { throw coded(code, code); } } });
    await assert.rejects(createApi(fake.backend).jwkParse(KEY), (e: unknown) => e instanceof PolyjoseError && e.code === code);
  }
});

test("jwksSelect: no match and several matches reject with their codes (ADR 0054 §4, §5)", async () => {
  for (const code of ["NoMatchingKey", "MultipleMatchingKeys"] as const) {
    const fake = fakeBackend({ handlers: { jwksSelect: () => { throw coded(code, "selection"); } } });
    const api = createApi(fake.backend);
    await assert.rejects(api.jwksSelect({ keys: [] }, { alg: "ES256" }), (e: unknown) => {
      assert.ok(e instanceof PolyjoseError);
      assert.equal(e.code, code);
      return true;
    });
    // The criteria reach the backend as given, with no name mapped (ADR 0054 §9).
    assert.deepEqual(fake.of("jwksSelect")[0]?.args, ['{"keys":[]}', { alg: "ES256" }]);
  }
  // A selected private key comes back as the backend wrote it, `d` included (ADR 0054 §3).
  const privateKey = '{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"c","kid":"1"}';
  const fake = fakeBackend({ handlers: { jwksSelect: () => privateKey } });
  assert.deepEqual(await createApi(fake.backend).jwksSelect(`{"keys":[${privateKey}]}`, { kid: "1" }), JSON.parse(privateKey));
});

test("a napi argument error (InvalidArg, StringExpected) becomes a TypeError with the original message", async () => {
  for (const [code, how] of [["InvalidArg", "sync"], ["StringExpected", "async"]] as const) {
    const message = `Failed to convert JavaScript value (${code})`;
    const fake = fakeBackend({
      handlers: { jwkParse: () => (how === "sync" ? (() => { throw coded(code, message); })() : Promise.reject(coded(code, message))) },
    });
    await assert.rejects(createApi(fake.backend).jwkParse(KEY), (e: unknown) => {
      assert.ok(e instanceof TypeError, `${code}: a TypeError`);
      assert.ok(!(e instanceof PolyjoseError));
      assert.equal(e.message, message);
      return true;
    });
  }
});

test("a code the backend's errorCodes() does not list is passed through unchanged, never a PolyjoseError", async () => {
  // 0013 F12: not a core failure the facade can vouch for, and not the caller's misuse either.
  const unlisted = coded("InvalidKey", "m");
  const fake = fakeBackend({
    errorCodes: ERROR_CODES.filter((c) => c !== "InvalidKey"),
    handlers: { jwkParse: () => { throw unlisted; } },
  });
  await assert.rejects(createApi(fake.backend).jwkParse(KEY), (e: unknown) => e === unlisted && !(e instanceof PolyjoseError));
});

test("a code the backend lists but ERROR_CODES does not (a newer backend) is passed through unchanged, never a PolyjoseError", async () => {
  // Review N2: `PolyjoseError.code` is always a member of the generated ErrorCode union.
  // 0013 F12: the backend's own error reaches the caller as is, not as a TypeError.
  for (const how of ["sync", "async"] as const) {
    const future = coded("FutureCode", "from the future");
    const fake = fakeBackend({
      errorCodes: [...ERROR_CODES, "FutureCode"],
      handlers: { jwkParse: () => (how === "sync" ? (() => { throw future; })() : Promise.reject(future)) },
    });
    await assert.rejects(createApi(fake.backend).jwkParse(KEY), (e: unknown) => {
      assert.equal(e, future, `${how}: the same object`);
      assert.ok(!(e instanceof PolyjoseError));
      assert.ok(!(e instanceof TypeError));
      return true;
    });
  }
});

test("a code in ERROR_CODES maps only if the backend lists it too, and then maps normally", async () => {
  const unlisted = coded("InvalidSignature", "s");
  const fake = fakeBackend({
    errorCodes: ["InvalidKey", "FutureCode"],
    handlers: { jwkParse: () => { throw coded("InvalidKey", "k"); }, jwkToPublic: () => { throw unlisted; } },
  });
  const api = createApi(fake.backend);
  await assert.rejects(api.jwkParse(KEY), (e: unknown) => e instanceof PolyjoseError && e.code === "InvalidKey" && e.message === "k");
  await assert.rejects(api.jwkToPublic(KEY), (e: unknown) => e === unlisted && !(e instanceof PolyjoseError));
});

test("a backend whose errorCodes() throws fails loudly, naming the cause, instead of turning core errors into TypeErrors", async () => {
  // Review N2: an empty code set would silently make every core failure a TypeError.
  const cause = new Error("errorCodes is broken");
  let listCalls = 0;
  let broken = true;
  const fake = fakeBackend({
    handlers: {
      errorCodes: () => {
        listCalls++;
        if (broken) throw cause;
        return [...ERROR_CODES];
      },
      jwkParse: () => { throw coded("InvalidKey", "invalid JWK"); },
    },
  });
  const api = createApi(fake.backend);
  for (let i = 0; i < 2; i++) {
    await assert.rejects(api.jwkParse(KEY), (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!(e instanceof TypeError), "not a TypeError: the facade is miswired, not the caller");
      assert.ok(!(e instanceof PolyjoseError));
      assert.match(e.message, /errorCodes\(\)/);
      assert.match(e.message, /errorCodes is broken/);
      assert.equal(e.cause, cause);
      return true;
    });
  }
  assert.equal(listCalls, 2, "a failed errorCodes() is not cached: the next failure asks again");
  // Once errorCodes() works, the same core failure is a PolyjoseError again.
  broken = false;
  await assert.rejects(api.jwkParse(KEY), (e: unknown) => e instanceof PolyjoseError && e.code === "InvalidKey");
});

test("a backend whose errorCodes() returns a non-array fails loudly too", async () => {
  for (const listed of ["InvalidKey", undefined, { 0: "InvalidKey", length: 1 }]) {
    const fake = fakeBackend({
      handlers: { errorCodes: () => listed, jwkParse: () => { throw coded("InvalidKey", "invalid JWK"); } },
    });
    await assert.rejects(createApi(fake.backend).jwkParse(KEY), (e: unknown) => {
      assert.ok(e instanceof Error && !(e instanceof TypeError) && !(e instanceof PolyjoseError), String(e));
      assert.match(e.message, /errorCodes\(\)/);
      return true;
    });
  }
});

test("errors without a core or argument code, and non-Error throws, are passed through unchanged", async () => {
  // 0013 F12: none of these says the caller misused the API, so none becomes a TypeError.
  const range = new RangeError("boom");
  const numeric = { code: 7, message: "numeric code" };
  const fake = fakeBackend({
    handlers: {
      jwkParse: () => { throw range; },
      jwkToPublic: () => { throw "a string"; },
      jwkThumbprint: () => Promise.reject(numeric),
    },
  });
  const api = createApi(fake.backend);
  await assert.rejects(api.jwkParse(KEY), (e: unknown) => e === range);
  await assert.rejects(api.jwkToPublic(KEY), (e: unknown) => e === "a string");
  await assert.rejects(api.jwkThumbprint(KEY, "SHA-256"), (e: unknown) => e === numeric);
});

// --- initialisation --------------------------------------------------------------------

test("ready() is awaited before the first call, and only once", async () => {
  const order: string[] = [];
  let release: () => void = () => {};
  let readyCalls = 0;
  const fake = fakeBackend({
    ready: () => {
      readyCalls += 1;
      order.push("ready:start");
      return new Promise<void>((resolve) => {
        release = () => {
          order.push("ready:done");
          resolve();
        };
      });
    },
    handlers: { jwkParse: () => { order.push("jwkParse"); return KEY; } },
  });
  const api = createApi(fake.backend);
  assert.equal(readyCalls, 0, "lazy: nothing happens at createApi");
  const first = api.jwkParse(KEY);
  const second = api.version();
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(fake.of("jwkParse").length, 0, "the first call waits for ready()");
  release();
  await first;
  await second;
  await api.jwkParse(KEY);
  assert.equal(readyCalls, 1, "later and concurrent calls don't re-initialise");
  assert.deepEqual(order.slice(0, 3), ["ready:start", "ready:done", "jwkParse"]);
});

test("a backend without ready() works", async () => {
  assert.equal(await createApi(fakeBackend().backend).version(), "0.1.2");
});

test("a failed ready() rejects the call unchanged, and the next call tries again", async () => {
  let attempts = 0;
  const failure = new Error("wasm fetch failed");
  const fake = fakeBackend({
    ready: () => {
      attempts += 1;
      return attempts === 1 ? Promise.reject(failure) : Promise.resolve();
    },
  });
  const api = createApi(fake.backend);
  await assert.rejects(api.version(), (e: unknown) => e === failure);
  assert.equal(await api.version(), "0.1.2");
  assert.equal(attempts, 2);
});
