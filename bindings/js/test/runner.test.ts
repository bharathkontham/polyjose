// The JS conformance runner (conformance/README.md "Rules for every runner", ADR 0034 results)
// over the fixture vectors, through the real facade and the toy backend.
import { assert, fs, path, process, test } from "../node/builtins.js";
import { createApi } from "../src/api.js";
import { runVectors, type VectorFile, type VectorResult } from "../conformance/runner.js";
import { coded, type Fake } from "./fake-backend.js";
import { toyBackend } from "./toy-backend.js";

const FIXTURES = path.resolve(process.cwd(), "test/fixtures/vectors");
const SCHEMA: unknown = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), "../../conformance/schema.json"), "utf8"));

function fixtureFiles(dir = FIXTURES): VectorFile[] {
  const out: VectorFile[] = [];
  const walk = (d: string): void => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".json")) out.push({ path: path.relative(dir, p).split(path.sep).join("/"), json: fs.readFileSync(p, "utf8") });
    }
  };
  walk(dir);
  return out.sort((a, b) => (a.path < b.path ? -1 : 1));
}

function fixture(name: string): VectorFile {
  const file = fixtureFiles().find((f) => f.path === name);
  assert.ok(file !== undefined, name);
  return file;
}

async function run(files: VectorFile[], fake: Fake = toyBackend(), features: string[] = []): Promise<VectorResult[]> {
  return runVectors(createApi(fake.backend), files, { schema: SCHEMA, features });
}

async function one(file: VectorFile, fake: Fake = toyBackend()): Promise<VectorResult> {
  const [result] = await run([file], fake);
  assert.ok(result !== undefined);
  return result;
}

/** A vector file from an object, with the fixture boilerplate. */
function vector(name: string, body: Record<string, unknown>): VectorFile {
  return { path: name, json: JSON.stringify({ source: "polyjose", description: "a runner test vector", ...body }) };
}

test("every fixture passes or is skipped by feature; ids, ops and actual follow ADR 0034", async () => {
  const files = fixtureFiles();
  const families = new Map<string, number>();
  for (const f of files) families.set(f.path.split("/")[0] ?? "", (families.get(f.path.split("/")[0] ?? "") ?? 0) + 1);
  for (const [family, n] of families) assert.ok(n >= 2, `${family}: at least two fixture vectors`);
  const results = await run(files);
  const failing = results.filter((r) => r.status === "fail");
  assert.deepEqual(failing, []);
  assert.equal(results.length, files.length);
  for (const [i, r] of results.entries()) {
    assert.equal(r.id, `${files[i]?.path}#0`);
    assert.equal(r.op, (JSON.parse(files[i]?.json ?? "{}") as { operation: string }).operation);
    if (r.status === "pass") {
      assert.ok(r.actual !== undefined && r.reason === undefined, r.id);
    }
  }
  const skipped = results.filter((r) => r.status === "skipped").map((r) => [r.id, r.reason, "actual" in r]);
  assert.deepEqual(skipped, [
    ["jwe/encrypt-compress.json#0", "feature:deflate", false],
    ["jwe/encrypt-fixed-rng.json#0", "feature:fixed-rng", false],
  ]);
  const actual = (id: string) => results.find((r) => r.id === id)?.actual;
  assert.deepEqual(actual("jws/verify-json-reject.json#0"), { ok: false, error: "InvalidSignature" });
  assert.deepEqual(actual("jws/verify-compact-limits.json#0"), { ok: true });
});

test("an enabled feature runs the vector instead of skipping it", async () => {
  const [result] = await run([fixture("jwe/encrypt-compress.json")], toyBackend(), ["deflate"]);
  assert.equal(result?.status, "pass");
  // The fixed-rng encryption isn't part of the binding API (ADR 0005): enabling it is a failure.
  const [rng] = await run([fixture("jwe/encrypt-fixed-rng.json")], toyBackend(), ["fixed-rng"]);
  assert.equal(rng?.status, "fail");
});

test("jwk.thumbprint passes the vector's hash to the facade unchanged, with no name table", async () => {
  // ADR 0054 §8.2, §9: the core parses the name, so the IANA name reaches the backend as written.
  const fake = toyBackend();
  assert.equal((await one(fixture("jwk-thumbprint/oct.json"), fake)).status, "pass");
  assert.deepEqual(fake.of("jwkThumbprint")[0]?.args[1], "sha-256");
  assert.deepEqual(fake.of("jwkThumbprintUri")[0]?.args[1], "sha-256");
});

test("jwk.thumbprint passes an absent hash as undefined, and a refused name is the outcome", async () => {
  // ADR 0054 §9: no name is supplied for an absent hash; ADR 0057 §2: the key error comes first.
  const fake = toyBackend();
  const absent = vector("jwk-thumbprint/absent.json", {
    operation: "jwk.thumbprint",
    input: { jwk: { kty: "oct", k: "AA" } },
    expect: { ok: true, thumbprint: "tp-oct", thumbprint_uri: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:tp-oct" },
  });
  assert.equal((await one(absent, fake)).status, "pass");
  assert.equal(fake.of("jwkThumbprint")[0]?.args.length, 2);
  assert.equal(fake.of("jwkThumbprint")[0]?.args[1], undefined);
  const both = vector("jwk-thumbprint/both.json", {
    operation: "jwk.thumbprint",
    input: { jwk: { k: "AA" }, hash: "SHA-1" },
    expect: { ok: false, error: "InvalidKey" },
  });
  assert.equal((await one(both)).status, "pass");
});

test("jwks.select maps the selector member by member and passes the set as its own text", async () => {
  // README jwks.select: kid, alg, key_use as given (key_use → keyUse), absent members unset; the
  // set's text in file order; the selected key compared as a JSON value.
  const fake = toyBackend();
  const picked = await one(fixture("jwks-select/select-kid.json"), fake);
  assert.equal(picked.status, "pass");
  const [set, sel] = fake.of("jwksSelect")[0]?.args ?? [];
  assert.equal(set, '{"keys":[{"kty":"oct","k":"c2VjcmV0LWtleS1ieXRlcw","kid":"a"},{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"b"}]}');
  assert.deepEqual(sel, { kid: "b", alg: "EdDSA", keyUse: "sig" });
  const empty = toyBackend();
  const several = await one(fixture("jwks-select/multiple-empty-selector.json"), empty);
  assert.deepEqual(several.actual, { ok: false, error: "MultipleMatchingKeys" });
  assert.deepEqual(empty.of("jwksSelect")[0]?.args[1], {});
  // A wrong key back is a failed vector, not a pass.
  const wrong = await one(fixture("jwks-select/select-kid.json"), toyBackend({ jwksSelect: () => '{"kty":"oct","k":"AA"}' }));
  assert.equal(wrong.status, "fail");
  // The runner never pre-validates a name: a refused key_use is the library's outcome.
  assert.deepEqual((await one(fixture("jwks-select/unsupported-key-use.json"))).actual, { ok: false, error: "UnsupportedAlgorithm" });
});

// --- 0004 T10-r1 implementer notes, ADR 0045 ----------------------------------------------

test("jwt.issue passes claims as the vector's own text, so integer-like members keep their order", async () => {
  const fake = toyBackend();
  assert.equal((await one(fixture("jwt/issue-typ-null-exact.json"), fake)).status, "pass");
  assert.equal(fake.of("jwtSign")[0]?.args[0], '{"iss":"joe","1":"one","exp":1300819380}');
});

test("jwt.issue: typ null omits typ, a typ string sets it, an absent typ sets nothing", async () => {
  const fake = toyBackend();
  await run([fixture("jwt/issue-typ-null-exact.json"), fixture("jwt/issue-roundtrip.json"), fixture("jwt/issue-encrypted.json")], fake);
  assert.deepEqual(
    fake.of("jwtSign").map((c) => c.args[2]),
    [{ alg: "HS256", omitTyp: true }, { alg: "HS256", typ: "at+jwt" }, { alg: "HS256" }],
  );
});

test("jwt.issue {ok:true}: shape check, then a round trip validating alg and claims", async () => {
  const passing = await one(fixture("jwt/issue-roundtrip.json"));
  assert.equal(passing.status, "pass");
  assert.deepEqual(passing.actual, { ok: true });
  // Two compact parts instead of three fails the vector.
  const short = await one(fixture("jwt/issue-roundtrip.json"), toyBackend({ jwtSign: () => "a.b" }));
  assert.equal(short.status, "fail");
  // A nested JWT must have five parts.
  const nested = await one(fixture("jwt/issue-encrypted.json"), toyBackend({ jwtEncryptNested: () => "a.b.c" }));
  assert.equal(nested.status, "fail");
  // Claims that don't come back equal fail it.
  const wrongClaims = await one(
    fixture("jwt/issue-roundtrip.json"),
    toyBackend({ jwtVerify: () => ({ claims: '{"sub":"y","exp":1300819380}', header: "{}", alg: "HS256" }) }),
  );
  assert.equal(wrongClaims.status, "fail");
  // Another alg coming back fails it.
  const wrongAlg = await one(
    fixture("jwt/issue-roundtrip.json"),
    toyBackend({ jwtVerify: () => ({ claims: '{"sub":"x","exp":1300819380}', header: "{}", alg: "HS384" }) }),
  );
  assert.equal(wrongAlg.status, "fail");
  // A validate the library refuses fails the vector, it is not an outcome.
  const refused = await one(fixture("jwt/issue-roundtrip.json"), toyBackend({ jwtVerify: () => { throw coded("InvalidSignature", "x"); } }));
  assert.equal(refused.status, "fail");
  assert.equal(refused.actual, undefined);
});

test("jwt.issue makes exactly the README calls: jwtSign, then jwtEncryptNested, no jwkParse pre-check (B02)", async () => {
  const fake = toyBackend();
  assert.equal((await one(fixture("jwt/issue-encrypted.json"), fake)).status, "pass");
  assert.deepEqual(
    fake.calls.filter((c) => c.op !== "errorCodes").map((c) => c.op),
    ["jwtSign", "jwtEncryptNested"],
  );
  const signed = toyBackend();
  await one(fixture("jwt/issue-typ-null-exact.json"), signed);
  assert.deepEqual(signed.calls.filter((c) => c.op !== "errorCodes").map((c) => c.op), ["jwtSign"]);
  // An encrypt.key the library refuses is the outcome of jwtEncryptNested, after jwtSign.
  const badEncKey = toyBackend({ jwtEncryptNested: () => { throw coded("InvalidKey", "k"); } });
  const result = await one(fixture("jwt/issue-encrypted.json"), badEncKey);
  assert.equal(result.status, "fail", "the expectation is ok:true, so an import error fails it");
  assert.deepEqual(result.actual, { ok: false, error: "InvalidKey" });
  assert.deepEqual(badEncKey.calls.filter((c) => c.op !== "errorCodes").map((c) => c.op), ["jwtSign", "jwtEncryptNested"]);
});

test("key_index 0 is a real index: kept, compared, and not dropped as falsy", async () => {
  assert.equal((await one(fixture("jwt/validate-jwks-index-0.json"))).status, "pass");
  assert.equal((await one(fixture("jwt/validate-jwks-index-1.json"))).status, "pass");
  const dropped = await one(
    fixture("jwt/validate-jwks-index-0.json"),
    toyBackend({ jwtVerifyWithJwks: () => ({ claims: '{"iss":"joe","exp":1300819380}', header: "{}", alg: "HS256" }) }),
  );
  assert.equal(dropped.status, "fail");
  // A key_index for a single-key vector is an output the expectation leaves out: fail.
  const extra = await one(
    fixture("jwt/validate-expired-false-members.json"),
    toyBackend({ jwtVerify: () => ({ claims: "{}", header: "{}", alg: "HS256", keyIndex: 0 }) }),
  );
  assert.equal(extra.status, "fail");
});

test("claims numbers compare as doubles (1300819380.0 equals 1300819380)", async () => {
  const fake = toyBackend();
  const result = await one(fixture("jwt/validate-jwks-index-0.json"), fake);
  assert.equal(result.status, "pass");
  assert.match(String(fake.of("jwtVerifyWithJwks")[0]?.args[0]), /\./);
});

test("policy: false booleans and typ default call nothing; every other member maps once", async () => {
  const fake = toyBackend();
  assert.equal((await one(fixture("jwt/validate-expired-false-members.json"), fake)).status, "pass");
  assert.deepEqual(fake.of("jwtVerify")[0]?.args[2], {
    allowedAlgs: ["HS256"],
    now: 1300819000,
    issuers: ["joe"],
    audiences: ["aud"],
    subject: "s",
    leeway: 30,
    maxAge: 60,
    requiredClaims: ["jti"],
    maxKeyCandidates: 2,
  });
  const nested = toyBackend();
  assert.equal((await one(fixture("jwt/validate-nested.json"), nested)).status, "pass");
  const call = nested.of("jwtDecryptNested")[0];
  assert.deepEqual(call?.args[2], { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"], maxPbes2Count: 5000 });
  assert.deepEqual(call?.args[4], {
    allowedAlgs: ["HS256"],
    now: 1300819000,
    issuers: ["joe", "ann"],
    audiences: ["aud"],
    typ: "at+jwt",
    profile: "access_token",
  });
  // typ any.
  const any = toyBackend();
  await one(fixture("jwt/issue-roundtrip.json"), any);
  assert.deepEqual(any.of("jwtVerify")[0]?.args[2], { allowedAlgs: ["HS256"], now: 1300819000, anyTyp: true });
});

test("policy typ mode default with profile access_token is a broken vector", async () => {
  const body = JSON.parse(fixture("jwt/validate-nested.json").json) as { input: { policy: Record<string, unknown> } };
  body.input.policy["typ"] = { mode: "default" };
  const result = await one({ path: "jwt/broken.json", json: JSON.stringify(body) });
  assert.equal(result.status, "fail");
  assert.match(result.reason ?? "", /contradicts/);
});

test("the runner never reads the clock: now always comes from the vector", async () => {
  const real = Date.now;
  Date.now = () => assert.fail("the runner must not read the wall clock (ADR 0028 §4)");
  try {
    const results = await run(fixtureFiles().filter((f) => f.path.startsWith("jwt/")));
    assert.deepEqual(results.filter((r) => r.status === "fail"), []);
  } finally {
    Date.now = real;
  }
});

test("jws.sign: a signer with only an unprotected header is run, never skipped (ADR 0045 §1)", async () => {
  const fake = toyBackend();
  assert.equal((await one(fixture("jws/sign-general-unprotected-only.json"), fake)).status, "pass");
  assert.deepEqual(fake.of("jwsSignGeneral")[0]?.args.slice(1), [[{ key: '{"kty":"oct","k":"c2VjcmV0LWtleS1ieXRlcw"}', unprotectedHeader: '{"alg":"HS256","kid":"u"}' }], false]);
});

test("jws.sign round trip: shape, verify with verify_with and the detached payload", async () => {
  const fake = toyBackend();
  assert.equal((await one(fixture("jws/sign-flattened-roundtrip.json"), fake)).status, "pass");
  const verify = fake.of("jwsVerifyJson")[0];
  assert.deepEqual((verify?.args[2] as { allowedAlgs: string[] }).allowedAlgs, ["ES256"]);
  assert.ok((verify?.args[2] as { detachedPayload?: Uint8Array }).detachedPayload instanceof Uint8Array);
  // A general-shaped output for a flattened request fails the shape check.
  const wrongShape = await one(fixture("jws/sign-flattened-roundtrip.json"), toyBackend({ jwsSignFlattened: () => '{"signatures":[]}' }));
  assert.equal(wrongShape.status, "fail");
});

test("jwe.encrypt maps every member, and checks the round trip", async () => {
  const fake = toyBackend();
  assert.equal((await one(fixture("jwe/encrypt-general-roundtrip.json"), fake)).status, "pass");
  const [plaintext, options, form] = fake.of("jweEncryptJson")[0]?.args ?? [];
  assert.equal(form, "general");
  assert.ok(plaintext instanceof Uint8Array);
  const o = options as Record<string, unknown>;
  assert.equal(o["enc"], "A128GCM");
  assert.equal(o["protectedHeader"], '{"cty":"text/plain"}');
  assert.equal(o["sharedUnprotectedHeader"], '{"jku":"https://example.com/keys"}');
  assert.ok(o["aad"] instanceof Uint8Array);
  assert.ok(!("compress" in o), "compress false or absent is never passed");
  const [r1, r2] = o["recipients"] as Record<string, unknown>[];
  assert.deepEqual(r1, { alg: "A128KW", key: '{"kty":"oct","k":"c2VjcmV0LWtleS1ieXRlcw"}', header: '{"kid":"r1"}' });
  assert.deepEqual(Object.keys(r2 ?? {}).sort(), ["alg", "apu", "key", "p2c", "p2sLen"]);
  // A plaintext that does not come back fails the vector.
  const lost = await one(
    fixture("jwe/encrypt-general-roundtrip.json"),
    toyBackend({ jweDecryptJson: () => ({ plaintext: new Uint8Array([1]), header: "{}", recipientIndex: 0 }) }),
  );
  assert.equal(lost.status, "fail");
});

test("jwe.decrypt passes every limit and understood_crit", async () => {
  const fake = toyBackend();
  assert.equal((await one(fixture("jwe/decrypt-compact.json"), fake)).status, "pass");
  assert.deepEqual(fake.of("jweDecryptCompact")[0]?.args[2], {
    allowedAlgs: ["A128KW"],
    allowedEnc: ["A128GCM"],
    understoodCrit: ["exp"],
    maxInputLen: 1000,
    maxRecipients: 1,
    maxPbes2Count: 10000,
    maxDecompressedLen: 250000,
  });
});

test("keys: a PEM or DER import that returns an oct key fails, whatever the vector expects", async () => {
  const oct = await one(fixture("keys/import-pem.json"), toyBackend({ jwkFromPem: () => '{"kty":"oct","k":"AA"}' }));
  assert.equal(oct.status, "fail");
  assert.match(oct.reason ?? "", /oct/);
});

test("keys.generate_for checks the key is private, has exactly the RFC members, and imports back", async () => {
  const pub = await one(fixture("keys/generate-for-a128kw.json"), toyBackend({ jwkGenerateForAlg: () => '{"kty":"oct","k":"MDEyMzQ1Njc4OWFiY2RlZg","alg":"A128KW","kid":"x"}' }));
  assert.equal(pub.status, "fail", "an extra member");
  const reimport = await one(fixture("keys/generate-for-a128kw.json"), toyBackend({ jwkParse: () => '{"kty":"oct","k":"AA","alg":"A128KW"}' }));
  assert.equal(reimport.status, "fail", "imports as another key");
  const ec = await one(fixture("keys/generate-for-a128kw.json"), toyBackend({ jwkGenerateForAlg: () => '{"kty":"EC","crv":"P-256","x":"a","y":"b","alg":"A128KW"}' }));
  assert.equal(ec.status, "fail", "an EC key without d is public");
});

test("keys.generate_oct/_ec/_okp map to jwkGenerateOct/Ec/Okp; shape without alg; use_with round trip (ADR 0034 §6)", async () => {
  const fake = toyBackend();
  const results = await run([fixture("keys/generate-oct.json"), fixture("keys/generate-ec.json"), fixture("keys/generate-okp.json")], fake);
  assert.deepEqual(results.map((r) => [r.status, r.actual]), [
    ["pass", { ok: true }],
    ["pass", { ok: true }],
    ["pass", { ok: true }],
  ]);
  assert.deepEqual(fake.of("jwkGenerateOct").map((c) => c.args), [[16]]);
  assert.deepEqual(fake.of("jwkGenerateEc").map((c) => c.args), [["P-256"]]);
  assert.deepEqual(fake.of("jwkGenerateOkp").map((c) => c.args), [["X25519"]]);
  // The other side is the public key for EC and OKP, the key itself for oct (RFC 7518 §6.4).
  assert.equal(fake.of("jwkToPublic").length, 2);
  // EC: a JWS signed with the key under {"alg":"ES256"}, verified with allow-list [ES256].
  const [sign] = fake.of("jwsSignCompact");
  assert.deepEqual(sign?.args.slice(2), [{ protectedHeader: '{"alg":"ES256"}' }]);
  assert.deepEqual((fake.of("jwsVerifyCompact")[0]?.args[2] as { allowedAlgs: string[] }).allowedAlgs, ["ES256"]);
  // A refusal of the core is the outcome; ec and okp cannot fail (schema).
  assert.deepEqual((await one(fixture("keys/generate-oct-reject.json"))).actual, { ok: false, error: "InvalidKey" });
});

test("use_with: a failing round trip, an alg in the shape, or a missing use_with fails the vector", async () => {
  const ec = fixture("keys/generate-ec.json");
  const unverified = await one(ec, toyBackend({ jwsVerifyCompact: () => { throw coded("InvalidSignature", "x"); } }));
  assert.equal(unverified.status, "fail");
  assert.equal(unverified.actual, undefined, "a runner check inside the operation leaves no actual");
  assert.match(unverified.reason ?? "", /use_with: the signature does not verify/);
  const bound = await one(ec, toyBackend({ jwkGenerateEc: () => '{"kty":"EC","crv":"P-256","x":"eA","y":"eQ","d":"ZA","alg":"ES256"}' }));
  assert.equal(bound.status, "fail", "a generator key has no alg");
  const okp = fixture("keys/generate-okp.json");
  const undecrypted = await one(okp, toyBackend({ jweDecryptCompact: () => { throw coded("DecryptionFailed", "x"); } }));
  assert.equal(undecrypted.status, "fail");
  assert.match(undecrypted.reason ?? "", /use_with: the key does not decrypt/);
  const body = JSON.parse(ec.json) as { expect: Record<string, unknown> };
  delete body.expect["use_with"];
  assert.equal((await one({ path: "keys/no-use-with.json", json: JSON.stringify(body) })).status, "fail", "use_with is required");
  // keys.generate_for takes an optional use_with, checked the same way.
  const forAlg = JSON.parse(fixture("keys/generate-for-a128kw.json").json) as { expect: Record<string, unknown> };
  forAlg.expect["use_with"] = { alg: "A128KW", enc: "A128GCM" };
  const fake = toyBackend();
  assert.equal((await one({ path: "keys/for-use-with.json", json: JSON.stringify(forAlg) }, fake)).status, "pass");
  assert.equal(fake.of("jweEncryptCompact").length, 1);
  assert.equal(fake.of("jwkToPublic").length, 0, "oct: the key itself");
});

test("features_absent: runs without the feature, skipped as feature:!<name> with it (ADR 0056)", async () => {
  const compress = JSON.parse(fixture("jwe/encrypt-compress.json").json) as Record<string, unknown>;
  delete compress["features"];
  const absent = (extra: Record<string, unknown>): VectorFile =>
    ({ path: "jwe/compress-absent.json", json: JSON.stringify({ ...compress, expect: { ok: false, error: "UnsupportedAlgorithm" }, ...extra }) });
  const noDeflate = toyBackend({ jweEncryptCompact: () => { throw coded("UnsupportedAlgorithm", "no deflate"); } });
  const [ran] = await run([absent({ features_absent: ["deflate"] })], noDeflate);
  assert.deepEqual([ran?.status, ran?.actual], ["pass", { ok: false, error: "UnsupportedAlgorithm" }]);
  const [skipped] = await run([absent({ features_absent: ["deflate"] })], toyBackend(), ["deflate"]);
  assert.deepEqual([skipped?.status, skipped?.reason, skipped !== undefined && "actual" in skipped], ["skipped", "feature:!deflate", false]);
  // Missing features first, then the enabled absent ones, each in the vector's order.
  const [mixed] = await run([absent({ features: ["fixed-rng"], features_absent: ["deflate"] })], toyBackend(), ["deflate"]);
  assert.equal(mixed?.reason, "feature:fixed-rng,!deflate");
  const [both] = await run([absent({ features_absent: ["fixed-rng", "deflate"] })], toyBackend(), ["deflate", "fixed-rng"]);
  assert.equal(both?.reason, "feature:!fixed-rng,!deflate");
});

test("features_absent is strict: known names, once each, non-empty, not also in features; compress needs deflate in a list", async () => {
  const decode = { operation: "b64url.decode", input: { b64u: "AQI" }, expect: { ok: true, bytes_hex: "0102" } };
  for (const [extra, needle] of [
    [{ features_absent: ["zip"] }, /features_absent/],
    [{ features_absent: ["deflate", "deflate"] }, /features_absent/],
    [{ features_absent: [] }, /features_absent/],
    [{ features_absent: "deflate" }, /features_absent/],
    [{ features: ["deflate"], features_absent: ["deflate"] }, /"deflate" is listed in `features` too/],
    [{ feature_absent: ["deflate"] }, /feature_absent/],
  ] as const) {
    const [result] = await run([vector("t/absent.json", { ...decode, ...extra })], toyBackend(), ["deflate"]);
    assert.equal(result?.status, "fail", JSON.stringify(extra));
    assert.match(result?.reason ?? "", needle);
  }
  const compress = JSON.parse(fixture("jwe/encrypt-compress.json").json) as Record<string, unknown>;
  const [onlyRng] = await run([{ path: "jwe/x.json", json: JSON.stringify({ ...compress, features: undefined, features_absent: ["fixed-rng"] }) }]);
  assert.equal(onlyRng?.status, "fail");
  assert.match(onlyRng?.reason ?? "", /needs "deflate" listed in `features` or `features_absent`/);
});

// --- errors and harness rules --------------------------------------------------------------

test("library errors are compared by code; a wrong code fails with the observed actual", async () => {
  const wrong = await one(fixture("jws/verify-json-reject.json"), toyBackend({ jwsVerifyJson: () => { throw coded("InvalidKey", "k"); } }));
  assert.equal(wrong.status, "fail");
  assert.deepEqual(wrong.actual, { ok: false, error: "InvalidKey" });
  const succeeded = await one(fixture("jws/verify-json-reject.json"), toyBackend({ jwsVerifyJson: () => ({ alg: "HS256", payload: new Uint8Array(), signatureIndex: 0 }) }));
  assert.equal(succeeded.status, "fail");
  assert.deepEqual(succeeded.actual, { ok: true });
});

test("a non-PolyjoseError (napi InvalidArg, a TypeError) is a harness failure, never an outcome", async () => {
  const napi = await one(fixture("jws/verify-json-reject.json"), toyBackend({ jwsVerifyJson: () => { throw coded("InvalidArg", "Failed to convert"); } }));
  assert.equal(napi.status, "fail");
  assert.equal(napi.actual, undefined);
  assert.match(napi.reason ?? "", /Failed to convert/);
});

test("a vector whose JWS payload isn't canonical base64url is broken, not an outcome", async () => {
  const body = JSON.parse(fixture("jws/verify-detached.json").json) as { input: Record<string, unknown> };
  body.input["detached_payload_b64u"] = "cGF5bG9hZA_";
  const result = await one({ path: "jws/x.json", json: JSON.stringify(body) });
  assert.equal(result.status, "fail");
  assert.match(result.reason ?? "", /canonical base64url/);
});

test("schema-invalid, duplicate-member and unparseable files fail, naming the file and source", async () => {
  const typo = vector("t/typo.json", { operation: "b64url.encode", input: { bytes_hex: "66", extra: 1 }, expect: { ok: true, b64u: "Zg" } });
  const dup = { path: "t/dup.json", json: '{"source":"polyjose","description":"d","operation":"b64url.encode","input":{"bytes_hex":"66","bytes_hex":"67"},"expect":{"ok":true,"b64u":"Zg"}}' };
  const garbage = { path: "t/garbage.json", json: "{" };
  const notObject = { path: "t/array.json", json: "[]" };
  const results = await run([typo, dup, garbage, notObject]);
  assert.deepEqual(results.map((r) => r.status), ["fail", "fail", "fail", "fail"]);
  assert.match(results[0]?.reason ?? "", /^t\/typo\.json \(source: polyjose\): \/input\/extra/);
  assert.match(results[1]?.reason ?? "", /duplicate member "bytes_hex"/);
  assert.equal(results[2]?.op, "unknown");
});

test("an unknown operation fails, never skips", async () => {
  const result = await one(vector("t/op.json", { operation: "jws.frobnicate", input: {}, expect: { ok: true } }));
  assert.equal(result.status, "fail");
  assert.equal(result.op, "jws.frobnicate");
});

test("a skipped vector is still schema-checked, and fails when invalid", async () => {
  const body = JSON.parse(fixture("jwe/encrypt-compress.json").json) as { input: Record<string, unknown> };
  body.input["typo"] = true;
  assert.equal((await one({ path: "jwe/bad.json", json: JSON.stringify(body) })).status, "fail");
  // rng_b64u without features: ["fixed-rng"] is invalid (README Features), not run.
  const undeclared = JSON.parse(fixture("jwe/encrypt-fixed-rng.json").json) as Record<string, unknown>;
  delete undeclared["features"];
  assert.equal((await one({ path: "jwe/undeclared.json", json: JSON.stringify(undeclared) })).status, "fail");
});

test("jwt.issue cross-member rules: no exact token with encrypt, validate required for {ok:true}", async () => {
  const exactEncrypted = JSON.parse(fixture("jwt/issue-encrypted.json").json) as Record<string, unknown>;
  exactEncrypted["expect"] = { ok: true, token: "a.b.c.d.e" };
  const noValidate = JSON.parse(fixture("jwt/issue-roundtrip.json").json) as { input: Record<string, unknown> };
  delete noValidate.input["validate"];
  const failureWithValidate = JSON.parse(fixture("jwt/issue-roundtrip.json").json) as Record<string, unknown>;
  failureWithValidate["expect"] = { ok: false, error: "InvalidKey" };
  const results = await run([
    { path: "a.json", json: JSON.stringify(exactEncrypted) },
    { path: "b.json", json: JSON.stringify(noValidate) },
    { path: "c.json", json: JSON.stringify(failureWithValidate) },
  ]);
  assert.deepEqual(results.map((r) => r.status), ["fail", "fail", "fail"]);
});

test("a schema option is required, and its absence fails every vector loudly", async () => {
  const results = await runVectors(createApi(toyBackend().backend), [fixture("b64url/encode.json")], {} as never);
  assert.equal(results[0]?.status, "fail");
});

test("the runner, schema check and scanner import nothing Node-only (they also run in browsers)", () => {
  for (const file of ["conformance/runner.ts", "conformance/schema.ts", "conformance/json-text.ts", "conformance/own.ts"]) {
    const source = fs.readFileSync(path.resolve(process.cwd(), file), "utf8");
    const imports = [...source.matchAll(/^\s*import[^;]*?from\s+"([^"]+)"/gm)].map((m) => m[1] ?? "");
    for (const spec of imports) {
      assert.ok(!spec.startsWith("node:") && !spec.includes("/node/") && spec.startsWith("."), `${file} imports ${spec}`);
    }
    assert.doesNotMatch(source, /\bprocess\.|\brequire\(|getBuiltinModule/, file);
  }
});
