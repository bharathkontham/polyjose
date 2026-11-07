// The raw napi backend of @polyjose/node, below the facade (`backend.js`, the typed `binding.cjs`;
// bindings/js/BACKEND.md), run with `node --test` against the compiled package (ADR 0047). The
// facade copies every byte input and builds fresh plain records before the backend is reached
// (0013 B06), so the public-API tests cannot see what the adapter itself does. These can:
//   - copy at call time (review-code.md SF-5 a): the adapter copies a caller's Buffer while the
//     call runs, so changing it before the task runs does not change what is signed;
//   - no input array returned (SF-5 b, BACKEND.md): every byte result is a fresh plain Uint8Array,
//     never an input array or a view of one;
//   - string records (SF-6): the JWT records resolve with every field, as strings;
//   - the records the adapter reads field by field (review-security.md L1): each field arrives;
//   - own data properties (0013 F09, BACKEND.md): every record a backend operation resolves with is
//     a plain or prototype-less object whose members are all own data properties, so the facade,
//     which reads own members only, reads every field;
//   - getter re-entrancy (L1): a getter that detaches and frees a byte argument during argument
//     conversion cannot make the adapter read freed memory. Run in a child process with
//     --expose-gc, so a crash fails the test instead of the runner.
// No assertion reads a clock (pipeline rule 8).
import { assert, path, test } from "../../js/dist/node/builtins.js";
import * as facade from "@polyjose/node";
import type { JwkObject } from "@polyjose/node";
import { backend } from "../backend.js";

interface SpawnResult {
  readonly status: number | null;
  readonly signal: string | null;
  readonly stdout: string;
  readonly stderr: string;
}
interface NodeChildProcess {
  spawnSync(
    file: string,
    args: readonly string[],
    options: { encoding: "utf8"; timeout: number; maxBuffer: number; cwd: string },
  ): SpawnResult;
}
interface NodeUrl {
  fileURLToPath(url: string): string;
  pathToFileURL(file: string): { readonly href: string };
}
interface Host {
  getBuiltinModule(id: "node:url"): NodeUrl;
  getBuiltinModule(id: "node:child_process"): NodeChildProcess;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly execPath: string;
}
interface NodeBuffer {
  from(text: string, encoding: "base64url"): Uint8Array;
  from(bytes: ArrayLike<number>): Uint8Array;
  isBuffer(value: unknown): boolean;
}
const host = (globalThis as unknown as { process: Host }).process;
const Buffer = (globalThis as unknown as { Buffer: NodeBuffer }).Buffer;
const url = host.getBuiltinModule("node:url");
const thisFile = url.fileURLToPath((import.meta as unknown as { url: string }).url);
/** bindings/node: this file is bindings/node/dist/backend.test.js. */
const pkgDir = path.resolve(path.dirname(thisFile), "..");

const ascii = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0));
/** Unpadded base64url (RFC 4648 §5), through Node's Buffer. */
const b64u = (bytes: Uint8Array): string =>
  (Buffer.from(bytes) as unknown as { toString(encoding: "base64url"): string }).toString("base64url");
const json = (s: string): Record<string, unknown> => JSON.parse(s) as Record<string, unknown>;
const text = (bytes: Uint8Array): string => String.fromCharCode(...bytes);

/** An HS256 key (RFC 7518 §3.2): 32 octets of 0x07. */
const hsKey = JSON.stringify({ kty: "oct", k: b64u(new Uint8Array(32).fill(7)), kid: "k1" });
/** A direct-encryption A128GCM key (RFC 7518 §4.5, §5.3): 16 octets of 0x09. */
const cek = JSON.stringify({ kty: "oct", k: b64u(new Uint8Array(16).fill(9)) });
const HS256 = '{"alg":"HS256"}';

/**
 * Asserts that `out` is a fresh plain Uint8Array with `input`'s contents: not `input`, not a view
 * of its ArrayBuffer, not a (pooled) Buffer, and that `input` still holds `expected`.
 */
function freshCopy(what: string, out: unknown, input: Uint8Array, expected: Uint8Array): void {
  assert.ok(out instanceof Uint8Array, `${what}: a Uint8Array`);
  assert.ok(!Buffer.isBuffer(out), `${what}: a plain Uint8Array, not a pooled Buffer`);
  assert.notEqual(out, input, `${what}: not the input array`);
  assert.notEqual(out.buffer, input.buffer, `${what}: not on the input's ArrayBuffer`);
  assert.deepEqual([...out], [...expected], `${what}: the input's bytes`);
  assert.deepEqual([...input], [...expected], `${what}: the input is unchanged`);
}

// --- Copy at call time (review-code.md SF-5 a; ADR 0030 §7.1, ADR 0031 §2) ------------------------

const PBES2 = "PBES2-HS256+A128KW";
const password = JSON.stringify({ kty: "oct", k: "cGotcGJlczItcGFzc3dvcmQ" });
/** The core's ceiling for `p2c` (ADR 0050 §2): the costliest PBES2 decrypt it allows. */
const P2C_CEILING = 1_000_000;

test("the adapter copies a byte argument at the call: filling the caller's Buffer while the task waits does not change what is signed", async () => {
  const costly = (await backend.jweEncryptCompact(ascii("busy"), {
    enc: "A128GCM",
    recipients: [{ alg: PBES2, key: password, p2c: P2C_CEILING }],
  })) as string;
  // Occupy every libuv pool thread first, so the signing task cannot start before the fill below.
  // An adapter that kept the borrowed bytes and read them in `compute` would sign the fill.
  const poolSize = Math.min(Math.max(Number(host.env["UV_THREADPOOL_SIZE"] ?? "4") || 4, 1), 1024);
  const busy = Array.from({ length: poolSize }, () =>
    backend.jweDecryptCompact(costly, password, {
      allowedAlgs: [PBES2],
      allowedEnc: ["A128GCM"],
      maxPbes2Count: P2C_CEILING,
    }),
  );

  const original = ascii("the caller's bytes when jwsSignCompact was called");
  const payload = Buffer.from(original);
  const signing = backend.jwsSignCompact(payload, hsKey, { protectedHeader: HS256 });
  payload.fill(0x58);
  const token = (await signing) as string;
  await Promise.all(busy);

  const verified = await backend.jwsVerifyCompact(token, hsKey, { allowedAlgs: ["HS256"] });
  assert.deepEqual([...verified.payload], [...original], "the bytes at call time are signed");
});

// --- No input array returned (SF-5 b; BACKEND.md, 0013 B06) --------------------------------------

test("jwsVerifyCompact returns a fresh payload, never the detachedPayload it was given", async () => {
  const bytes = ascii("a detached payload (RFC 7515 Appendix F)");
  const token = (await backend.jwsSignCompact(bytes, hsKey, { protectedHeader: HS256, detached: true })) as string;
  for (const [kind, dp] of [
    ["Uint8Array", bytes.slice()],
    ["Buffer", Buffer.from(bytes)],
  ] as const) {
    const out = await backend.jwsVerifyCompact(token, hsKey, { allowedAlgs: ["HS256"], detachedPayload: dp });
    freshCopy(`detachedPayload as ${kind}`, out.payload, dp, bytes);
  }
});

test("jweDecryptCompact and jweDecryptJson return fresh plaintext and aad, never the arrays given to encrypt", async () => {
  const plainBytes = ascii("plaintext (RFC 7516 §5.2)");
  const aadBytes = ascii("aad (RFC 7516 §5.1 step 14)");
  const plaintext = Buffer.from(plainBytes);
  const compact = (await backend.jweEncryptCompact(plaintext, {
    enc: "A128GCM",
    recipients: [{ alg: "dir", key: cek }],
  })) as string;
  const decrypted = await backend.jweDecryptCompact(compact, cek, { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] });
  freshCopy("compact plaintext", decrypted.plaintext, plaintext, plainBytes);

  const aad = Buffer.from(aadBytes);
  const flattened = (await backend.jweEncryptJson(
    plaintext,
    { enc: "A128GCM", recipients: [{ alg: "dir", key: cek }], aad },
    "flattened",
  )) as string;
  const fromJson = await backend.jweDecryptJson(flattened, cek, { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] });
  freshCopy("JSON plaintext", fromJson.plaintext, plaintext, plainBytes);
  assert.ok(fromJson.aad instanceof Uint8Array, "the aad is returned");
  freshCopy("JSON aad", fromJson.aad, aad, aadBytes);
  assert.notEqual(fromJson.plaintext.buffer, fromJson.aad.buffer, "plaintext and aad do not share memory");
});

test("base64urlDecode returns a fresh Uint8Array each time, never the encoded input", async () => {
  const bytes = Uint8Array.from({ length: 48 }, (_, i) => i);
  const input = Buffer.from(bytes);
  const encoded = (await backend.base64urlEncode(input)) as string;
  const first = await backend.base64urlDecode(encoded);
  const second = await backend.base64urlDecode(encoded);
  freshCopy("base64urlDecode", first, input, bytes);
  assert.notEqual(first.buffer, second.buffer, "two results never share an ArrayBuffer");
});

// --- String records (SF-6): every field arrives, as a string ---------------------------------------

test("the JWT records resolve with every field, strings as strings (jwtVerify, jwtVerifyWithJwks, jwtDecryptNested)", async () => {
  const now = 1_700_000_000;
  const claims = JSON.stringify({ sub: "a", exp: now + 60 });
  const signed = (await backend.jwtSign(claims, hsKey, { alg: "HS256" })) as string;
  const verify = { allowedAlgs: ["HS256"], now };

  const one = await backend.jwtVerify(signed, hsKey, verify);
  assert.equal(typeof one.claims, "string");
  assert.deepEqual(json(one.claims), { sub: "a", exp: now + 60 });
  assert.equal(typeof one.header, "string");
  assert.equal(json(one.header)["alg"], "HS256");
  assert.equal(one.alg, "HS256");
  assert.equal(one.kid, "k1", "the verifying key's kid (RFC 7517 §4.5)");
  assert.ok(one.keyIndex === undefined || one.keyIndex === null, "no set, no index");

  const set = JSON.stringify({ keys: [json(cek), json(hsKey)] });
  const fromSet = await backend.jwtVerifyWithJwks(signed, set, verify);
  assert.equal(fromSet.keyIndex, 1, "the JWK Set member that verified (ADR 0029)");
  assert.equal(fromSet.kid, "k1");

  const nested = (await backend.jwtEncryptNested(signed, {
    enc: "A128GCM",
    recipients: [{ alg: "dir", key: cek }],
  })) as string;
  const out = await backend.jwtDecryptNested(nested, cek, { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] }, hsKey, verify);
  assert.deepEqual(json(out.inner.claims), { sub: "a", exp: now + 60 });
  assert.equal(out.inner.alg, "HS256");
  assert.equal(typeof out.outerHeader, "string");
  assert.equal(json(out.outerHeader)["cty"], "JWT", "cty set by the core (RFC 7519 §5.2)");
  assert.equal(out.recipientIndex, 0);
});

// --- Own data properties (0013 F09; BACKEND.md "Results") ------------------------------------------

/**
 * Asserts that `record` is a plain (`Object.prototype`) or prototype-less object, that it has an
 * own member for each of `fields`, and that every own member is a data property (`value`, no
 * `get`/`set`). `nested` names the members that are records themselves, checked the same way.
 */
function ownDataRecord(
  what: string,
  record: unknown,
  fields: readonly string[],
  nested: Readonly<Record<string, readonly string[]>> = {},
): void {
  assert.equal(typeof record, "object", `${what}: an object`);
  assert.notEqual(record, null, `${what}: not null`);
  const proto = Object.getPrototypeOf(record) as unknown;
  assert.ok(proto === Object.prototype || proto === null, `${what}: a plain or prototype-less object`);
  const obj = record as Record<string, unknown>;
  for (const field of fields) {
    assert.ok(Object.hasOwn(obj, field), `${what}.${field} is an own member`);
  }
  for (const key of Reflect.ownKeys(obj)) {
    const d = Object.getOwnPropertyDescriptor(obj, key);
    const name = `${what}.${String(key)}`;
    assert.ok(d !== undefined && Object.hasOwn(d, "value"), `${name} is a data property`);
    assert.equal(d.get, undefined, `${name} has no getter`);
    assert.equal(d.set, undefined, `${name} has no setter`);
  }
  for (const [field, inner] of Object.entries(nested)) {
    ownDataRecord(`${what}.${field}`, obj[field], inner);
  }
}

const JWT_VERIFIED = ["claims", "header", "alg", "kid"] as const;

test("every record the raw backend resolves with is made of own data properties (jwsVerify*, jweDecrypt*, jwtVerify*, jwtDecryptNested*)", async () => {
  const payload = ascii("payload (RFC 7515 §5.2)");
  const compactJws = (await backend.jwsSignCompact(payload, hsKey, { protectedHeader: HS256 })) as string;
  ownDataRecord(
    "jwsVerifyCompact",
    await backend.jwsVerifyCompact(compactJws, hsKey, { allowedAlgs: ["HS256"] }),
    ["alg", "payload", "protectedHeader", "signatureIndex"],
  );
  const flattenedJws = (await backend.jwsSignFlattened(
    payload,
    { key: hsKey, protectedHeader: HS256, unprotectedHeader: '{"kid":"u"}' },
    false,
  )) as string;
  ownDataRecord(
    "jwsVerifyJson",
    await backend.jwsVerifyJson(flattenedJws, hsKey, { allowedAlgs: ["HS256"] }),
    ["alg", "payload", "protectedHeader", "unprotectedHeader", "signatureIndex"],
  );

  const plaintext = ascii("plaintext (RFC 7516 §5.2)");
  const decrypt = { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] };
  const compactJwe = (await backend.jweEncryptCompact(plaintext, {
    enc: "A128GCM",
    recipients: [{ alg: "dir", key: cek }],
  })) as string;
  ownDataRecord("jweDecryptCompact", await backend.jweDecryptCompact(compactJwe, cek, decrypt), [
    "plaintext",
    "header",
    "protectedHeader",
    "recipientIndex",
  ]);
  const generalJwe = (await backend.jweEncryptJson(
    plaintext,
    {
      enc: "A128GCM",
      protectedHeader: '{"cty":"text/plain"}',
      sharedUnprotectedHeader: '{"jku":"https://example.com/s"}',
      aad: ascii("aad"),
      recipients: [{ alg: "dir", key: cek, header: '{"kid":"r"}' }],
    },
    "general",
  )) as string;
  ownDataRecord("jweDecryptJson", await backend.jweDecryptJson(generalJwe, cek, decrypt), [
    "plaintext",
    "header",
    "protectedHeader",
    "sharedUnprotectedHeader",
    "recipientHeader",
    "aad",
    "recipientIndex",
  ]);

  const now = 1_700_000_000;
  const signed = (await backend.jwtSign(JSON.stringify({ sub: "a", exp: now + 60 }), hsKey, { alg: "HS256" })) as string;
  const verify = { allowedAlgs: ["HS256"], now };
  const set = JSON.stringify({ keys: [json(cek), json(hsKey)] });
  ownDataRecord("jwtVerify", await backend.jwtVerify(signed, hsKey, verify), JWT_VERIFIED);
  ownDataRecord("jwtVerifyWithJwks", await backend.jwtVerifyWithJwks(signed, set, verify), [...JWT_VERIFIED, "keyIndex"]);

  const nested = (await backend.jwtEncryptNested(signed, { enc: "A128GCM", recipients: [{ alg: "dir", key: cek }] })) as string;
  ownDataRecord(
    "jwtDecryptNested",
    await backend.jwtDecryptNested(nested, cek, decrypt, hsKey, verify),
    ["inner", "outerHeader", "recipientIndex"],
    { inner: JWT_VERIFIED },
  );
  ownDataRecord(
    "jwtDecryptNestedWithJwks",
    await backend.jwtDecryptNestedWithJwks(nested, cek, decrypt, set, verify),
    ["inner", "outerHeader", "recipientIndex"],
    { inner: [...JWT_VERIFIED, "keyIndex"] },
  );
});

test("the facade reads every field of those records (it reads own members only, 0013 F09)", async () => {
  const hsJwk = json(hsKey) as JwkObject;
  const cekJwk = json(cek) as JwkObject;
  const payload = ascii("payload (RFC 7515 §5.2)");
  const flattenedJws = await facade.jwsSignFlattened(
    payload,
    { key: hsJwk, protectedHeader: { alg: "HS256" }, unprotectedHeader: { kid: "u" } },
    false,
  );
  const jws = await facade.jwsVerifyJson(flattenedJws, hsJwk, { allowedAlgs: ["HS256"] });
  assert.equal(jws.alg, "HS256");
  assert.deepEqual([...jws.payload], [...payload]);
  assert.deepEqual(jws.protectedHeader, { alg: "HS256" });
  assert.deepEqual(jws.unprotectedHeader, { kid: "u" });
  assert.equal(jws.signatureIndex, 0);

  const plaintext = ascii("plaintext (RFC 7516 §5.2)");
  const decrypt = { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] };
  const generalJwe = await facade.jweEncryptJson(
    plaintext,
    {
      enc: "A128GCM",
      protectedHeader: { cty: "text/plain" },
      sharedUnprotectedHeader: { jku: "https://example.com/s" },
      aad: ascii("aad"),
      recipients: [{ alg: "dir", key: cekJwk, header: { kid: "r" } }],
    },
    "general",
  );
  const jwe = await facade.jweDecryptJson(generalJwe, cekJwk, decrypt);
  assert.deepEqual([...jwe.plaintext], [...plaintext]);
  assert.equal(jwe.header["kid"], "r", "the union header (RFC 7516 §5.2 step 4)");
  assert.equal(jwe.protectedHeader?.["cty"], "text/plain");
  assert.equal(jwe.protectedHeader?.["enc"], "A128GCM");
  assert.deepEqual(jwe.sharedUnprotectedHeader, { jku: "https://example.com/s" });
  assert.equal(jwe.recipientHeader?.["kid"], "r");
  assert.deepEqual([...(jwe.aad ?? [])], [...ascii("aad")]);
  assert.equal(jwe.recipientIndex, 0);

  const now = 1_700_000_000;
  const claims = { sub: "a", exp: now + 60 };
  const signed = await facade.jwtSign(claims, hsJwk, { alg: "HS256" });
  const verify = { allowedAlgs: ["HS256"], now };
  const set = { keys: [cekJwk, hsJwk] };
  const one = await facade.jwtVerifyWithJwks(signed, set, verify);
  assert.deepEqual(one.claims, claims);
  assert.equal(one.header["alg"], "HS256");
  assert.equal(one.alg, "HS256");
  assert.equal(one.keyIndex, 1);
  assert.equal(one.kid, "k1");
  const nested = await facade.jwtEncryptNested(signed, { enc: "A128GCM", recipients: [{ alg: "dir", key: cekJwk }] });
  const out = await facade.jwtDecryptNestedWithJwks(nested, cekJwk, decrypt, set, verify);
  assert.deepEqual(out.inner.claims, claims);
  assert.equal(out.inner.keyIndex, 1);
  assert.equal(out.inner.kid, "k1");
  assert.equal(out.outerHeader["cty"], "JWT");
  assert.equal(out.recipientIndex, 0);
});

// --- The records read field by field (L1): each field arrives ---------------------------------------

test("JwsSignOptions and JwsSigner: protectedB64u, detached and unprotectedHeader reach the core", async () => {
  const payload = ascii("payload");
  const protectedB64u = b64u(ascii(HS256));
  const compact = (await backend.jwsSignCompact(payload, hsKey, { protectedB64u, detached: true })) as string;
  const [head, body] = compact.split(".");
  assert.equal(head, protectedB64u, "signed over the given encoding (RFC 7515 §5.1 step 3)");
  assert.equal(body, "", "detached (RFC 7515 Appendix F)");
  await assert.rejects(Promise.resolve().then(() => backend.jwsSignCompact(payload, hsKey, {})), (e: unknown) => {
    assert.equal((e as { code?: unknown }).code, "InvalidHeader", "neither header form (ADR 0030 §4)");
    return true;
  });

  const flattened = json(
    (await backend.jwsSignFlattened(payload, { key: hsKey, protectedHeader: HS256, unprotectedHeader: '{"kid":"u"}' }, false)) as string,
  );
  assert.deepEqual(flattened["header"], { kid: "u" }, "the unprotected header (RFC 7515 §7.2.1)");
  assert.equal(flattened["payload"], b64u(payload));

  const general = json(
    (await backend.jwsSignGeneral(
      payload,
      [
        { key: hsKey, protectedHeader: HS256 },
        { key: hsKey, protectedHeader: HS256, unprotectedHeader: '{"kid":"second"}' },
      ],
      true,
    )) as string,
  );
  const signatures = general["signatures"] as { header?: unknown }[];
  assert.equal(signatures.length, 2, "both signers");
  assert.deepEqual(signatures[1]?.header, { kid: "second" });
  assert.equal(general["payload"], undefined, "detached");
});

test("JwsVerifyOptions: maxInputLen and maxSignatures reach the core", async () => {
  const payload = ascii("payload");
  const compact = (await backend.jwsSignCompact(payload, hsKey, { protectedHeader: HS256 })) as string;
  const ok = await backend.jwsVerifyCompact(compact, hsKey, { allowedAlgs: ["HS256"], maxInputLen: compact.length });
  assert.equal(ok.alg, "HS256");
  await assert.rejects(
    Promise.resolve().then(() => backend.jwsVerifyCompact(compact, hsKey, { allowedAlgs: ["HS256"], maxInputLen: compact.length - 1 })),
    (e: unknown) => typeof (e as { code?: unknown }).code === "string",
  );
  const general = (await backend.jwsSignGeneral(
    payload,
    [
      { key: hsKey, protectedHeader: HS256 },
      { key: hsKey, protectedHeader: HS256 },
    ],
    false,
  )) as string;
  assert.equal((await backend.jwsVerifyJson(general, hsKey, { allowedAlgs: ["HS256"], maxSignatures: 2 })).alg, "HS256");
  await assert.rejects(
    Promise.resolve().then(() => backend.jwsVerifyJson(general, hsKey, { allowedAlgs: ["HS256"], maxSignatures: 1 })),
    (e: unknown) => typeof (e as { code?: unknown }).code === "string",
  );
});

test("JweEncryptOptions and JweRecipient: every field reaches the core", async () => {
  const ec = (await backend.jwkGenerateEc("P-256")) as string;
  const ecPublic = (await backend.jwkToPublic(ec)) as string;
  const apu = ascii("Alice");
  const apv = ascii("Bob");
  const plaintext = ascii("plaintext ".repeat(8));
  const general = json(
    (await backend.jweEncryptJson(
      plaintext,
      {
        enc: "A128GCM",
        protectedHeader: '{"cty":"text/plain"}',
        sharedUnprotectedHeader: '{"jku":"https://example.com/s"}',
        aad: ascii("aad"),
        compress: false,
        recipients: [
          { alg: "ECDH-ES+A128KW", key: ecPublic, header: '{"kid":"e"}', apu, apv },
          { alg: PBES2, key: password, p2c: 1000, p2sLen: 24 },
        ],
      },
      "general",
    )) as string,
  );
  assert.equal(json(text(Buffer.from(general["protected"] as string, "base64url")))["cty"], "text/plain", "protectedHeader");
  assert.deepEqual(general["unprotected"], { jku: "https://example.com/s" }, "sharedUnprotectedHeader");
  assert.equal(general["aad"], b64u(ascii("aad")));
  const [ecdh, pbes2] = general["recipients"] as { header: Record<string, unknown> }[];
  assert.equal(ecdh?.header["kid"], "e", "the recipient header");
  assert.equal(ecdh?.header["apu"], b64u(apu), "apu (RFC 7518 §4.6.1.2)");
  assert.equal(ecdh?.header["apv"], b64u(apv), "apv (RFC 7518 §4.6.1.3)");
  assert.equal(pbes2?.header["p2c"], 1000, "p2c (RFC 7518 §4.8.1.2)");
  assert.equal(Buffer.from(pbes2?.header["p2s"] as string, "base64url").length, 24, "p2sLen (RFC 7518 §4.8.1.1)");

  const viaEc = await backend.jweDecryptJson(JSON.stringify(general), ec, { allowedAlgs: ["ECDH-ES+A128KW"], allowedEnc: ["A128GCM"] });
  assert.deepEqual([...viaEc.plaintext], [...plaintext], "decrypted");
  assert.equal(viaEc.recipientIndex, 0);

  // compress reaches the core: the bindings ship without the deflate feature (bindings/surface), so
  // DEFLATE (RFC 7516 §4.1.3) is refused rather than silently skipped.
  await assert.rejects(
    Promise.resolve().then(() =>
      backend.jweEncryptJson(plaintext, { enc: "A128GCM", compress: true, recipients: [{ alg: "dir", key: cek }] }, "general"),
    ),
    (e: unknown) => (e as { code?: unknown }).code === "UnsupportedAlgorithm",
  );
});

// --- Getter re-entrancy (review-security.md L1) -----------------------------------------------------

/**
 * The child: each scenario passes the backend a 64 MiB byte argument (0x11) together with a getter
 * that, while napi converts the arguments, detaches that argument's ArrayBuffer, lets it be
 * collected and sprays 8 × 64 MiB of 0x42 so the freed region is reused. An adapter that copied
 * the bytes only after the getter ran would sign or encrypt 0x42, or crash. Each scenario reports
 * whether the original bytes came out. The last one runs the same attack through the facade
 * (audit L1 a), which snapshots its inputs before any record is read.
 */
function spraySource(): string {
  const backendUrl = url.pathToFileURL(path.join(pkgDir, "backend.js")).href;
  const indexUrl = url.pathToFileURL(path.join(pkgDir, "index.js")).href;
  return `
import { backend as raw } from ${JSON.stringify(backendUrl)};
import * as facade from ${JSON.stringify(indexUrl)};
const SIZE = 64 << 20;
const original = Buffer.alloc(SIZE, 0x11);
const fresh = () => new Uint8Array(SIZE).fill(0x11);
const keyJwk = { kty: "oct", k: Buffer.alloc(32, 7).toString("base64url") };
const key = JSON.stringify(keyJwk);
const cek = JSON.stringify({ kty: "oct", k: Buffer.alloc(16, 9).toString("base64url") });
const HS256 = '{"alg":"HS256"}';
let spray = [];
const free = (view) => {
  structuredClone(view.buffer, { transfer: [view.buffer] });
  for (let i = 0; i < 4; i++) globalThis.gc();
  for (let i = 0; i < 8; i++) spray.push(new Uint8Array(SIZE).fill(0x42));
  if (view.byteLength !== 0) throw new Error("the argument was not detached");
};
const same = (b64u) => Buffer.from(b64u, "base64url").equals(original);
const results = [];
const run = async (name, scenario) => {
  try {
    results.push({ name, ok: (await scenario()) === true });
  } catch (e) {
    results.push({ name, ok: false, error: String(e?.code ?? "") + " " + String(e?.message ?? e).slice(0, 200) });
  }
  spray = [];
  for (let i = 0; i < 4; i++) globalThis.gc();
};

await run("jwsSignCompact: an options getter frees the payload", async () => {
  const payload = fresh();
  const options = { get protectedHeader() { free(payload); return HS256; } };
  return same((await raw.jwsSignCompact(payload, key, options)).split(".")[1]);
});
await run("jwsSignFlattened: a signer getter frees the payload", async () => {
  const payload = fresh();
  const signer = { key, get protectedHeader() { free(payload); return HS256; } };
  return same(JSON.parse(await raw.jwsSignFlattened(payload, signer, false)).payload);
});
await run("jwsSignGeneral: an array element getter frees the payload", async () => {
  const payload = fresh();
  const signers = [];
  Object.defineProperty(signers, 0, { enumerable: true, get() { free(payload); return { key, protectedHeader: HS256 }; } });
  return same(JSON.parse(await raw.jwsSignGeneral(payload, signers, false)).payload);
});
await run("jweEncryptCompact: an options getter frees the plaintext", async () => {
  const plaintext = fresh();
  const options = { get enc() { free(plaintext); return "A128GCM"; }, recipients: [{ alg: "dir", key: cek }] };
  const token = await raw.jweEncryptCompact(plaintext, options);
  const out = await raw.jweDecryptCompact(token, cek, { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"], maxInputLen: 4294967295 });
  return Buffer.from(out.plaintext).equals(original);
});
await run("jweEncryptJson: a later options getter frees the aad", async () => {
  const aad = fresh();
  const options = { enc: "A128GCM", recipients: [{ alg: "dir", key: cek }], aad, get compress() { free(aad); return undefined; } };
  return same(JSON.parse(await raw.jweEncryptJson(new Uint8Array([1, 2, 3]), options, "flattened")).aad);
});
await run("jweEncryptCompact: a recipient's apv getter frees its apu", async () => {
  const ecPublic = await raw.jwkToPublic(await raw.jwkGenerateEc("P-256"));
  const apu = fresh();
  const recipient = { alg: "ECDH-ES+A128KW", key: ecPublic, apu, get apv() { free(apu); return undefined; } };
  const token = await raw.jweEncryptCompact(new Uint8Array([1, 2, 3]), { enc: "A128GCM", recipients: [recipient] });
  return same(JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("latin1")).apu);
});
await run("jwsVerifyCompact: a later options getter frees the detachedPayload", async () => {
  const token = await raw.jwsSignCompact(fresh(), key, { protectedHeader: HS256, detached: true });
  const detachedPayload = fresh();
  const options = { allowedAlgs: ["HS256"], detachedPayload, get maxInputLen() { free(detachedPayload); return undefined; } };
  const out = await raw.jwsVerifyCompact(token, key, options);
  return Buffer.from(out.payload).equals(original);
});
await run("facade jwsSignCompact: an options getter frees the payload", async () => {
  const payload = fresh();
  const options = { get protectedHeader() { free(payload); return { alg: "HS256" }; } };
  return same((await facade.jwsSignCompact(payload, keyJwk, options)).split(".")[1]);
});
console.log(JSON.stringify(results));
`;
}

test("a getter that frees a byte argument during argument conversion cannot make the raw backend read freed memory (review-security.md L1)", () => {
  const child = host.getBuiltinModule("node:child_process").spawnSync(
    host.execPath,
    ["--expose-gc", "--input-type=module", "-e", spraySource()],
    // A guard against a hang, not a timing assertion (pipeline rule 8).
    { encoding: "utf8", timeout: 600_000, maxBuffer: 1 << 20, cwd: pkgDir },
  );
  assert.equal(child.signal, null, `the child was killed by ${String(child.signal)} (a crash reading freed memory?)\n${child.stderr}`);
  assert.equal(child.status, 0, `the child failed:\n${child.stderr}`);
  const lines = child.stdout.trim().split("\n");
  const results = JSON.parse(lines[lines.length - 1] ?? "[]") as { name: string; ok: boolean; error?: string }[];
  assert.equal(results.length, 8, child.stdout);
  assert.deepEqual(
    results.filter((r) => !r.ok),
    [],
    "every scenario signs or encrypts the original bytes",
  );
});
