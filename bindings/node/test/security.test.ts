// The JS-level security properties of @polyjose/node (feature 0007 T03; ADR 0030 §5-§7, ADR 0031
// §2), run with `node --test` against the compiled package (ADR 0047):
//   - no input in errors: a failing call of every family, given secrets that hold a marker, rejects
//     with a PolyjoseError whose message, string form, stack and inspected form hold none of them;
//   - off the JS thread: a costly PBES2 decrypt resolves while the event loop keeps running timers;
//   - input copy: the payload is copied when the call is made, so the caller may reuse its buffer;
//   - the security decisions (allow-lists, RSA public-key only, no SHA-1) reach JS unchanged, for
//     the JS call shapes the conformance vectors cannot express, such as a missing allowedAlgs.
// No assertion reads a clock (pipeline rule 8): event-loop progress is a count of timer ticks.
import { assert, fs, path, test } from "../../js/dist/node/builtins.js";
import {
  ERROR_CODES,
  PolyjoseError,
  base64urlDecode,
  base64urlEncode,
  jweDecryptCompact,
  jweEncryptCompact,
  jwkFromDer,
  jwkGenerateEc,
  jwkGenerateOct,
  jwkParse,
  jwkThumbprint,
  jwkThumbprintUri,
  jwkToPem,
  jwkToPublic,
  jwsSignCompact,
  jwsVerifyCompact,
  jwtDecryptNested,
  jwtEncryptNested,
  jwtSign,
  jwtVerify,
} from "@polyjose/node";
import type { JweDecryptOptions, JwkObject, JwsVerifyOptions, JwtVerifyOptions, ThumbprintHash } from "@polyjose/node";

// Node built-ins without @types/node (ADR 0047), typed with only what this file calls.
interface NodeUrl {
  fileURLToPath(url: string): string;
}
interface NodeUtil {
  inspect(value: unknown): string;
}
interface Host {
  getBuiltinModule(id: "node:url"): NodeUrl;
  getBuiltinModule(id: "node:util"): NodeUtil;
  readonly env: Readonly<Record<string, string | undefined>>;
}
interface Timers {
  setInterval(fn: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
}
const host = (globalThis as unknown as { process: Host }).process;
const timers = globalThis as unknown as Timers;
const util = host.getBuiltinModule("node:util");
const thisFile = host.getBuiltinModule("node:url").fileURLToPath((import.meta as unknown as { url: string }).url);
/** The repository root: this file is bindings/node/dist/security.test.js. */
const repo = path.resolve(path.dirname(thisFile), "..", "..", "..");

/** The ASCII bytes of `s`. */
const ascii = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0));

/** One input of a conformance vector (conformance/vectors/binding-surface, ADR 0034 §6). */
function vectorInput(name: string): Record<string, unknown> {
  const file = path.join(repo, "conformance", "vectors", "binding-surface", name);
  const vector = JSON.parse(fs.readFileSync(file, "utf8")) as { input: Record<string, unknown> };
  return vector.input;
}

/**
 * `call` returns a Promise that rejects with a PolyjoseError of `code` (ADR 0030 §5, ADR 0031 §1),
 * and none of `secrets` appears in the error's message, `String(err)`, `err.stack` or its
 * `util.inspect` form, which also shows its own properties (ADR 0030 §5, "No input in errors").
 * The assertion messages name the view, never the text, so a failure prints no secret.
 */
async function rejectsWithoutSecrets(
  what: string,
  call: () => Promise<unknown>,
  code: (typeof ERROR_CODES)[number],
  secrets: readonly string[],
): Promise<void> {
  const pending = call();
  assert.ok(pending instanceof Promise, `${what}: returns a Promise`);
  let caught: unknown;
  try {
    await pending;
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof PolyjoseError, `${what}: rejects with a PolyjoseError`);
  assert.equal(caught.code, code, `${what}: the code`);
  const stack = caught.stack;
  assert.ok(stack !== undefined && stack.length > 0, `${what}: has a stack`);
  const views: Record<string, string> = {
    message: caught.message,
    "String(err)": String(caught),
    "err.stack": stack,
    "util.inspect(err)": util.inspect(caught),
  };
  for (const [view, text] of Object.entries(views)) {
    secrets.forEach((secret, i) => {
      assert.ok(secret.length >= 8, `${what}: secret ${i} is a distinctive marker`);
      assert.ok(!text.includes(secret), `${what}: ${view} contains secret ${i}`);
    });
  }
}

// --- No input in errors (ADR 0030 §5, §7) --------------------------------------------------------------

/** Markers, each a valid key length, so a call can get past key parsing to where it fails. */
const MARKER_32 = "polyjose-secret-marker-32-bytes!";
const MARKER_16 = "pj-marker-16byte";

test("a failing call of every family keeps the secrets that hold a marker out of the error", async () => {
  const k32 = await base64urlEncode(ascii(MARKER_32));
  const k16 = await base64urlEncode(ascii(MARKER_16));
  /** An HS256-sized `oct` key whose `k` is the marker (RFC 7518 §6.4.1). */
  const octMarker: JwkObject = { kty: "oct", k: k32 };
  /** A P-256 private JWK whose `d` is the marker, which does not match its `x` and `y`. */
  const ecMarker: JwkObject = { ...(await jwkGenerateEc("P-256")), d: k32 };
  const payload = ascii(`payload holding ${MARKER_32}`);
  const otherKey = await jwkGenerateOct(32);
  const signed = await jwsSignCompact(payload, otherKey, { protectedHeader: { alg: "HS256" } });
  const jwt = await jwtSign({ sub: MARKER_32 }, otherKey, { alg: "HS256" });
  const jwe = await jweEncryptCompact(payload, {
    enc: "A128GCM",
    recipients: [{ alg: "A128KW", key: await jwkGenerateOct(16) }],
  });
  const nested = await jwtEncryptNested(jwt, {
    enc: "A128GCM",
    recipients: [{ alg: "A128KW", key: await jwkGenerateOct(16) }],
  });
  const decryptA128KW: JweDecryptOptions = { allowedAlgs: ["A128KW"], allowedEnc: ["A128GCM"] };
  // Every form a secret takes in these calls: the raw markers, their base64url (the JWK members and
  // token segments), the JWK JSON and the tokens' payload segments.
  const secrets = [
    MARKER_32,
    MARKER_16,
    k32,
    k16,
    JSON.stringify(octMarker),
    JSON.stringify(ecMarker),
    signed.split(".")[1] ?? "",
    jwt.split(".")[1] ?? "",
    jwe.split(".")[3] ?? "",
  ];

  // Utilities: strict base64url (RFC 4648 §5) of a string that holds the marker.
  await rejectsWithoutSecrets("base64urlDecode", () => base64urlDecode(MARKER_32), "InvalidBase64", secrets);
  // JWK (RFC 7517, RFC 7518 §6): a private member that does not decode, or does not match.
  await rejectsWithoutSecrets("jwkParse oct", () => jwkParse({ kty: "oct", k: MARKER_32 }), "InvalidBase64", secrets);
  await rejectsWithoutSecrets("jwkParse EC", () => jwkParse(ecMarker), "InvalidKey", secrets);
  await rejectsWithoutSecrets("jwkToPublic EC", () => jwkToPublic(ecMarker), "InvalidKey", secrets);
  await rejectsWithoutSecrets("jwkToPem oct", () => jwkToPem(octMarker, "pkcs8"), "UnsupportedAlgorithm", secrets);
  // Bytes that are not a PKCS #8 structure (RFC 5958): InvalidKey (bindings/surface keys.rs).
  await rejectsWithoutSecrets("jwkFromDer", () => jwkFromDer(payload, "pkcs8"), "InvalidKey", secrets);
  // JWS (RFC 7515 §5): a key of another family, a key that does not match, a wrong key.
  await rejectsWithoutSecrets(
    "jwsSignCompact oct as ES256",
    () => jwsSignCompact(payload, octMarker, { protectedHeader: { alg: "ES256" } }),
    "KeyAlgorithmMismatch",
    secrets,
  );
  await rejectsWithoutSecrets(
    "jwsSignCompact EC",
    () => jwsSignCompact(payload, ecMarker, { protectedHeader: { alg: "ES256" } }),
    "InvalidKey",
    secrets,
  );
  await rejectsWithoutSecrets(
    "jwsVerifyCompact wrong key",
    () => jwsVerifyCompact(signed, octMarker, { allowedAlgs: ["HS256"] }),
    "InvalidSignature",
    secrets,
  );
  // JWE (RFC 7516 §5): a `dir` key of the wrong length, a wrong key-wrapping key.
  await rejectsWithoutSecrets(
    "jweEncryptCompact dir",
    () => jweEncryptCompact(payload, { enc: "A128GCM", recipients: [{ alg: "dir", key: octMarker }] }),
    "InvalidKey",
    secrets,
  );
  await rejectsWithoutSecrets(
    "jweDecryptCompact wrong key",
    () => jweDecryptCompact(jwe, { kty: "oct", k: k16 }, decryptA128KW),
    "DecryptionFailed",
    secrets,
  );
  // JWT (RFC 7519 §7): claims that hold the marker, signed or verified with the wrong key.
  await rejectsWithoutSecrets(
    "jwtSign oct as ES256",
    () => jwtSign({ sub: MARKER_32 }, octMarker, { alg: "ES256" }),
    "KeyAlgorithmMismatch",
    secrets,
  );
  await rejectsWithoutSecrets(
    "jwtVerify wrong key",
    () => jwtVerify(jwt, octMarker, { allowedAlgs: ["HS256"] }),
    "InvalidSignature",
    secrets,
  );
  await rejectsWithoutSecrets(
    "jwtDecryptNested wrong key",
    () => jwtDecryptNested(nested, { kty: "oct", k: k16 }, decryptA128KW, otherKey, { allowedAlgs: ["HS256"] }),
    "DecryptionFailed",
    secrets,
  );
});

// --- Off the JS thread (ADR 0031 §2, research §3) -------------------------------------------------------

/** A PBES2 password (RFC 7518 §4.8) and a compact JWE that costs `p2c` PBKDF2 iterations. */
const PBES2_ALG = "PBES2-HS256+A128KW";
const password: JwkObject = { kty: "oct", k: "cGotcGJlczItcGFzc3dvcmQ" };
const pbes2Options = (maxPbes2Count?: number): JweDecryptOptions => ({
  allowedAlgs: [PBES2_ALG],
  allowedEnc: ["A128GCM"],
  ...(maxPbes2Count === undefined ? {} : { maxPbes2Count }),
});
/** The core's ceiling for `p2c` and `maxPbes2Count` (ADR 0050 §2): the costliest decrypt allowed. */
const P2C_CEILING = 1_000_000;
const pbes2Plaintext = ascii("decrypted on the libuv thread pool");
let pbes2Token: Promise<string> | undefined;
const costlyToken = (): Promise<string> =>
  (pbes2Token ??= jweEncryptCompact(pbes2Plaintext, {
    enc: "A128GCM",
    recipients: [{ alg: PBES2_ALG, key: password, p2c: P2C_CEILING }],
  }));

test("a PBES2 decrypt over the default budget rejects; raised, it runs while the event loop keeps ticking", async () => {
  const token = await costlyToken();
  // The core's default budget (10,000, ADR 0023) refuses this token before deriving anything, with
  // the uniform decrypt failure (RFC 7516 §11.5, ADR 0050 §2), so the raised budget is what lets it run.
  await rejectsWithoutSecrets("default budget", () => jweDecryptCompact(token, password, pbes2Options()), "DecryptionFailed", [
    "cGotcGJlczItcGFzc3dvcmQ",
  ]);

  let ticks = 0;
  const timer = timers.setInterval(() => {
    ticks += 1;
  }, 1);
  try {
    const pending = jweDecryptCompact(token, password, pbes2Options(P2C_CEILING));
    const ticksAtCall = ticks;
    const out = await pending;
    assert.deepEqual(out.plaintext, pbes2Plaintext, "the raised budget decrypts");
    // The criterion is ticks > 0 while the call is pending. A call that blocked the JS thread would
    // allow at most one late tick before its result is delivered (Node runs each due interval once
    // per timers phase), so two or more show the event loop ran during the derivation.
    assert.ok(ticks - ticksAtCall >= 2, `the event loop ticked ${ticks - ticksAtCall} times during the decrypt`);
  } finally {
    timers.clearInterval(timer);
  }
});

// --- Input copy (ADR 0030 §7.1, ADR 0031 §2, research §4) ----------------------------------------------

test("jwsSignCompact copies the payload when called: changing the caller's bytes before awaiting does not change what is signed", async () => {
  const key = await jwkGenerateOct(32);
  const original = ascii("the payload as it was when jwsSignCompact was called");
  const token = await costlyToken();
  // Occupy every libuv pool thread (UV_THREADPOOL_SIZE, 4 by default) with a costly decrypt first,
  // so the signing task cannot start its work until after the bytes below are changed: if the
  // adapter read the caller's memory off the JS thread instead of copying it, it would sign them.
  const poolSize = Math.min(Math.max(Number(host.env["UV_THREADPOOL_SIZE"] ?? "4") || 4, 1), 1024);
  const busy = Array.from({ length: poolSize }, () => jweDecryptCompact(token, password, pbes2Options(P2C_CEILING)));

  const payload = original.slice();
  const signing = jwsSignCompact(payload, key, { protectedHeader: { alg: "HS256" } });
  payload.fill(0x58);
  const signed = await signing;
  await Promise.all(busy);

  const verified = await jwsVerifyCompact(signed, key, { allowedAlgs: ["HS256"] });
  assert.deepEqual(verified.payload, original, "the signed payload is the bytes at call time");

  // The adapter wipes its own copy (ADR 0030 §7.6), never the caller's buffer.
  const kept = original.slice();
  await jwsSignCompact(kept, key, { protectedHeader: { alg: "HS256" } });
  assert.deepEqual(kept, original, "the caller's payload is left as it was");
});

// --- Security decisions reach JS unchanged (ADR 0030 §6, RFC 8725 §3.1) ---------------------------------

test("jwsVerifyCompact rejects an empty, a none-only and a missing allowedAlgs with AlgorithmNotAllowed", async () => {
  // RFC 7515 Appendix A.1: an HS256 JWS and its key, which verify under ["HS256"].
  const a1 = vectorInput("jws-verify-allowed-algs-none-only.json");
  const jws = a1["jws"] as string;
  const key = a1["key"] as JwkObject;
  assert.equal((await jwsVerifyCompact(jws, key, { allowedAlgs: ["HS256"] })).alg, "HS256");
  // An Unsecured JWS (RFC 7515 §A.5 form, `alg: none`): never accepted (ADR 0007), even when listed.
  const unsecured = `${await base64urlEncode(ascii('{"alg":"none"}'))}.${await base64urlEncode(ascii("x"))}.`;

  const shapes: [string, string, unknown][] = [
    ["allowedAlgs: []", jws, { allowedAlgs: [] }],
    ['allowedAlgs: ["none"]', jws, { allowedAlgs: ["none"] }],
    ['allowedAlgs: ["none"], alg none token', unsecured, { allowedAlgs: ["none"] }],
    ["no allowedAlgs property", jws, {}],
    ["allowedAlgs: undefined", jws, { allowedAlgs: undefined }],
    ["allowedAlgs: null", jws, { allowedAlgs: null }],
  ];
  for (const [what, token, options] of shapes) {
    await rejectsWithoutSecrets(
      `jwsVerifyCompact ${what}`,
      () => jwsVerifyCompact(token, key, options as JwsVerifyOptions),
      "AlgorithmNotAllowed",
      [key["k"] as string],
    );
  }
});

test("JWE decrypt and JWT verify without their allow-lists reject with AlgorithmNotAllowed", async () => {
  const key = await jwkGenerateOct(16);
  const jwe = await jweEncryptCompact(ascii("x"), { enc: "A128GCM", recipients: [{ alg: "A128KW", key }] });
  const jweShapes: [string, unknown][] = [
    ["no options properties", {}],
    ["no allowedEnc", { allowedAlgs: ["A128KW"] }],
    ["no allowedAlgs", { allowedEnc: ["A128GCM"] }],
  ];
  for (const [what, options] of jweShapes) {
    await assert.rejects(
      jweDecryptCompact(jwe, key, options as JweDecryptOptions),
      (e: unknown) => e instanceof PolyjoseError && e.code === "AlgorithmNotAllowed",
      `jweDecryptCompact ${what}`,
    );
  }
  const hs = await jwkGenerateOct(32);
  const jwt = await jwtSign({ sub: "s" }, hs, { alg: "HS256" });
  await assert.rejects(
    jwtVerify(jwt, hs, {} as JwtVerifyOptions),
    (e: unknown) => e instanceof PolyjoseError && e.code === "AlgorithmNotAllowed",
    "jwtVerify without allowedAlgs",
  );
});

test("an RSA private JWK is UnsupportedAlgorithm (ADR 0021), and so is a SHA-1 thumbprint (ADR 0022)", async () => {
  // RFC 7515 Appendix A.2's RSA private JWK.
  const signer = (vectorInput("jws-sign-rsa-private-jwk.json")["signers"] as { key: JwkObject }[])[0];
  assert.ok(signer !== undefined, "the vector has a signer");
  const rsa = signer.key;
  const rsaSecrets = [rsa["d"] as string, rsa["p"] as string, rsa["q"] as string];
  await rejectsWithoutSecrets("jwkParse RSA private", () => jwkParse(rsa), "UnsupportedAlgorithm", rsaSecrets);
  await rejectsWithoutSecrets("jwkToPublic RSA private", () => jwkToPublic(rsa), "UnsupportedAlgorithm", rsaSecrets);
  await rejectsWithoutSecrets(
    "jwsSignCompact RSA private",
    () => jwsSignCompact(ascii("x"), rsa, { protectedHeader: { alg: "RS256" } }),
    "UnsupportedAlgorithm",
    rsaSecrets,
  );

  const jwk = await jwkGenerateOct(32);
  const sha1 = "SHA-1" as ThumbprintHash; // outside the type on purpose: a JS caller can pass it
  await rejectsWithoutSecrets("jwkThumbprint SHA-1", () => jwkThumbprint(jwk, sha1), "UnsupportedAlgorithm", [
    jwk["k"] as string,
  ]);
  await rejectsWithoutSecrets("jwkThumbprintUri SHA-1", () => jwkThumbprintUri(jwk, sha1), "UnsupportedAlgorithm", [
    jwk["k"] as string,
  ]);
});
