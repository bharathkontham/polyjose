/**
 * [WASM-pkg-node] The security decisions of ADR 0030 §5-§7 and RFC 8725, as JS call shapes on
 * the installed package (the same checks as 0007 T03 for `@polyjose/node`):
 * - no input in errors: a failing call with secret material (a private JWK's `d`/`k`, a payload)
 *   rejects with a `PolyjoseError` whose `message`, `String(err)` and `stack` hold none of it
 *   (ADR 0030 §5: error messages never carry input or key material);
 * - a verify or decrypt whose options lack `allowedAlgs` (or `allowedEnc`) is
 *   `AlgorithmNotAllowed`, as are `[]` and `["none"]` (RFC 8725 §3.1, §3.2; ADR 0031 §1: a
 *   missing allow-list becomes `[]`). The vectors can't express a missing property;
 * - mutating the caller's `Uint8Array` after the call has started doesn't change the result
 *   (here on a warm module; `input-copy.test.ts` checks the first call of a process).
 */
import * as api from "@polyjose/wasm";
import type { JweDecryptOptions, JwsVerifyOptions, JwtVerifyOptions } from "@polyjose/wasm";
import { assert, test } from "./node.js";

/** Valid base64url, so it gets past the decoder and into key and payload handling. */
const MARKER = "polyjoseSecretMarker7f3a";
/** Not base64url ('!'), so the decoder itself rejects it. */
const BAD_MARKER = "polyjose!Secret!Marker!7f3a";
const MARKERS = [MARKER, BAD_MARKER];

const enc = new TextEncoder();
const codes: readonly string[] = await api.errorCodes();

/** Rejects with a PolyjoseError whose code is a core code and whose text holds no marker. */
async function rejectsClean(call: Promise<unknown>, what: string): Promise<void> {
  await assert.rejects(call, (e: unknown) => {
    assert.ok(e instanceof api.PolyjoseError, `${what}: not a PolyjoseError: ${String(e)}`);
    assert.ok(e instanceof Error);
    assert.equal(e.name, "PolyjoseError");
    assert.ok(codes.includes(e.code), `${what}: code ${e.code} is not in errorCodes()`);
    for (const text of [e.message, String(e), e.stack ?? ""]) {
      for (const marker of MARKERS) {
        assert.ok(!text.includes(marker), `${what}: the error text holds the input marker: ${text}`);
      }
    }
    return true;
  }, `${what}: expected a rejection`);
}

/** Rejects with `AlgorithmNotAllowed`. */
async function notAllowed(call: Promise<unknown>, what: string): Promise<void> {
  await assert.rejects(call, (e: unknown) => {
    assert.ok(e instanceof api.PolyjoseError, `${what}: not a PolyjoseError: ${String(e)}`);
    assert.equal(e.code, "AlgorithmNotAllowed", what);
    return true;
  }, `${what}: expected a rejection`);
}

await test("no input in errors: JWK, JWS, JWE and JWT failures don't echo key or payload (ADR 0030 §5)", async () => {
  // An oct key of the valid marker is a well-formed 18-byte key, so only the bad one fails to parse.
  await rejectsClean(api.jwkParse({ kty: "oct", k: BAD_MARKER }), "jwkParse oct with a non-base64url k");
  for (const k of MARKERS) {
    await rejectsClean(
      api.jwkParse({ kty: "EC", crv: "P-256", x: k, y: k, d: k }),
      `jwkParse EC d=${k === MARKER ? "marker" : "bad"}`,
    );
    await rejectsClean(
      api.jwsSignCompact(enc.encode(MARKER), { kty: "EC", crv: "P-256", x: k, y: k, d: k }, { protectedHeader: { alg: "ES256" } }),
      "jwsSignCompact with a marker EC key and payload",
    );
    await rejectsClean(
      api.jwtSign({ sub: MARKER }, { kty: "oct", k }, { alg: "HS256" }),
      "jwtSign with a marker oct key (too short for HS256, RFC 7518 §3.2) and claim",
    );
    await rejectsClean(
      api.jweDecryptCompact(`eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..${k}.${k}.${k}`, { kty: "oct", k }, {
        allowedAlgs: ["dir"],
        allowedEnc: ["A256GCM"],
      }),
      "jweDecryptCompact with a marker key and token",
    );
  }

  // A well-formed key and token, and a failure deeper in: the wrong key (RFC 7515 §5.2 step 8).
  const key = await api.jwkGenerateOct(32);
  const other = await api.jwkGenerateOct(32);
  const token = await api.jwsSignCompact(enc.encode(MARKER), key, { protectedHeader: { alg: "HS256" } });
  await rejectsClean(api.jwsVerifyCompact(token, other, { allowedAlgs: ["HS256"] }), "jwsVerifyCompact, wrong key");
  const jwe = await api.jweEncryptCompact(enc.encode(MARKER), { enc: "A256GCM", recipients: [{ alg: "dir", key }] });
  await rejectsClean(
    api.jweDecryptCompact(jwe, other, { allowedAlgs: ["dir"], allowedEnc: ["A256GCM"] }),
    "jweDecryptCompact, wrong key",
  );
});

await test("a missing allowedAlgs/allowedEnc, [] and ['none'] are AlgorithmNotAllowed (RFC 8725 §3.1)", async () => {
  const key = await api.jwkGenerateOct(32);
  const jws = await api.jwsSignCompact(enc.encode("payload"), key, { protectedHeader: { alg: "HS256" } });
  await notAllowed(api.jwsVerifyCompact(jws, key, {} as unknown as JwsVerifyOptions), "jwsVerifyCompact without allowedAlgs");
  await notAllowed(api.jwsVerifyCompact(jws, key, { allowedAlgs: [] }), "jwsVerifyCompact allowedAlgs: []");
  await notAllowed(api.jwsVerifyCompact(jws, key, { allowedAlgs: ["none"] }), "jwsVerifyCompact allowedAlgs: ['none']");

  const jwe = await api.jweEncryptCompact(enc.encode("plaintext"), { enc: "A256GCM", recipients: [{ alg: "dir", key }] });
  await notAllowed(
    api.jweDecryptCompact(jwe, key, { allowedEnc: ["A256GCM"] } as unknown as JweDecryptOptions),
    "jweDecryptCompact without allowedAlgs",
  );
  await notAllowed(
    api.jweDecryptCompact(jwe, key, { allowedAlgs: ["dir"] } as unknown as JweDecryptOptions),
    "jweDecryptCompact without allowedEnc",
  );

  const jwt = await api.jwtSign({ sub: "alice" }, key, { alg: "HS256" });
  await notAllowed(api.jwtVerify(jwt, key, {} as unknown as JwtVerifyOptions), "jwtVerify without allowedAlgs");
});

await test("mutating the payload after jwsSignCompact starts doesn't change what is signed (warm)", async () => {
  const key = await api.jwkGenerateOct(32);
  const original = [1, 2, 3, 4, 5, 6, 7, 8];
  const payload = new Uint8Array(original);
  const pending = api.jwsSignCompact(payload, key, { protectedHeader: { alg: "HS256" } });
  payload.fill(0xee);
  const verified = await api.jwsVerifyCompact(await pending, key, { allowedAlgs: ["HS256"] });
  assert.deepEqual(Array.from(verified.payload), original);
});
