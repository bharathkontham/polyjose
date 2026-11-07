/**
 * The package's engine-independent security checks, shared by every runtime under test (review
 * N8): `security.test.ts` and `input-copy.test.ts` run them in Node (wasm-pkg-node), the Chrome
 * page (`page.ts`, wasm-pkg-chrome) and the worker (`worker.ts`, wasm-pkg-workerd) run
 * {@link securityReport}. Each check is a {@link ProbeCheck}, so every runtime reports them the
 * same way; none of them touches the conformance results files. No Node imports: it runs in
 * browsers and workerd.
 *
 * - **No input in errors** (ADR 0030 §5: error messages never carry input or key material): a
 *   failing call with secret material (a private JWK's `d`/`k`, a payload) rejects with a
 *   `PolyjoseError` whose `message`, `String(err)` and `stack` hold none of it.
 * - **Missing allow-lists** (RFC 8725 §3.1, §3.2; ADR 0031 §1: a missing allow-list becomes
 *   `[]`): a verify or decrypt whose options lack `allowedAlgs` (or `allowedEnc`) is
 *   `AlgorithmNotAllowed`, as are `[]` and `["none"]`. The vectors can't express a missing
 *   property.
 * - **Input copy** (ADR 0030 §7): mutating the caller's `Uint8Array` right after a call starts,
 *   before awaiting it, doesn't change what is signed. On a cold module (the facade's lazy
 *   `ready()`, ADR 0031 §3) the call starts before the WebAssembly module is instantiated.
 */
import type { PolyjoseApi } from "../js/src/api.js";
import type { ProbeCheck, ProbeReport } from "./results.js";

/** Valid base64url, so it gets past the decoder and into key and payload handling. */
export const MARKER = "polyjoseSecretMarker7f3a";
/** Not base64url ('!'), so the decoder itself rejects it. */
export const BAD_MARKER = "polyjose!Secret!Marker!7f3a";
const MARKERS = [MARKER, BAD_MARKER];

/** RFC 7515 Appendix A.1's HMAC key: no API call is needed to make it, so a cold check stays cold. */
const RFC7515_A1_KEY = {
  kty: "oct",
  k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
};

const enc = new TextEncoder();

function describe(e: unknown): string {
  return e instanceof Error ? `${e.name} code=${String((e as { code?: unknown }).code)}` : String(e);
}

/** Runs `call`; the check passes only if it rejects with a PolyjoseError of a core code whose text holds no marker. */
async function rejectsClean(api: PolyjoseApi, codes: readonly string[], what: string, call: () => Promise<unknown>): Promise<ProbeCheck> {
  try {
    await call();
  } catch (e) {
    if (!(e instanceof api.PolyjoseError) || !(e instanceof Error) || e.name !== "PolyjoseError") {
      return { what, ok: false, detail: `not a PolyjoseError: ${describe(e)}` };
    }
    if (!codes.includes(e.code)) return { what, ok: false, detail: `code ${e.code} is not in errorCodes()` };
    for (const text of [e.message, String(e), e.stack ?? ""]) {
      for (const marker of MARKERS) {
        if (text.includes(marker)) return { what, ok: false, detail: `the error text holds the input marker: ${text}` };
      }
    }
    return { what, ok: true, detail: `PolyjoseError code=${e.code}, no marker in message, String() or stack` };
  }
  return { what, ok: false, detail: "resolved; expected a rejection" };
}

/** Runs `call`; the check passes only if it rejects with `AlgorithmNotAllowed`. */
async function notAllowed(api: PolyjoseApi, what: string, call: () => Promise<unknown>): Promise<ProbeCheck> {
  try {
    await call();
  } catch (e) {
    const ok = e instanceof api.PolyjoseError && e.code === "AlgorithmNotAllowed";
    return { what, ok, detail: describe(e) };
  }
  return { what, ok: false, detail: "resolved; expected AlgorithmNotAllowed" };
}

/** Failing JWK, JWS, JWE and JWT calls don't echo key or payload in their errors (ADR 0030 §5). */
export async function noInputInErrors(api: PolyjoseApi): Promise<ProbeCheck[]> {
  const codes: readonly string[] = await api.errorCodes();
  const checks: ProbeCheck[] = [];
  // An oct key of the valid marker is a well-formed 18-byte key, so only the bad one fails to parse.
  checks.push(await rejectsClean(api, codes, "jwkParse oct with a non-base64url k", () => api.jwkParse({ kty: "oct", k: BAD_MARKER })));
  for (const k of MARKERS) {
    const which = k === MARKER ? "marker" : "bad marker";
    checks.push(await rejectsClean(api, codes, `jwkParse EC d=${which}`, () => api.jwkParse({ kty: "EC", crv: "P-256", x: k, y: k, d: k })));
    checks.push(
      await rejectsClean(api, codes, `jwsSignCompact with a ${which} EC key and payload`, () =>
        api.jwsSignCompact(enc.encode(MARKER), { kty: "EC", crv: "P-256", x: k, y: k, d: k }, { protectedHeader: { alg: "ES256" } }),
      ),
    );
    checks.push(
      await rejectsClean(api, codes, `jwtSign with a ${which} oct key (too short for HS256, RFC 7518 §3.2) and claim`, () =>
        api.jwtSign({ sub: MARKER }, { kty: "oct", k }, { alg: "HS256" }),
      ),
    );
    checks.push(
      await rejectsClean(api, codes, `jweDecryptCompact with a ${which} key and token`, () =>
        api.jweDecryptCompact(`eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..${k}.${k}.${k}`, { kty: "oct", k }, {
          allowedAlgs: ["dir"],
          allowedEnc: ["A256GCM"],
        }),
      ),
    );
  }

  // A well-formed key and token, and a failure deeper in: the wrong key (RFC 7515 §5.2 step 8;
  // RFC 7516 §5.2 step 16).
  const key = await api.jwkGenerateOct(32);
  const other = await api.jwkGenerateOct(32);
  const token = await api.jwsSignCompact(enc.encode(MARKER), key, { protectedHeader: { alg: "HS256" } });
  checks.push(await rejectsClean(api, codes, "jwsVerifyCompact, wrong key", () => api.jwsVerifyCompact(token, other, { allowedAlgs: ["HS256"] })));
  const jwe = await api.jweEncryptCompact(enc.encode(MARKER), { enc: "A256GCM", recipients: [{ alg: "dir", key }] });
  checks.push(
    await rejectsClean(api, codes, "jweDecryptCompact, wrong key", () =>
      api.jweDecryptCompact(jwe, other, { allowedAlgs: ["dir"], allowedEnc: ["A256GCM"] }),
    ),
  );
  return checks;
}

/** A missing `allowedAlgs`/`allowedEnc`, `[]` and `["none"]` are `AlgorithmNotAllowed` (RFC 8725 §3.1, §3.2). */
export async function missingAllowLists(api: PolyjoseApi): Promise<ProbeCheck[]> {
  const key = await api.jwkGenerateOct(32);
  const jws = await api.jwsSignCompact(enc.encode("payload"), key, { protectedHeader: { alg: "HS256" } });
  const jwe = await api.jweEncryptCompact(enc.encode("plaintext"), { enc: "A256GCM", recipients: [{ alg: "dir", key }] });
  const jwt = await api.jwtSign({ sub: "alice" }, key, { alg: "HS256" });
  return [
    await notAllowed(api, "jwsVerifyCompact without allowedAlgs", () => api.jwsVerifyCompact(jws, key, {} as never)),
    await notAllowed(api, "jwsVerifyCompact allowedAlgs: []", () => api.jwsVerifyCompact(jws, key, { allowedAlgs: [] })),
    await notAllowed(api, "jwsVerifyCompact allowedAlgs: ['none']", () => api.jwsVerifyCompact(jws, key, { allowedAlgs: ["none"] })),
    await notAllowed(api, "jweDecryptCompact without allowedAlgs", () => api.jweDecryptCompact(jwe, key, { allowedEnc: ["A256GCM"] } as never)),
    await notAllowed(api, "jweDecryptCompact without allowedEnc", () => api.jweDecryptCompact(jwe, key, { allowedAlgs: ["dir"] } as never)),
    await notAllowed(api, "jwtVerify without allowedAlgs", () => api.jwtVerify(jwt, key, {} as never)),
  ];
}

/**
 * Starts a `jwsSignCompact` (RFC 7515 Appendix A.1's key, so the call needs no other API call
 * first), fills the caller's payload with 0xee before awaiting, and checks that what was signed
 * is the original payload (ADR 0030 §7). Called first in a fresh runtime, this is the cold case.
 */
export async function payloadCopy(api: PolyjoseApi, what: string): Promise<ProbeCheck> {
  const original = [1, 2, 3, 4, 5, 6, 7, 8];
  const payload = new Uint8Array(original);
  try {
    const pending = api.jwsSignCompact(payload, RFC7515_A1_KEY, { protectedHeader: { alg: "HS256" } });
    payload.fill(0xee);
    const verified = await api.jwsVerifyCompact(await pending, RFC7515_A1_KEY, { allowedAlgs: ["HS256"] });
    const got = Array.from(verified.payload);
    const ok = got.length === original.length && got.every((b, i) => b === original[i]);
    return { what, ok, detail: ok ? "the signed payload is the original" : `signed [${got.join(",")}], expected [${original.join(",")}]` };
  } catch (e) {
    return { what, ok: false, detail: `threw: ${describe(e)}` };
  }
}

export const COLD_COPY = "mutating the payload after the first jwsSignCompact starts doesn't change what is signed (cold)";
export const WARM_COPY = "mutating the payload after jwsSignCompact starts doesn't change what is signed (warm)";

/**
 * Every check above, for the Chrome page and the worker. `cold` says whether this is the
 * runtime's first API call (the caller knows; the facade does not expose it): the input-copy check
 * then runs first, before anything else instantiates the module. A caller that is not cold gets
 * a failing cold check, so a reordering can't silently turn the cold case warm.
 */
export async function securityReport(api: PolyjoseApi, cold: boolean): Promise<ProbeReport> {
  const checks: ProbeCheck[] = [];
  checks.push(cold ? await payloadCopy(api, COLD_COPY) : { what: COLD_COPY, ok: false, detail: "not the first API call of this runtime" });
  checks.push(...(await noInputInErrors(api)));
  checks.push(...(await missingAllowLists(api)));
  checks.push(await payloadCopy(api, WARM_COPY));
  return { ok: checks.every((c) => c.ok), checks };
}

/** The lines a host prints for a {@link securityReport} from `runner`, and whether it passed. */
export function securityLines(runner: string, report: unknown): { ok: boolean; lines: string[] } {
  const r = report as Partial<ProbeReport> | null;
  if (r === null || typeof r !== "object" || !Array.isArray(r.checks)) {
    return { ok: false, lines: [`${runner}: security: FAIL no report (${JSON.stringify(report)})`] };
  }
  const lines = r.checks.map((c) => `${runner}: security: ${c.ok ? "ok" : "FAIL"} ${c.what} (${c.detail})`);
  return { ok: r.ok === true && r.checks.length > 0 && r.checks.every((c) => c.ok), lines };
}
