/**
 * The results document of ADR 0034 §2, built inside the runtime under test: the Chrome page
 * (`page.ts`) and the worker (`worker.ts`) both call {@link resultsDocument} with the vectors the
 * Node host collected (`host.ts`), so all three package runs share the shared JS runner
 * (`bindings/js/conformance/runner.ts`) and this file. No Node imports: it runs in browsers and
 * workerd.
 *
 * The document is the one `bindings/js/conformance/node-main.ts` writes for `wasm-pkg-node`:
 * `{ runner, polyjose, features, error_codes, results }`, results sorted by id, features `[]`
 * (the bindings enable no vector feature, ADR 0034 §3), and `error_codes` from the binding
 * (ADR 0034 §8).
 */
import type { PolyjoseApi } from "../js/src/api.js";
import { runVectors, type VectorFile, type VectorResult } from "../js/conformance/runner.js";

/** What the host hands the runtime: the parsed `conformance/schema.json` and the vector files. */
export interface VectorInput {
  readonly schema: unknown;
  readonly files: readonly VectorFile[];
  /** Host-side failures (an unreadable file, a symbolic link), merged into the results as `fail`. */
  readonly failures: readonly VectorResult[];
}

/** The ADR 0034 §2 results file. */
export interface ResultsDocument {
  readonly runner: string;
  readonly polyjose: string;
  readonly features: readonly string[];
  readonly error_codes: readonly string[];
  readonly results: readonly VectorResult[];
}

/** Runs every vector through `api` and returns the results document for `runner`. */
export async function resultsDocument(api: PolyjoseApi, runner: string, input: VectorInput): Promise<ResultsDocument> {
  const features: string[] = [];
  const results = [...(await runVectors(api, input.files, { schema: input.schema, features })), ...input.failures].sort(
    (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  );
  return { runner, polyjose: await api.version(), features, error_codes: [...(await api.errorCodes())], results };
}

/** One check of {@link errorShapeProbe}. */
export interface ProbeCheck {
  readonly what: string;
  readonly ok: boolean;
  readonly detail: string;
}

/** The outcome of {@link errorShapeProbe}; `ok` only if every check passed. */
export interface ProbeReport {
  readonly ok: boolean;
  readonly checks: readonly ProbeCheck[];
}

/**
 * Thrown errors are the facade's `PolyjoseError` in this runtime (ADR 0031 §1, §3): an
 * `instanceof Error` named `PolyjoseError` whose `code` is in `errorCodes()`, and a verify
 * without `allowedAlgs` is `AlgorithmNotAllowed` (RFC 8725 §3.1). The runner already treats any
 * other exception as a failing vector; this checks the shape directly, on each runtime.
 */
export async function errorShapeProbe(api: PolyjoseApi): Promise<ProbeReport> {
  const codes: readonly string[] = await api.errorCodes();
  const key = await api.jwkGenerateOct(32);
  const token = await api.jwsSignCompact(new TextEncoder().encode("probe"), key, { protectedHeader: { alg: "HS256" } });
  const cases: readonly { what: string; call: () => Promise<unknown>; code?: string }[] = [
    { what: "base64urlDecode of a non-base64url string", call: () => api.base64urlDecode("not base64url!") },
    { what: "jwkParse of a JWK without kty", call: () => api.jwkParse({ k: "AAAA" } as never) },
    {
      what: "jwsVerifyCompact without allowedAlgs",
      call: () => api.jwsVerifyCompact(token, key, {} as never),
      code: "AlgorithmNotAllowed",
    },
  ];
  const checks: ProbeCheck[] = [];
  for (const c of cases) {
    let thrown: unknown;
    let resolved = false;
    try {
      await c.call();
      resolved = true;
    } catch (e) {
      thrown = e;
    }
    if (resolved) {
      checks.push({ what: c.what, ok: false, detail: "resolved; expected a PolyjoseError" });
      continue;
    }
    const e = thrown;
    const ok =
      e instanceof api.PolyjoseError &&
      e instanceof Error &&
      e.name === "PolyjoseError" &&
      codes.includes(e.code) &&
      (c.code === undefined || e.code === c.code);
    const detail =
      e instanceof Error ? `${e.name} code=${String((e as { code?: unknown }).code)} instanceof PolyjoseError=${String(e instanceof api.PolyjoseError)}` : String(e);
    checks.push({ what: c.what, ok, detail });
  }
  return { ok: checks.every((c) => c.ok), checks };
}
