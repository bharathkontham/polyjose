/**
 * [WASM-pkg-workerd] The worker of `loader-integrity.test.ts`'s workerd cases (feature 0006 F05,
 * security audit L1), and the helpers that test shares with its Node child cases. It imports
 * nothing from Node.
 *
 * `GET /<case>` runs one case of the audit's scenario in a fresh workerd (the driver starts one
 * miniflare per case, since the glue's state is per isolate). The modules are imported
 * dynamically, in the case's order, by their names in the bundle: `/node_modules/@polyjose/wasm/…`
 * is the package as wrangler uploads it, so `polyjose_wasm.js` and `backend.js` there are the very
 * modules `workerd.mjs` imports, which is the in-realm route of L1. `/f05/forged.wasm` is the
 * other module the driver adds, compiled by workerd as a `CompiledWasm` module, because Workers
 * can't compile wasm from bytes at run time.
 */

/** The package API, structurally (this file can't name `@polyjose/wasm`'s types by import). */
export interface LoaderApi {
  jwkGenerateOct(lenBytes: number): Promise<unknown>;
  jwsSignCompact(payload: Uint8Array, key: unknown, options: { protectedHeader: { alg: string } }): Promise<string>;
  jwsVerifyCompact(token: string, key: unknown, options: { allowedAlgs: string[] }): Promise<unknown>;
  base64urlEncode(bytes: Uint8Array): Promise<string>;
}

/** The glue, as a by-name importer sees it (wasm-bindgen 0.2.130 `--target web`). */
interface Glue {
  initSync(module: unknown): unknown;
  default(moduleOrPath: unknown): Promise<unknown>;
}

/** `backend.js`, as a by-name importer sees it. */
interface BackendFile {
  setLoader(load: () => unknown): void;
}

/** The message of a rejection, as `<name>: <message>`, or "resolved". */
export async function outcome(call: () => Promise<unknown>): Promise<string> {
  try {
    await call();
    return "resolved";
  } catch (e) {
    return e instanceof Error ? `${e.name}: ${e.message}` : String(e);
  }
}

/**
 * A genuine HS256 token verifies (`genuine` is "resolved"), and one signed by another key is
 * refused (`otherKey` is its error code, or "VERIFIED"; RFC 7515 §5.2).
 */
export async function verifies(api: LoaderApi): Promise<{ genuine: string; otherKey: string }> {
  const key = await api.jwkGenerateOct(32);
  const other = await api.jwkGenerateOct(32);
  const payload = new TextEncoder().encode('{"admin":false}');
  const token = await api.jwsSignCompact(payload, key, { protectedHeader: { alg: "HS256" } });
  const foreign = await api.jwsSignCompact(payload, other, { protectedHeader: { alg: "HS256" } });
  const genuine = await outcome(() => api.jwsVerifyCompact(token, key, { allowedAlgs: ["HS256"] }));
  let otherKey: string;
  try {
    await api.jwsVerifyCompact(foreign, key, { allowedAlgs: ["HS256"] });
    otherKey = "VERIFIED";
  } catch (e) {
    const code = typeof e === "object" && e !== null && Object.hasOwn(e, "code") ? (e as { code: unknown }).code : undefined;
    otherKey = typeof code === "string" ? code : String(e);
  }
  return { genuine, otherKey };
}

/** Calls after a refused initialisation: each must be refused too. */
export async function refusedCalls(api: LoaderApi): Promise<Record<string, string>> {
  return {
    first: await outcome(() => api.jwkGenerateOct(32)),
    second: await outcome(() => api.base64urlEncode(new Uint8Array([1]))),
    verify: await outcome(() => api.jwsVerifyCompact("e30.e30.AAAA", { kty: "oct", k: "AAAAAAAAAAAAAAAAAAAAAA" }, { allowedAlgs: ["HS256"] })),
  };
}

const PACKAGE = "/node_modules/@polyjose/wasm";

/** A dynamic import by a name held in a variable, so tsc doesn't resolve it. */
async function load<T>(name: string): Promise<T> {
  return (await import(name)) as T;
}

async function forged(): Promise<WebAssembly.Module> {
  return (await load<{ default: WebAssembly.Module }>("/f05/forged.wasm")).default;
}

async function run(name: string): Promise<Record<string, unknown>> {
  const report: Record<string, unknown> = { case: name };
  switch (name) {
    case "clean":
      return { ...report, ...(await verifies(await load<LoaderApi>(`${PACKAGE}/workerd.mjs`))) };
    case "pre-init-sync":
    case "pre-init-async": {
      const glue = await load<Glue>(`${PACKAGE}/polyjose_wasm.js`);
      const module = await forged();
      if (name === "pre-init-sync") glue.initSync({ module });
      else void glue.default({ module_or_path: module }).catch(() => undefined); // still pending
      return { ...report, ...(await refusedCalls(await load<LoaderApi>(`${PACKAGE}/workerd.mjs`))) };
    }
    case "set-loader-after": {
      const api = await load<LoaderApi>(`${PACKAGE}/workerd.mjs`);
      const backend = await load<BackendFile>(`${PACKAGE}/backend.js`);
      const module = await forged();
      let called = false;
      const evil = (): unknown => {
        called = true;
        return module;
      };
      report["beforeFirstCall"] = await outcome(async () => backend.setLoader(evil));
      Object.assign(report, await verifies(api));
      report["afterFirstCall"] = await outcome(async () => backend.setLoader(evil));
      report["evilCalled"] = called;
      return report;
    }
    case "set-loader-first": {
      const backend = await load<BackendFile>(`${PACKAGE}/backend.js`);
      const module = await forged();
      let called = false;
      backend.setLoader(() => {
        called = true;
        return module;
      });
      report["import"] = await outcome(() => load(`${PACKAGE}/workerd.mjs`));
      report["evilCalled"] = called;
      return report;
    }
    default:
      throw new Error(`unknown case ${name}`);
  }
}

export default {
  async fetch(request: Request): Promise<Response> {
    try {
      const report = await run(new URL(request.url).pathname.slice(1));
      return new Response(JSON.stringify(report), { headers: { "content-type": "application/json; charset=utf-8" } });
    } catch (e) {
      return new Response(e instanceof Error ? `${e.name}: ${e.message}\n${e.stack ?? ""}` : String(e), { status: 500 });
    }
  },
};
