/**
 * The napi-rs backend of `@polyjose/node` (ADR 0031 §1-§2, `bindings/js/BACKEND.md`).
 *
 * The generated loader `binding.cjs` (`napi build --platform --js binding.cjs`) already is the
 * backend contract: one function per ADR 0030 §4 operation, camelCase, in the ADR's argument
 * order, rejecting with an `Error` whose `code` is one of `errorCodes()` (ADR 0030 §5). So this
 * module only loads it, checks what it loaded and gives it the facade's `Backend` type; it adds no
 * JOSE logic and renames nothing (ADR 0030 §1: loading and integrity checks are entry idiom).
 *
 * The loader is CommonJS (it picks the platform's `.node` file at run time), loaded here through
 * `createRequire`, so the package stays ESM-only (ADR 0031 §3). Its types come from the generated
 * `binding.d.ts`.
 *
 * **Fail closed (feature 0007 F02, review-code.md SF-4).** The napi-rs CLI 3.10.12 template always
 * emits a WASI fallback, and no `napi build` option omits it: when the native load fails, or when
 * `NAPI_RS_FORCE_WASI` / `NAPI_RS_WASI_FLAVOR` asks for it, the loader goes on to
 * `./polyjose.wasi.cjs` and then the package `@polyjose/node-wasm32-wasi`. polyjose publishes no
 * WASI build (ADR 0031 §2 ships eight native targets; `@polyjose/wasm` is the separate WASM
 * package), so anything that chain could load is not ours. The generated file is never edited;
 * this module wraps it instead:
 *   1. it refuses to load at all while either WASI variable is set, whatever its value;
 *   2. it refuses while any WASI candidate resolves from the loader's directory, resolved exactly
 *      as the loader's own `require.resolve` would (the same directory, `node_modules` walk and
 *      `NODE_PATH`), so the loader's WASI branch can never find anything.
 * `test/loader.test.ts` pins the loader's load targets, so a CLI bump that adds a candidate fails
 * there before it can be missed here.
 */

import type { Backend } from "./facade/backend.js";
import type * as Binding from "./binding.js";

// Node built-ins without @types/node (ADR 0047: typescript is the only dev-dependency), as in
// bindings/js/node/builtins.ts; process.getBuiltinModule exists from Node 22.3, under the 22.12 floor.
interface NodeRequire {
  (id: string): unknown;
  resolve(id: string): string;
}
interface NodeModule {
  createRequire(from: string): NodeRequire;
}
interface Host {
  readonly env: Readonly<Record<string, string | undefined>>;
  getBuiltinModule(id: "node:module"): NodeModule;
}

/** The loader's WASI switches: `NAPI_RS_FORCE_WASI` (`true`, `error`) and `NAPI_RS_WASI_FLAVOR`. */
const WASI_VARIABLES = ["NAPI_RS_FORCE_WASI", "NAPI_RS_WASI_FLAVOR"] as const;

/**
 * Everything the loader's WASI chain resolves before it loads (binding.cjs,
 * `__napiWasiResolveCandidate`): the local loader and the package, whose `package.json` alone
 * already proves it is installed.
 */
const WASI_CANDIDATES = [
  "./polyjose.wasi.cjs",
  "@polyjose/node-wasm32-wasi",
  "@polyjose/node-wasm32-wasi/package.json",
] as const;

/** A load refusal. It names a variable, a specifier or a version; never a path's contents. */
function refuse(reason: string): never {
  throw new Error(`@polyjose/node: ${reason}`);
}

/**
 * Whether `id` resolves from the loader's directory. Only `MODULE_NOT_FOUND` means absent; any
 * other failure (an `exports` restriction, an unreadable directory) counts as present.
 */
function resolves(req: NodeRequire, id: string): boolean {
  try {
    req.resolve(id);
    return true;
  } catch (err) {
    return (err as { code?: unknown } | null)?.code !== "MODULE_NOT_FOUND";
  }
}

/** Loads `binding.cjs` only when its WASI chain is unreachable (see the module comment). */
function loadBinding(host: Host, moduleUrl: string): typeof Binding {
  for (const name of WASI_VARIABLES) {
    if (host.env[name] !== undefined) {
      refuse(`${name} is set, but polyjose publishes no WASI build; unset it to load the native addon`);
    }
  }
  // backend.js and binding.cjs are siblings, so this resolves exactly as the loader does.
  const req = host.getBuiltinModule("node:module").createRequire(moduleUrl);
  for (const id of WASI_CANDIDATES) {
    if (resolves(req, id)) {
      refuse(`${id} resolves next to the loader, but polyjose publishes no WASI build; remove it`);
    }
  }
  return req("./binding.cjs") as typeof Binding;
}

const binding = loadBinding(
  (globalThis as unknown as { process: Host }).process,
  (import.meta as unknown as { url: string }).url,
);

/**
 * Every `Backend` operation exists in the binding, under the same name, and accepts the arguments
 * the facade passes (checked at compile time against the generated `binding.d.ts`). The binding
 * declares its results as `Promise<unknown>` (its tasks resolve through a conversion trait), so
 * the result types are the contract's (BACKEND.md), proven by the conformance run.
 */
type AcceptsFacadeArguments = {
  readonly [K in Exclude<keyof Backend, "ready">]: (...args: Parameters<Backend[K]>) => unknown;
};

/** The napi loader, typed as the facade's backend. */
export const backend: Backend = (binding satisfies AcceptsFacadeArguments) as unknown as Backend;
