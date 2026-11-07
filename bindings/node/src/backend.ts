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
 * **Fail closed (feature 0007 F02; review-code.md SF-4, review-security.md M1).** The generated
 * loader returns the first module that loads, of any kind:
 *   - `NAPI_RS_NATIVE_LIBRARY_PATH`, if set;
 *   - then `./polyjose.<platform>.node` next to it;
 *   - then `require('@polyjose/node-<platform>')`, which walks every ancestor `node_modules` and
 *     `NODE_PATH`;
 *   - then a WASI chain: `./polyjose.wasi.cjs`, then `@polyjose/node-wasm32-wasi`. The napi-rs CLI
 *     3.10.12 template always emits it; no `napi build` option omits it, and
 *     `NAPI_RS_FORCE_WASI` / `NAPI_RS_WASI_FLAVOR` can select it.
 * It stamps a JavaScript module found that way `"native"` too. So a JS file planted in an
 * ancestor directory or on `NODE_PATH` would become the crypto backend and could "verify" any
 * token. polyjose publishes only native addons (ADR 0031 §2: eight targets, no WASI build;
 * `@polyjose/wasm` is a separate package). The generated file is never edited; this module wraps
 * it and accepts nothing else.
 *
 * **Before loading,** nothing runs unless every module the loader could pick is a native addon:
 *   1. Neither WASI variable is set, whatever its value.
 *   2. No WASI candidate resolves.
 *   3. Every native candidate that resolves is a `.node` file: the override path, and for every
 *      platform the loader probes, `./polyjose.<platform>.node` and `@polyjose/node-<platform>`.
 *      `@polyjose/node-<platform>/package.json`, which the loader also reads, must be a
 *      `package.json`.
 * Resolution is the loader's own: `backend.js` sits next to `binding.cjs`, and `require.resolve`
 * uses the same directory, `node_modules` walk, `NODE_PATH` and symlink handling as the loader's
 * `require`, and runs no code. Node loads a `.node` file only as a native addon, never as
 * JavaScript.
 *
 * **After loading,** what the loader returned must be:
 *   4. the exports of exactly one `.node` module in the CommonJS cache, shared only with a loader
 *      (`binding.cjs`), so no JavaScript module wraps or re-exports it;
 *   5. stamped `__napiBindingTarget === "native"`;
 *   6. at this package's version: `version()` must equal `package.json`'s version. That is the
 *      workspace version, which every release keeps in step (feature 0007 T04). So an addon from
 *      another release is refused, whatever `NAPI_RS_ENFORCE_VERSION_CHECK` says (SF-4 item 3).
 * This doesn't defend against code already running in the process, which can patch anything.
 * It makes sure the package never selects a substitute.
 *
 * `test/loader.test.ts` pins the loader's load targets and checks `LOADER_PLATFORMS` against them.
 * So a CLI bump that adds a candidate fails there before this module can miss it.
 */

import type { Backend } from "./facade/backend.js";
import type * as Binding from "./binding.js";

// Node built-ins without @types/node (ADR 0047: typescript is the only dev-dependency), as in
// bindings/js/node/builtins.ts; process.getBuiltinModule exists from Node 22.3, under the 22.12 floor.
interface NodeRequire {
  (id: string): unknown;
  resolve(id: string): string;
  readonly cache: Readonly<Record<string, { readonly exports?: unknown } | undefined>>;
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

/**
 * Every platform name the generated loader probes: the eight polyjose publishes (ADR 0031 §2) and
 * the napi-rs template's others, which are never published. `test/loader.test.ts` checks that this
 * is exactly the loader's set.
 */
export const LOADER_PLATFORMS = [
  "darwin-x64",
  "darwin-arm64",
  "linux-x64-gnu",
  "linux-arm64-gnu",
  "linux-x64-musl",
  "linux-arm64-musl",
  "win32-x64-msvc",
  "win32-arm64-msvc",
  "android-arm64",
  "android-arm-eabi",
  "win32-x64-gnu",
  "win32-ia32-msvc",
  "darwin-universal",
  "freebsd-x64",
  "freebsd-arm64",
  "freebsd-ppc64",
  "linux-arm-musleabihf",
  "linux-arm-gnueabihf",
  "linux-loong64-musl",
  "linux-loong64-gnu",
  "linux-riscv64-musl",
  "linux-riscv64-gnu",
  "linux-ppc64-gnu",
  "linux-s390x-gnu",
  "openharmony-arm64",
  "openharmony-x64",
  "openharmony-arm",
] as const;

/** A load refusal. It names a variable, a specifier or a version; never a path's contents. */
function refuse(reason: string): never {
  throw new Error(`@polyjose/node: ${reason}`);
}

/**
 * Where `id` resolves from the loader's directory: the file, or `null` when it is absent. Only
 * `MODULE_NOT_FOUND` means absent. Any other failure, such as an `exports` restriction or an
 * unreadable directory, is a refusal.
 */
function resolved(req: NodeRequire, id: string): string | null {
  try {
    return req.resolve(id);
  } catch (err) {
    if ((err as { code?: unknown } | null)?.code === "MODULE_NOT_FOUND") return null;
    return refuse(`${id} cannot be resolved cleanly, so it cannot be checked; refusing to load`);
  }
}

/** Steps 1-3 of the module comment: every module the loader could pick is a native addon. */
function checkCandidates(host: Host, req: NodeRequire): void {
  for (const name of WASI_VARIABLES) {
    if (host.env[name] !== undefined) {
      refuse(`${name} is set, but polyjose publishes no WASI build; unset it to load the native addon`);
    }
  }
  for (const id of WASI_CANDIDATES) {
    if (resolved(req, id) !== null) {
      refuse(`${id} resolves next to the loader, but polyjose publishes no WASI build; remove it`);
    }
  }
  // The loader tests the override for truthiness, so an empty value means "not set".
  const override = host.env["NAPI_RS_NATIVE_LIBRARY_PATH"];
  if (override !== undefined && override !== "") {
    const file = resolved(req, override);
    if (file === null || !file.endsWith(".node")) {
      refuse("NAPI_RS_NATIVE_LIBRARY_PATH does not name a native .node addon; refusing to load");
    }
  }
  for (const platform of LOADER_PLATFORMS) {
    for (const id of [`./polyjose.${platform}.node`, `@polyjose/node-${platform}`]) {
      const file = resolved(req, id);
      if (file !== null && !file.endsWith(".node")) {
        refuse(`${id} resolves to a file that is not a native .node addon; refusing to load`);
      }
    }
    const manifest = resolved(req, `@polyjose/node-${platform}/package.json`);
    if (manifest !== null && !/[\\/]package\.json$/.test(manifest)) {
      refuse(`@polyjose/node-${platform}/package.json resolves to another file; refusing to load`);
    }
  }
}

/** Steps 4-6 of the module comment: the loaded binding is this release's native addon. */
function checkLoaded(req: NodeRequire, loaded: Partial<typeof Binding> | null): typeof Binding {
  if (typeof loaded !== "object" || loaded === null) {
    return refuse("the loader returned no binding object");
  }
  const owners = Object.keys(req.cache).filter((file) => req.cache[file]?.exports === loaded);
  const addons = owners.filter((file) => file.endsWith(".node"));
  // A second copy of this package (another path, same platform package) has its own binding.cjs.
  const others = owners.filter((file) => !file.endsWith(".node") && !/[\\/]binding\.cjs$/.test(file));
  if (addons.length !== 1 || others.length !== 0) {
    refuse("the loaded binding is not exactly one native .node addon; refusing to load");
  }
  if (loaded.__napiBindingTarget !== "native") {
    refuse('the loaded binding is not the native addon (__napiBindingTarget is not "native")');
  }
  const expected = (req("./package.json") as { version?: unknown }).version;
  const actual = typeof loaded.version === "function" ? loaded.version() : undefined;
  if (typeof expected !== "string" || actual !== expected) {
    refuse(`the native addon is version ${String(actual)}, but this package is ${String(expected)}; reinstall it`);
  }
  return loaded as typeof Binding;
}

/** Loads `binding.cjs` only when it can load nothing but the native addon (the module comment). */
function loadBinding(host: Host, moduleUrl: string): typeof Binding {
  // backend.js and binding.cjs are siblings, so this resolves exactly as the loader does.
  const req = host.getBuiltinModule("node:module").createRequire(moduleUrl);
  checkCandidates(host, req);
  return checkLoaded(req, req("./binding.cjs") as Partial<typeof Binding> | null);
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
