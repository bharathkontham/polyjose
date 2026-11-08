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
 * **The hash pin (feature 0007 F07; bindings security audit N-M1, the JVM's 0008 F05 bar).** Steps
 * 1-6 make sure the package loads a native addon at this version, but `version()` is what the
 * addon itself says, and a native addon is as easy to plant as a JavaScript file. So before the
 * loader runs, this module also *authenticates* the addon:
 *   a. `addon-sha256.json`, next to this file, maps each platform polyjose built this package for
 *      to its addon's SHA-256 (FIPS 180-4). It is generated, never hand-edited:
 *      `scripts/addon-hashes.sh`, run by `scripts/build.sh` for a local build and by the release
 *      assembly of the main package for every published platform. No map, a malformed one, or no
 *      entry for this host refuses the load: nothing is trusted by default.
 *   b. It picks the one file the loader would load on this host (the platform name of
 *      `hostPlatform`, the loader's own): `NAPI_RS_NATIVE_LIBRARY_PATH` when set, else
 *      `./polyjose.<platform>.node`, else `@polyjose/node-<platform>`, resolved as above. A
 *      caller's override is not refused; it is held to the same pin.
 *   c. It reads that file once, hashes those bytes with `node:crypto` and refuses on a mismatch,
 *      naming the platform, the source and both hashes. There is no fallback to another candidate.
 *   d. It writes the same bytes, with `O_EXCL`, into a new directory from `fs.mkdtempSync` under
 *      `os.tmpdir()` (mode 0700 on POSIX; on Windows the per-user `%TEMP%` ACL), under a random
 *      leaf name (macOS looks a leaf name up in `DYLD_LIBRARY_PATH` before the path), checks the
 *      copy's SHA-256 again, and points `NAPI_RS_NATIVE_LIBRARY_PATH` at it for the one
 *      synchronous `require("./binding.cjs")`. The loader's override branch loads exactly that
 *      path and probes nothing else, so between the check and `dlopen` only this user (who can
 *      already change anything they run) could swap the file; whoever can write the installed
 *      file or an ancestor `node_modules` can't. The caller's environment is restored right
 *      after, and the copy is deleted (a loaded library stays mapped; Windows can't delete a
 *      loaded DLL, so there the copy stays in the temporary directory).
 *
 * **After loading,** what the loader returned must be:
 *   4. the exports of exactly one `.node` module in the CommonJS cache, the private copy of step
 *      d, shared only with a loader (`binding.cjs`), so no JavaScript module wraps or re-exports
 *      it, and a `binding.cjs` that other code required first (with its own addon) is refused;
 *   5. stamped `__napiBindingTarget === "native"`;
 *   6. at this package's version: `version()` must equal `package.json`'s version. That is the
 *      workspace version, which every release keeps in step (feature 0007 T04). So an addon from
 *      another release is refused, whatever `NAPI_RS_ENFORCE_VERSION_CHECK` says (SF-4 item 3).
 * Every refusal is an `Error` with `code` `ERR_POLYJOSE_ADDON_REFUSED`. This doesn't defend against
 * code already running in the process, which can patch anything. It makes sure the package never
 * selects a substitute.
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
interface NodeFs {
  readFileSync(path: string): Uint8Array;
  readFileSync(path: string, encoding: "utf8"): string;
  writeFileSync(path: string, data: Uint8Array, options: { readonly flag: "wx"; readonly mode: number }): void;
  mkdtempSync(prefix: string): string;
  realpathSync(path: string): string;
  rmSync(path: string, options: { readonly recursive: true; readonly force: true }): void;
}
interface NodeCrypto {
  createHash(algorithm: "sha256"): { update(data: Uint8Array): { digest(encoding: "hex"): string } };
  randomBytes(size: number): { toString(encoding: "hex"): string };
}
interface NodeOs {
  tmpdir(): string;
}
interface NodePath {
  join(...parts: string[]): string;
}
interface ProcessReport {
  excludeNetwork: boolean;
  getReport(): { readonly header?: { readonly glibcVersionRuntime?: unknown }; readonly sharedObjects?: unknown } | null;
}
interface Host {
  readonly env: Record<string, string | undefined>;
  readonly platform: string;
  readonly arch: string;
  readonly config?: { readonly variables?: { readonly shlib_suffix?: unknown; readonly node_target_type?: unknown } };
  readonly report?: ProcessReport;
  getBuiltinModule(id: "node:module"): NodeModule;
  getBuiltinModule(id: "node:fs"): NodeFs;
  getBuiltinModule(id: "node:crypto"): NodeCrypto;
  getBuiltinModule(id: "node:os"): NodeOs;
  getBuiltinModule(id: "node:path"): NodePath;
}

/** The loader's override variable: a path it `require`s instead of probing (binding.cjs `requireNative`). */
const OVERRIDE = "NAPI_RS_NATIVE_LIBRARY_PATH";

/** The addon hash map next to this file (step a): `{ "<platform>": "<SHA-256, 64 lowercase hex>" }`. */
const PINS = "./addon-sha256.json";

/** The `code` of every load refusal (step c's mismatch included). */
const REFUSED = "ERR_POLYJOSE_ADDON_REFUSED";

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

/** The eight platforms polyjose publishes an addon for (ADR 0031 §2): the only keys a map may have. */
const PUBLISHED_PLATFORMS: readonly string[] = [
  "darwin-x64",
  "darwin-arm64",
  "linux-x64-gnu",
  "linux-arm64-gnu",
  "linux-x64-musl",
  "linux-arm64-musl",
  "win32-x64-msvc",
  "win32-arm64-msvc",
];

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

/**
 * A load refusal, with `code` `ERR_POLYJOSE_ADDON_REFUSED`. It names a variable, a specifier, a
 * platform, a version or a SHA-256; never a path's contents.
 */
function refuse(reason: string): never {
  throw Object.assign(new Error(`@polyjose/node: ${reason}`), { code: REFUSED });
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
  const override = host.env[OVERRIDE];
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

/**
 * The loader's platform name for this host, as binding.cjs `requireNative` computes it for the
 * eight published platforms; any other host gets `<platform>-<arch>`, which no map lists.
 */
function hostPlatform(host: Host, fs: NodeFs): string {
  const { platform, arch } = host;
  if (arch !== "x64" && arch !== "arm64") return `${platform}-${arch}`;
  if (platform === "darwin") return `darwin-${arch}`;
  if (platform === "linux") return `linux-${arch}-${isMusl(host, fs) ? "musl" : "gnu"}`;
  if (platform === "win32") {
    // The loader sends these Windows x64 hosts to win32-x64-gnu, which polyjose doesn't publish.
    const v = host.config?.variables;
    if (arch === "x64" && (v?.shlib_suffix === "dll.a" || v?.node_target_type === "shared_library")) return "win32-x64-gnu";
    return `win32-${arch}-msvc`;
  }
  return `${platform}-${arch}`;
}

/**
 * musl or glibc, decided as the loader's `isMusl` decides it, in its order: `/usr/bin/ldd` names
 * musl or not; else the process report (setting `excludeNetwork` first, as the loader does): a
 * glibc runtime version means glibc, a `libc.musl-`/`ld-musl-` shared object means musl. The
 * loader's last resort, `ldd --version` in a child process, is not run: without a report this
 * refuses instead of guessing.
 */
function isMusl(host: Host, fs: NodeFs): boolean {
  try {
    return fs.readFileSync("/usr/bin/ldd", "utf8").includes("musl");
  } catch {
    // Unreadable: ask the process report, as the loader does.
  }
  const report = host.report;
  if (report === undefined || typeof report.getReport !== "function") {
    return refuse("cannot tell glibc from musl (no /usr/bin/ldd, no process report); refusing to load");
  }
  report.excludeNetwork = true;
  const r = report.getReport();
  if (r === null || typeof r !== "object") return refuse("cannot tell glibc from musl (empty process report)");
  if (r.header?.glibcVersionRuntime) return false;
  const objects = r.sharedObjects;
  const musl = (f: unknown): boolean => typeof f === "string" && (f.includes("libc.musl-") || f.includes("ld-musl-"));
  return Array.isArray(objects) && objects.some(musl);
}

/** Step a: the package's addon hash map, validated, as a null-prototype record. */
function readPins(req: NodeRequire, fs: NodeFs): Readonly<Record<string, string>> {
  const file = resolved(req, PINS);
  if (file === null) {
    return refuse(
      "addon-sha256.json is missing, so no native addon is trusted; this package was not assembled by polyjose's build",
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return refuse("addon-sha256.json is not valid JSON; refusing to load");
  }
  const pins: Record<string, string> = Object.create(null) as Record<string, string>;
  const valid =
    typeof parsed === "object" &&
    parsed !== null &&
    !Array.isArray(parsed) &&
    Object.entries(parsed).every(([platform, hash]) => {
      if (!PUBLISHED_PLATFORMS.includes(platform) || typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) return false;
      pins[platform] = hash;
      return true;
    });
  if (!valid) {
    return refuse("addon-sha256.json is not a map of published platforms to lowercase SHA-256 hex; refusing to load");
  }
  return pins;
}

/** SHA-256 (FIPS 180-4) of `bytes`, lowercase hex. */
function sha256(crypto: NodeCrypto, bytes: Uint8Array): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

/** Step b: the one file the loader would load on this host, and how it was named. */
function pickSource(host: Host, req: NodeRequire, platform: string): { readonly file: string; readonly name: string } {
  const override = host.env[OVERRIDE];
  const overridden = override !== undefined && override !== "";
  const ids = overridden ? [override] : [`./polyjose.${platform}.node`, `@polyjose/node-${platform}`];
  for (const id of ids) {
    const file = resolved(req, id);
    if (file !== null) return { file, name: overridden ? OVERRIDE : id };
  }
  return refuse(`no native addon for ${platform} is installed (@polyjose/node-${platform}); reinstall without --omit=optional`);
}

interface Builtins {
  readonly fs: NodeFs;
  readonly crypto: NodeCrypto;
  readonly os: NodeOs;
  readonly path: NodePath;
}

/**
 * Steps a-d: loads `binding.cjs` with the override pointing at a private, hash-checked copy of
 * the addon. Returns what it loaded and the copy's path (the CommonJS cache key, step 4).
 */
function loadPinned(host: Host, req: NodeRequire, b: Builtins): { readonly loaded: unknown; readonly copy: string } {
  const pins = readPins(req, b.fs);
  const platform = hostPlatform(host, b.fs);
  const expected = pins[platform];
  if (expected === undefined) {
    const listed = Object.keys(pins).sort().join(", ");
    return refuse(
      `this package has no pinned SHA-256 for ${platform} (addon-sha256.json lists ${listed || "none"}); refusing to load`,
    );
  }
  const source = pickSource(host, req, platform);
  const bytes = b.fs.readFileSync(source.file);
  const actual = sha256(b.crypto, bytes);
  if (actual !== expected) {
    refuse(`${source.name} for ${platform} has SHA-256 ${actual}, but this package pins ${expected}; refusing to load it`);
  }
  // The real path, as the CommonJS cache keys it (macOS's tmpdir is a symlink).
  const dir = b.fs.realpathSync(b.fs.mkdtempSync(b.path.join(b.os.tmpdir(), "polyjose-addon-")));
  try {
    const copy = b.path.join(dir, `polyjose-${b.crypto.randomBytes(16).toString("hex")}.node`);
    b.fs.writeFileSync(copy, bytes, { flag: "wx", mode: 0o700 });
    if (sha256(b.crypto, b.fs.readFileSync(copy)) !== expected) {
      refuse(`the private copy of the addon for ${platform} does not have the pinned SHA-256; refusing to load it`);
    }
    const previous = host.env[OVERRIDE];
    host.env[OVERRIDE] = copy;
    try {
      return { loaded: req("./binding.cjs"), copy };
    } finally {
      if (previous === undefined) delete host.env[OVERRIDE];
      else host.env[OVERRIDE] = previous;
    }
  } finally {
    try {
      b.fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // Windows can't delete a DLL while it is loaded; the copy stays in the temporary directory.
    }
  }
}

/** Steps 4-6 of the module comment: the loaded binding is this release's native addon. */
function checkLoaded(req: NodeRequire, loaded: Partial<typeof Binding> | null, copy: string): typeof Binding {
  if (typeof loaded !== "object" || loaded === null) {
    return refuse("the loader returned no binding object");
  }
  const owners = Object.keys(req.cache).filter((file) => req.cache[file]?.exports === loaded);
  const addons = owners.filter((file) => file.endsWith(".node"));
  // A second copy of this package (another path, same platform package) has its own binding.cjs.
  const others = owners.filter((file) => !file.endsWith(".node") && !/[\\/]binding\.cjs$/.test(file));
  if (addons.length !== 1 || addons[0] !== copy || others.length !== 0) {
    refuse("the loaded binding is not exactly the hash-checked native addon; refusing to load");
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

/** Loads `binding.cjs` only when it can load nothing but the pinned native addon (the module comment). */
function loadBinding(host: Host, moduleUrl: string): typeof Binding {
  // backend.js and binding.cjs are siblings, so this resolves exactly as the loader does.
  const req = host.getBuiltinModule("node:module").createRequire(moduleUrl);
  checkCandidates(host, req);
  const builtins: Builtins = {
    fs: host.getBuiltinModule("node:fs"),
    crypto: host.getBuiltinModule("node:crypto"),
    os: host.getBuiltinModule("node:os"),
    path: host.getBuiltinModule("node:path"),
  };
  const { loaded, copy } = loadPinned(host, req, builtins);
  return checkLoaded(req, loaded as Partial<typeof Binding> | null, copy);
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
