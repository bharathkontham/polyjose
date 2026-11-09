/**
 * The napi-rs backend of `@polyjose/node` (ADR 0031 §1-§2, `bindings/js/BACKEND.md`; packaging as
 * superseded by the feature 0017 ADR: one package that ships the addon of all eight targets).
 *
 * The native addon `polyjose.<platform>.node` already is the backend contract: one function per
 * ADR 0030 §4 operation, camelCase, in the ADR's argument order, rejecting with an `Error` whose
 * `code` is one of `errorCodes()` (ADR 0030 §5). Its types are the `binding.d.ts` that
 * `napi build --dts` generates. So this module only picks the addon for this host, authenticates
 * it, loads it and gives it the facade's `Backend` type; it adds no JOSE logic and renames nothing
 * (ADR 0030 §1: loading and integrity checks are entry idiom).
 *
 * **No resolving loader (feature 0017; review-security.md M1, feature 0007 F02).** napi-rs's
 * generated loader picks the first module that loads from an override variable, the package
 * directory, every ancestor `node_modules`, `NODE_PATH` and a WASI chain, so a JavaScript or native
 * file planted in any of them could become the crypto backend and "verify" any token. polyjose
 * builds no such loader (`napi build --no-js`) and resolves no module name at all: this file reads
 * only files of its own package directory, `dirname(import.meta.url)`, by absolute path. It never
 * reads `process.env`, so neither `NODE_PATH` nor any `NAPI_RS_*` variable changes what loads.
 *
 * **The steps (the F07 hash-pin model, bindings security audit N-M1, the JVM's 0008 F05 bar):**
 *   1. The platform name (`detectPlatform`): `darwin-<arch>`, `win32-<arch>-msvc`, or
 *      `linux-<arch>-gnu|musl` for x64 and arm64, with napi-rs's names. Any other host is refused
 *      by name, pointing at `@polyjose/wasm`, which runs everywhere.
 *   2. `addon-sha256.json`, in the package directory, maps each shipped platform to its addon's
 *      SHA-256 (FIPS 180-4). It is generated, never hand-edited: `scripts/addon-hashes.sh`, run by
 *      `scripts/build.sh` for a local build and by `scripts/pack-main.sh` over the eight addons the
 *      package ships. No map, a malformed one, or no entry for this host refuses the load: nothing
 *      is trusted by default.
 *   3. It reads `polyjose.<platform>.node` from the package directory once, hashes those bytes with
 *      `node:crypto` and refuses on a mismatch, naming the platform, the file and both hashes.
 *      There is no fallback to another file.
 *   4. It writes the same bytes, with `O_EXCL`, into a new directory from `fs.mkdtempSync` under
 *      `os.tmpdir()` (mode 0700 on POSIX; on Windows the per-user `%TEMP%` ACL), under a random
 *      leaf name (macOS looks a leaf name up in `DYLD_LIBRARY_PATH` before the path), checks the
 *      copy's SHA-256 again, and `require`s that absolute path, which Node's `.node` handler hands
 *      to `dlopen`. So between the check and `dlopen` only this user (who can already change
 *      anything they run) could swap the file; whoever can write the installed package can't. The
 *      copy is deleted right after (a loaded library stays mapped; Windows can't delete a loaded
 *      DLL, so there the copy stays in the temporary directory).
 *   5. What loaded must be the exports of exactly that one module in the CommonJS cache, the
 *      private copy, so no JavaScript module wraps or re-exports it.
 *   6. It must be this package's version: `version()` equals `package.json`'s version, the
 *      workspace version every release keeps in step (feature 0007 T04), so an addon of another
 *      release is refused.
 * Every refusal is an `Error` with `code` `ERR_POLYJOSE_ADDON_REFUSED`. This doesn't defend against
 * code already running in the process, which can patch anything. It makes sure the package never
 * selects a substitute.
 *
 * `test/loader.test.ts` pins what this module loads (its built-ins and its one `require`), the
 * platform detection, and each refusal.
 */

import type { Backend } from "./facade/backend.js";
import type * as Binding from "./binding.js";

// Node built-ins without @types/node (ADR 0047: typescript is the only dev-dependency), as in
// bindings/js/node/builtins.ts; process.getBuiltinModule exists from Node 22.3, under the 22.12 floor.
interface NodeRequire {
  (id: string): unknown;
  readonly cache: Readonly<Record<string, { readonly exports?: unknown } | undefined>>;
}
interface NodeModule {
  createRequire(from: string): NodeRequire;
}
/** The one `fs` call platform detection makes (so tests can fake it). */
interface TextReader {
  readFileSync(path: string, encoding: "utf8"): string;
}
interface NodeFs extends TextReader {
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
  dirname(path: string): string;
}
interface NodeUrl {
  fileURLToPath(url: string): string;
}
interface ProcessReport {
  excludeNetwork: boolean;
  getReport(): { readonly header?: { readonly glibcVersionRuntime?: unknown }; readonly sharedObjects?: unknown } | null;
}
/** What `detectPlatform` reads of `process`. */
interface PlatformHost {
  readonly platform: string;
  readonly arch: string;
  readonly report?: ProcessReport;
}
interface Host extends PlatformHost {
  getBuiltinModule(id: "node:module"): NodeModule;
  getBuiltinModule(id: "node:fs"): NodeFs;
  getBuiltinModule(id: "node:crypto"): NodeCrypto;
  getBuiltinModule(id: "node:os"): NodeOs;
  getBuiltinModule(id: "node:path"): NodePath;
  getBuiltinModule(id: "node:url"): NodeUrl;
}

/** The addon hash map in the package directory (step 2): `{ "<platform>": "<SHA-256, 64 lowercase hex>" }`. */
const PINS = "addon-sha256.json";

/** The `code` of every load refusal. */
const REFUSED = "ERR_POLYJOSE_ADDON_REFUSED";

/**
 * The eight platforms whose addon this package ships (ADR 0031 §2's targets): the only keys a map
 * may have. `test/loader.test.ts` checks them against package.json's `napi.targets` and `files`.
 */
export const PLATFORMS = [
  "darwin-x64",
  "darwin-arm64",
  "linux-x64-gnu",
  "linux-arm64-gnu",
  "linux-x64-musl",
  "linux-arm64-musl",
  "win32-x64-msvc",
  "win32-arm64-msvc",
] as const;

const SHIPPED: readonly string[] = PLATFORMS;

/**
 * A load refusal, with `code` `ERR_POLYJOSE_ADDON_REFUSED`. It names a platform, a file of the
 * package, a version or a SHA-256; never a file's contents.
 */
function refuse(reason: string): never {
  throw Object.assign(new Error(`@polyjose/node: ${reason}`), { code: REFUSED });
}

/**
 * Step 1: this host's platform name, napi-rs's (`napi build --platform` names the addon after it):
 * `darwin-x64|arm64`, `win32-x64|arm64-msvc`, `linux-x64|arm64-gnu|musl`. Any other platform or
 * architecture is `<platform>-<arch>`, which `PLATFORMS` does not list. On Linux it reads
 * /usr/bin/ldd and may take a process report (`isMusl`); it refuses when it cannot tell the libc.
 */
export function detectPlatform(host: PlatformHost, fs: TextReader): string {
  const { platform, arch } = host;
  if (arch !== "x64" && arch !== "arm64") return `${platform}-${arch}`;
  if (platform === "darwin") return `darwin-${arch}`;
  if (platform === "win32") return `win32-${arch}-msvc`;
  if (platform === "linux") return `linux-${arch}-${isMusl(host, fs) ? "musl" : "gnu"}`;
  return `${platform}-${arch}`;
}

/**
 * musl or glibc, decided in napi-rs's order (its generated `isMusl`): `/usr/bin/ldd` names musl
 * or not (glibc ships ldd as a script of its own, musl's runs `ld-musl-*`); if it cannot be read,
 * the process report, taken with `excludeNetwork` set (restored after): a glibc runtime version
 * means glibc, else a `libc.musl-`/`ld-musl-` shared object means musl. napi-rs's last resort,
 * `ldd --version` in a child process, is not run: without a usable report this refuses instead
 * of guessing.
 */
function isMusl(host: PlatformHost, fs: TextReader): boolean {
  try {
    return fs.readFileSync("/usr/bin/ldd", "utf8").includes("musl");
  } catch {
    // Unreadable: ask the process report, as napi-rs does.
  }
  const report = host.report;
  if (report === undefined || typeof report.getReport !== "function") {
    return refuse(`cannot tell glibc from musl on linux-${host.arch} (no /usr/bin/ldd, no process report); refusing to load`);
  }
  const before = report.excludeNetwork;
  report.excludeNetwork = true;
  let r: ReturnType<ProcessReport["getReport"]>;
  try {
    r = report.getReport();
  } finally {
    report.excludeNetwork = before;
  }
  if (r === null || typeof r !== "object") {
    return refuse(`cannot tell glibc from musl on linux-${host.arch} (empty process report); refusing to load`);
  }
  if (r.header?.glibcVersionRuntime) return false;
  const objects = r.sharedObjects;
  const musl = (f: unknown): boolean => typeof f === "string" && (f.includes("libc.musl-") || f.includes("ld-musl-"));
  return Array.isArray(objects) && objects.some(musl);
}

/** Step 2: the package's addon hash map, validated, as a null-prototype record. */
function readPins(fs: NodeFs, file: string): Readonly<Record<string, string>> {
  let text: string;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return refuse(
      "addon-sha256.json is missing, so no native addon is trusted; this package was not assembled by polyjose's build",
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return refuse("addon-sha256.json is not valid JSON; refusing to load");
  }
  const pins: Record<string, string> = Object.create(null) as Record<string, string>;
  const valid =
    typeof parsed === "object" &&
    parsed !== null &&
    !Array.isArray(parsed) &&
    Object.entries(parsed).every(([platform, hash]) => {
      if (!SHIPPED.includes(platform) || typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) return false;
      pins[platform] = hash;
      return true;
    });
  if (!valid) {
    return refuse("addon-sha256.json is not a map of shipped platforms to lowercase SHA-256 hex; refusing to load");
  }
  return pins;
}

/** SHA-256 (FIPS 180-4) of `bytes`, lowercase hex. */
function sha256(crypto: NodeCrypto, bytes: Uint8Array): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

interface Builtins {
  readonly fs: NodeFs;
  readonly crypto: NodeCrypto;
  readonly os: NodeOs;
  readonly path: NodePath;
}

/**
 * Steps 1-4: requires a private, hash-checked copy of this package's addon for this host. Returns
 * what it loaded and the copy's path (the CommonJS cache key, step 5).
 */
function loadPinned(host: Host, req: NodeRequire, b: Builtins, dir: string): { readonly loaded: unknown; readonly copy: string } {
  const platform = detectPlatform(host, b.fs);
  if (!SHIPPED.includes(platform)) {
    return refuse(
      `there is no native addon for ${platform} (this package ships ${SHIPPED.join(", ")}); ` +
        "use @polyjose/wasm, which has the same API and runs on every platform",
    );
  }
  const pins = readPins(b.fs, b.path.join(dir, PINS));
  const expected = pins[platform];
  if (expected === undefined) {
    const listed = Object.keys(pins).sort().join(", ");
    return refuse(
      `this package has no pinned SHA-256 for ${platform} (addon-sha256.json lists ${listed || "none"}); refusing to load`,
    );
  }
  const name = `polyjose.${platform}.node`;
  let bytes: Uint8Array;
  try {
    bytes = b.fs.readFileSync(b.path.join(dir, name));
  } catch {
    return refuse(`./${name} is missing from this package or cannot be read; reinstall @polyjose/node`);
  }
  const actual = sha256(b.crypto, bytes);
  if (actual !== expected) {
    refuse(`./${name} for ${platform} has SHA-256 ${actual}, but this package pins ${expected}; refusing to load it`);
  }
  // The real path, as the CommonJS cache keys it (macOS's tmpdir is a symlink).
  const tmp = b.fs.realpathSync(b.fs.mkdtempSync(b.path.join(b.os.tmpdir(), "polyjose-addon-")));
  try {
    const copy = b.path.join(tmp, `polyjose-${b.crypto.randomBytes(16).toString("hex")}.node`);
    b.fs.writeFileSync(copy, bytes, { flag: "wx", mode: 0o700 });
    if (sha256(b.crypto, b.fs.readFileSync(copy)) !== expected) {
      refuse(`the private copy of the addon for ${platform} does not have the pinned SHA-256; refusing to load it`);
    }
    return { loaded: req(copy), copy };
  } finally {
    try {
      b.fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      // Windows can't delete a DLL while it is loaded; the copy stays in the temporary directory.
    }
  }
}

/** Steps 5-6: the loaded binding is the private copy, at this package's version. */
function checkLoaded(
  req: NodeRequire,
  b: Builtins,
  dir: string,
  loaded: Partial<typeof Binding> | null,
  copy: string,
): typeof Binding {
  if (typeof loaded !== "object" || loaded === null) {
    return refuse("the native addon returned no binding object");
  }
  const owners = Object.keys(req.cache).filter((file) => req.cache[file]?.exports === loaded);
  if (owners.length !== 1 || owners[0] !== copy) {
    refuse("the loaded binding is not exactly the hash-checked native addon; refusing to load");
  }
  let expected: unknown;
  try {
    expected = (JSON.parse(b.fs.readFileSync(b.path.join(dir, "package.json"), "utf8")) as { version?: unknown }).version;
  } catch {
    expected = undefined;
  }
  const actual = typeof loaded.version === "function" ? loaded.version() : undefined;
  if (typeof expected !== "string" || actual !== expected) {
    refuse(`the native addon is version ${String(actual)}, but this package is ${String(expected)}; reinstall it`);
  }
  return loaded as typeof Binding;
}

/** Loads this package's pinned native addon for this host (the module comment). */
function loadBinding(host: Host, moduleUrl: string): typeof Binding {
  const builtins: Builtins = {
    fs: host.getBuiltinModule("node:fs"),
    crypto: host.getBuiltinModule("node:crypto"),
    os: host.getBuiltinModule("node:os"),
    path: host.getBuiltinModule("node:path"),
  };
  // The package directory: backend.js sits at its root, next to the addons and the pins.
  const dir = builtins.path.dirname(host.getBuiltinModule("node:url").fileURLToPath(moduleUrl));
  const req = host.getBuiltinModule("node:module").createRequire(moduleUrl);
  const { loaded, copy } = loadPinned(host, req, builtins, dir);
  return checkLoaded(req, builtins, dir, loaded as Partial<typeof Binding> | null, copy);
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

/** The native addon, typed as the facade's backend. */
export const backend: Backend = (binding satisfies AcceptsFacadeArguments) as unknown as Backend;
