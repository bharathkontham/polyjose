// How @polyjose/node loads its native addon (feature 0017 T01; feature 0007 F02 and F07;
// review-code.md SF-4; review-security.md M1; bindings audit N-M1; ADR 0031 §2 as superseded by
// the 0017 ADR), run with `node --test` against the built package (ADR 0047):
//   - the load surface: backend.js runs no generated loader and resolves nothing. It reads files
//     of its own package directory, and its one `require` loads the private copy of the addon by
//     absolute path. The set of built-ins and require targets is pinned here, so a change that
//     adds a candidate (a platform package, `NODE_PATH`, an override variable) fails here first;
//   - platform detection: darwin, win32 msvc, and Linux gnu vs musl (/usr/bin/ldd, then the
//     process report, napi-rs's order), with an unsupported platform refused by name;
//   - the hash pin (F07): only `polyjose.<host>.node` from the package directory, whose SHA-256 is
//     the one addon-sha256.json pins for the host, loads, from a private copy, and nothing planted
//     in an ancestor node_modules, on NODE_PATH, at NAPI_RS_NATIVE_LIBRARY_PATH or as a WASI
//     candidate ever runs. Each case runs in a child process on a temporary copy of the package.
import { assert, path, test } from "../../js/dist/node/builtins.js";
import { PLATFORMS, backend, detectPlatform } from "../backend.js";

// Node built-ins without @types/node (ADR 0047), typed with only what this file calls.
interface SpawnResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: Error;
}
interface NodeChildProcess {
  spawnSync(
    file: string,
    args: readonly string[],
    options: { env: Record<string, string>; encoding: "utf8"; cwd: string },
  ): SpawnResult;
}
interface NodeFs {
  readFileSync(path: string, encoding: "utf8"): string;
  readFileSync(path: string): Uint8Array;
  writeFileSync(path: string, data: string | Uint8Array): void;
  mkdirSync(path: string, options: { recursive: true }): string | undefined;
  mkdtempSync(prefix: string): string;
  rmSync(path: string, options: { recursive: true; force: true }): void;
  existsSync(path: string): boolean;
  copyFileSync(from: string, to: string): void;
  cpSync(from: string, to: string, options: { recursive: true }): void;
  realpathSync(path: string): string;
  readdirSync(path: string): string[];
}
interface NodeUrl {
  fileURLToPath(url: string): string;
  pathToFileURL(path: string): { readonly href: string };
}
interface NodeOs {
  tmpdir(): string;
}
interface NodeCrypto {
  createHash(algorithm: "sha256"): { update(data: Uint8Array): { digest(encoding: "hex"): string } };
}
interface NodeModule {
  createRequire(from: string): { readonly cache: Readonly<Record<string, { readonly exports?: unknown } | undefined>> };
}
interface Host {
  readonly execPath: string;
  readonly platform: string;
  readonly arch: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  getBuiltinModule(id: "node:child_process"): NodeChildProcess;
  getBuiltinModule(id: "node:crypto"): NodeCrypto;
  getBuiltinModule(id: "node:fs"): NodeFs;
  getBuiltinModule(id: "node:module"): NodeModule;
  getBuiltinModule(id: "node:os"): NodeOs;
  getBuiltinModule(id: "node:url"): NodeUrl;
}
const host = (globalThis as unknown as { process: Host }).process;
const cp = host.getBuiltinModule("node:child_process");
const fs = host.getBuiltinModule("node:fs");
const os = host.getBuiltinModule("node:os");
const sha256 = (bytes: Uint8Array): string => host.getBuiltinModule("node:crypto").createHash("sha256").update(bytes).digest("hex");
const url = host.getBuiltinModule("node:url");
const thisFile = url.fileURLToPath((import.meta as unknown as { url: string }).url);
/** bindings/node: this file is bindings/node/dist/loader.test.js. */
const pkgDir = path.resolve(path.dirname(thisFile), "..");

/** The eight prebuilds polyjose ships inside @polyjose/node (ADR 0031 §2, 0017): Rust target → platform. */
const SHIPPED: Readonly<Record<string, string>> = {
  "x86_64-apple-darwin": "darwin-x64",
  "aarch64-apple-darwin": "darwin-arm64",
  "x86_64-unknown-linux-gnu": "linux-x64-gnu",
  "aarch64-unknown-linux-gnu": "linux-arm64-gnu",
  "x86_64-unknown-linux-musl": "linux-x64-musl",
  "aarch64-unknown-linux-musl": "linux-arm64-musl",
  "x86_64-pc-windows-msvc": "win32-x64-msvc",
  "aarch64-pc-windows-msvc": "win32-arm64-msvc",
};

// ---- The load surface, read from the compiled backend.js ----

/** backend.js without comments (their prose names the things it does not load). */
const backendCode = fs
  .readFileSync(path.join(pkgDir, "backend.js"), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .split("\n")
  .filter((line) => !/^\s*\/\//.test(line))
  .join("\n");

test("backend.js loads only the pinned built-ins and requires only the private copy (no platform package)", () => {
  const builtins = [...backendCode.matchAll(/getBuiltinModule\(([^()]*)\)/g)].map((m) => (m[1] ?? "").trim());
  assert.deepEqual(
    [...new Set(builtins)].sort(),
    ['"node:crypto"', '"node:fs"', '"node:module"', '"node:os"', '"node:path"', '"node:url"'],
    "the built-ins backend.js uses",
  );
  // The one CommonJS load: the private, hash-checked copy, by absolute path (`req(copy)`).
  const loads = [...backendCode.matchAll(/\breq\(([^()]*)\)/g)].map((m) => (m[1] ?? "").trim());
  assert.deepEqual(loads, ["copy"], "the require targets of backend.js");
  for (const banned of [
    /\brequire\s*\(/,
    /\.resolve\s*\(/,
    /\bimport\s*\(/,
    /process\.dlopen/,
    /@polyjose\/node-/,
    /node_modules/,
    /NODE_PATH/,
    /NAPI_RS_/,
    /binding\.cjs/,
    /\.env\b/,
    /process\.cwd/,
  ]) {
    assert.doesNotMatch(backendCode, banned, `backend.js has no ${banned.source}`);
  }
});

test("no generated napi loader is built or shipped: package.json files lists no binding.cjs", () => {
  assert.ok(!fs.existsSync(path.join(pkgDir, "binding.cjs")), "scripts/build.sh writes no binding.cjs (napi build --no-js)");
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8")) as { files: string[] };
  assert.ok(!pkg.files.some((f) => /binding\./.test(f)), "files lists no binding.*");
});

test("PLATFORMS is the eight shipped platforms of package.json's napi.targets", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8")) as {
    napi: { targets: string[] };
    files: string[];
  };
  assert.deepEqual([...pkg.napi.targets].sort(), Object.keys(SHIPPED).sort());
  assert.deepEqual([...PLATFORMS].sort(), Object.values(SHIPPED).sort());
  const addons = pkg.files.filter((f) => f.endsWith(".node")).sort();
  assert.deepEqual(addons, PLATFORMS.map((p) => `polyjose.${p}.node`).sort(), "package.json files lists each addon");
});

test("the in-process backend is the exports of the private copy of the addon", () => {
  const req = host.getBuiltinModule("node:module").createRequire(thisFile);
  const owners = Object.keys(req.cache).filter((k) => req.cache[k]?.exports === backend);
  assert.equal(owners.length, 1, `one module owns the backend (${owners.join(", ")})`);
  assert.match(owners[0] ?? "", /[\\/]polyjose-addon-[^\\/]+[\\/]polyjose-[0-9a-f]{32}\.node$/);
});

// ---- Platform detection (napi-rs's names; ADR 0031 §2) ----

/** A fake host for detectPlatform: `ldd` is /usr/bin/ldd's text, or null when it cannot be read. */
function fakeHost(
  platform: string,
  arch: string,
  ldd: string | null,
  report?: { header?: { glibcVersionRuntime?: string }; sharedObjects?: string[] } | null,
): { host: Parameters<typeof detectPlatform>[0]; fs: Parameters<typeof detectPlatform>[1]; reads: string[]; excluded: () => unknown } {
  const reads: string[] = [];
  const probe = { excludeNetwork: false as boolean, seen: undefined as unknown };
  const h = {
    platform,
    arch,
    ...(report === undefined
      ? {}
      : {
          report: {
            get excludeNetwork(): boolean {
              return probe.excludeNetwork;
            },
            set excludeNetwork(v: boolean) {
              probe.excludeNetwork = v;
            },
            getReport: () => {
              probe.seen = probe.excludeNetwork;
              return report;
            },
          },
        }),
  };
  const f = {
    readFileSync(file: string, _encoding: "utf8"): string {
      reads.push(file);
      if (ldd === null) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      return ldd;
    },
  };
  return { host: h, fs: f, reads, excluded: () => probe.seen };
}

const GLIBC_LDD = "#! /bin/bash\n# This file is part of the GNU C Library.\nTEXTDOMAIN=libc\n";
const MUSL_LDD = "#!/bin/sh\nexec /lib/ld-musl-x86_64.so.1 --list \"$@\"\n";

/** Runs `fn` and returns the refusal's message, asserting its code. */
function refusal(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    assert.equal((e as { code?: unknown }).code, "ERR_POLYJOSE_ADDON_REFUSED");
    return e instanceof Error ? e.message : String(e);
  }
  assert.fail("expected a refusal");
}

test("detectPlatform: darwin and Windows msvc, x64 and arm64", () => {
  for (const [platform, arch, want] of [
    ["darwin", "x64", "darwin-x64"],
    ["darwin", "arm64", "darwin-arm64"],
    ["win32", "x64", "win32-x64-msvc"],
    ["win32", "arm64", "win32-arm64-msvc"],
  ] as const) {
    const f = fakeHost(platform, arch, null);
    assert.equal(detectPlatform(f.host, f.fs), want);
    assert.deepEqual(f.reads, [], `${want}: no libc probe off Linux`);
  }
});

test("detectPlatform: Linux gnu or musl from /usr/bin/ldd first", () => {
  for (const arch of ["x64", "arm64"]) {
    const gnu = fakeHost("linux", arch, GLIBC_LDD, { sharedObjects: ["/lib/ld-musl-x86_64.so.1"] });
    assert.equal(detectPlatform(gnu.host, gnu.fs), `linux-${arch}-gnu`);
    assert.deepEqual(gnu.reads, ["/usr/bin/ldd"]);
    assert.equal(gnu.excluded(), undefined, "the report is not consulted when ldd answers");
    const musl = fakeHost("linux", arch, MUSL_LDD, { header: { glibcVersionRuntime: "2.39" } });
    assert.equal(detectPlatform(musl.host, musl.fs), `linux-${arch}-musl`);
  }
});

test("detectPlatform: without /usr/bin/ldd, the process report decides (glibc runtime, else a musl object)", () => {
  const glibc = fakeHost("linux", "x64", null, { header: { glibcVersionRuntime: "2.28" }, sharedObjects: [] });
  assert.equal(detectPlatform(glibc.host, glibc.fs), "linux-x64-gnu");
  assert.equal(glibc.excluded(), true, "excludeNetwork is set while the report is taken");
  assert.equal(glibc.host.report?.excludeNetwork, false, "and restored after");
  const musl = fakeHost("linux", "arm64", null, { header: {}, sharedObjects: ["/usr/lib/libc.musl-aarch64.so.1"] });
  assert.equal(detectPlatform(musl.host, musl.fs), "linux-arm64-musl");
  const ldMusl = fakeHost("linux", "x64", null, { sharedObjects: ["/lib/ld-musl-x86_64.so.1"] });
  assert.equal(detectPlatform(ldMusl.host, ldMusl.fs), "linux-x64-musl");
  const neither = fakeHost("linux", "x64", null, { header: {}, sharedObjects: ["/lib/x86_64-linux-gnu/libc.so.6"] });
  assert.equal(detectPlatform(neither.host, neither.fs), "linux-x64-gnu", "no musl object: glibc, as napi-rs decides");
});

test("detectPlatform: no ldd and no usable report is a refusal, never a guess", () => {
  const none = fakeHost("linux", "x64", null);
  assert.match(refusal(() => detectPlatform(none.host, none.fs)), /cannot tell glibc from musl/);
  const empty = fakeHost("linux", "arm64", null, null);
  assert.match(refusal(() => detectPlatform(empty.host, empty.fs)), /cannot tell glibc from musl/);
});

test("detectPlatform: any other platform or architecture is named <platform>-<arch>, which no pin lists", () => {
  for (const [platform, arch] of [
    ["freebsd", "x64"],
    ["linux", "ia32"],
    ["linux", "riscv64"],
    ["win32", "ia32"],
    ["android", "arm64"],
  ] as const) {
    const f = fakeHost(platform, arch, MUSL_LDD);
    const name = detectPlatform(f.host, f.fs);
    assert.equal(name, `${platform}-${arch}`);
    assert.ok(!PLATFORMS.includes(name as never), `${name} is not shipped`);
  }
});

test("detectPlatform on this host names the addon scripts/build.sh built", () => {
  assert.equal(detectPlatform(host as never, fs as never), hostPlatform);
});

// ---- Fail closed, in child processes on a temporary copy of the package ----

/** The addon hash map the package ships (F07): `{ "<platform>": "<SHA-256 hex>" }`. */
const PINS = "addon-sha256.json";

/** The package's own load refusals carry this `code` (backend.ts `refuse`). */
const REFUSED = "ERR_POLYJOSE_ADDON_REFUSED";

/** The host's built addon, `polyjose.<platform>.node` (scripts/build.sh builds the host only). */
const hostAddon = ((): string => {
  const addons = fs.readdirSync(pkgDir).filter((f) => /^polyjose\.[a-z0-9-]+\.node$/.test(f));
  assert.equal(addons.length, 1, `exactly one built addon in bindings/node (found ${addons.join(", ")})`);
  return addons[0] ?? "";
})();

/** The host's platform name, e.g. `darwin-arm64`, from the built addon's file name. */
const hostPlatform = hostAddon.replace(/^polyjose\./, "").replace(/\.node$/, "");

/**
 * Copies what the package ships into `dir`, optionally with another version: the entry, the
 * backend, the facade, package.json, the addon hash map scripts/build.sh wrote for the host's
 * addon (F07) and, with `addon`, the host's addon itself.
 */
function copyPackageFiles(dir: string, addon: boolean, version?: string): void {
  fs.mkdirSync(dir, { recursive: true });
  for (const f of ["index.js", "backend.js", PINS]) fs.copyFileSync(path.join(pkgDir, f), path.join(dir, f));
  fs.cpSync(path.join(pkgDir, "facade"), path.join(dir, "facade"), { recursive: true });
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8")) as Record<string, unknown>;
  if (version !== undefined) pkg["version"] = version;
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(pkg, null, 2));
  if (addon) fs.copyFileSync(path.join(pkgDir, hostAddon), path.join(dir, hostAddon));
}

/** The parent's environment without any NAPI_RS_* or NODE_PATH variable, plus `extra`. */
function childEnv(extra: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(host.env)) {
    if (v !== undefined && !k.startsWith("NAPI_RS_") && k !== "NODE_PATH" && k !== "NODE_OPTIONS") env[k] = v;
  }
  return { ...env, ...extra };
}

/** What a child that imported the package saw. */
interface ImportOutcome {
  readonly loaded: boolean;
  readonly error: string | null;
  /** The thrown error's `code`, when it has a string one. */
  readonly code: string | null;
  /** Every `.node` file in the CommonJS module cache, wherever it is: what was dlopen()ed. */
  readonly addons: string[];
  /** `NAPI_RS_NATIVE_LIBRARY_PATH` after the import (the package never touches it). */
  readonly overrideAfter: string | null;
  /** After a successful import: the forged token verified (review-security.md M1's PoC). */
  readonly forged: boolean;
  /** After a successful import: the name of the error the forged token was rejected with. */
  readonly forgeryRejectedWith: string | null;
}

/**
 * review-security.md M1's forged token: HS256 over `{}` with a garbage signature, and a garbage
 * key. The genuine addon rejects it; a substitute backend "verifies" it.
 */
const FORGED_TOKEN = "eyJhbGciOiJIUzI1NiJ9.e30.AAAA";

/**
 * Imports the copy's index.js in a fresh `node`, from a neutral working directory, then (if the
 * import succeeded) tries to verify FORGED_TOKEN through the public jwsVerifyCompact. `preload` is
 * the path of an ES module run first (`--import`, as a file URL: Windows paths are not URLs), e.g.
 * one that fakes `process.platform`.
 */
function importInChild(dir: string, env: Record<string, string> = {}, preload?: string): ImportOutcome {
  const script = [
    'import { createRequire } from "node:module";',
    'import { pathToFileURL } from "node:url";',
    'import { join } from "node:path";',
    "const dir = process.argv[1];",
    "const out = { loaded: false, error: null, code: null, addons: [], overrideAfter: null, forged: false, forgeryRejectedWith: null };",
    "let api = null;",
    'try { api = await import(pathToFileURL(join(dir, "index.js")).href); out.loaded = true; }',
    "catch (e) { out.error = e instanceof Error ? e.message : String(e); if (typeof e?.code === \"string\") out.code = e.code; }",
    "out.overrideAfter = process.env.NAPI_RS_NATIVE_LIBRARY_PATH ?? null;",
    "if (api !== null) {",
    `  try { await api.jwsVerifyCompact(${JSON.stringify(FORGED_TOKEN)}, { kty: "oct", k: "AAAA" }, { allowedAlgs: ["HS256"] }); out.forged = true; }`,
    '  catch (e) { out.forgeryRejectedWith = e instanceof Error ? e.name : "non-Error"; }',
    "}",
    'out.addons = Object.keys(createRequire(join(dir, "probe.cjs")).cache).filter((k) => k.endsWith(".node")).sort();',
    "process.stdout.write(JSON.stringify(out));",
  ].join("\n");
  const args = [...(preload === undefined ? [] : ["--import", url.pathToFileURL(preload).href]), "--input-type=module", "-e", script, dir];
  const r = cp.spawnSync(host.execPath, args, { env: childEnv(env), encoding: "utf8", cwd: os.tmpdir() });
  assert.equal(r.error, undefined, "spawn node");
  assert.equal(r.status, 0, `the probe exits 0 (stderr: ${r.stderr})`);
  return JSON.parse(r.stdout) as ImportOutcome;
}

/** The private copy's directory: `<os.tmpdir()>/polyjose-addon-XXXXXX` (backend.ts). */
const tmpReal = fs.realpathSync(os.tmpdir());

/** The import loaded exactly one addon, a private copy outside the package, removed after the load. */
function loadedPrivateCopy(dir: string, outcome: ImportOutcome, what: string): void {
  assert.equal(outcome.error, null, what);
  assert.equal(outcome.loaded, true, what);
  assert.equal(outcome.addons.length, 1, `${what}: exactly one addon loaded (${outcome.addons.join(", ")})`);
  const addon = outcome.addons[0] ?? "";
  assert.ok(!addon.startsWith(dir + path.sep), `${what}: the loaded file is not the one in the package`);
  assert.equal(path.dirname(path.dirname(addon)), tmpReal, `${what}: the copy is in a directory under os.tmpdir()`);
  const leaf = (file: string): string => file.slice(path.dirname(file).length + 1);
  assert.match(leaf(path.dirname(addon)), /^polyjose-addon-/, `${what}: the private directory`);
  assert.match(leaf(addon), /^polyjose-[0-9a-f]{32}\.node$/, `${what}: a random leaf name`);
  if (host.platform !== "win32") {
    assert.ok(!fs.existsSync(path.dirname(addon)), `${what}: the copy is removed once it is loaded`);
  }
  assert.equal(outcome.forged, false, `${what}: the forged token is not verified`);
  assert.equal(outcome.forgeryRejectedWith, "PolyjoseError", `${what}: the genuine core rejects the forged token`);
}

/** The import threw the package's own refusal and loaded no addon from anywhere. */
function refused(outcome: ImportOutcome, message: RegExp, what: string): void {
  assert.equal(outcome.loaded, false, `${what}: the import throws`);
  assert.equal(outcome.code, REFUSED, `${what}: the refusal's code (${outcome.error ?? ""})`);
  assert.match(outcome.error ?? "", /^@polyjose\/node: /, `${what}: the package's own refusal`);
  assert.match(outcome.error ?? "", message, what);
  assert.deepEqual(outcome.addons, [], `${what}: no native addon was loaded from anywhere`);
  assert.equal(outcome.forged, false, `${what}: no forged token verified`);
}

// An installed layout: <site>/app/node_modules/@polyjose/node holds the package. Substitutes are
// planted where a resolving loader would find them: <site>/node_modules (an ancestor of the
// install), <site>/node-path (for NODE_PATH), the override path, and the WASI candidates. Each JS
// fake is M1's PoC: it claims this version, "verifies" any token and writes a marker when it runs.

interface Site {
  readonly root: string;
  /** The package: <root>/app/node_modules/@polyjose/node. */
  readonly pkg: string;
  /** Written by a JavaScript fake backend when it runs. */
  readonly marker: string;
}

/** M1's substitute backend, as a CommonJS module that records running at `marker`. */
const fakeBackend = (marker: string): string =>
  [
    `require("fs").writeFileSync(${JSON.stringify(marker)}, "ran");`,
    'const known = { errorCodes: () => ["InvalidSignature"], version: () => "0.1.1" };',
    "module.exports = new Proxy(known, { get(t, k) {",
    "  if (k in t) return t[k];",
    '  if (k === "jwsVerifyCompact" || k === "jwsVerifyJson")',
    '    return async () => ({ alg: "HS256", payload: new TextEncoder().encode(\'{"admin":true}\'), signatureIndex: 0, protectedHeader: \'{"alg":"HS256"}\' });',
    "  return undefined;",
    "} });",
    "",
  ].join("\n");

/** Writes a fake package `name` (JS main) under `nodeModules`. */
function plantFakePackage(nodeModules: string, name: string, marker: string): void {
  const dir = path.join(nodeModules, ...name.split("/"));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name, version: "0.1.1", main: "index.js" }));
  fs.writeFileSync(path.join(dir, "index.js"), fakeBackend(marker));
}

/** The genuine addon's bytes, and the native fake's: the same plus one byte (F07, N-M1). */
const genuineBytes = (): Uint8Array => fs.readFileSync(path.join(pkgDir, hostAddon));
const fakeBytes = (): Uint8Array => {
  const genuine = genuineBytes();
  const fake = new Uint8Array(genuine.length + 1);
  fake.set(genuine);
  return fake;
};

/** Writes a 0.1.x-style `@polyjose/node-<host>` platform package with `addon` under `nodeModules`. */
function plantPlatformPackage(nodeModules: string, addon: Uint8Array): string {
  const p = path.join(nodeModules, "@polyjose", `node-${hostPlatform}`);
  fs.mkdirSync(p, { recursive: true });
  fs.writeFileSync(path.join(p, "package.json"), JSON.stringify({ name: `@polyjose/node-${hostPlatform}`, version: "0.1.1", main: hostAddon }));
  fs.writeFileSync(path.join(p, hostAddon), addon);
  return path.join(p, hostAddon);
}

interface SiteOptions {
  /** The package holds its genuine addon (a complete install). */
  readonly addon: boolean;
  /** Overrides package.json's version (the load-time version check). */
  readonly version?: string;
}

function withSite(options: SiteOptions, body: (site: Site) => void): void {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "polyjose-node-site-")));
  try {
    const site: Site = {
      root,
      pkg: path.join(root, "app", "node_modules", "@polyjose", "node"),
      marker: path.join(root, "fake-ran"),
    };
    copyPackageFiles(site.pkg, options.addon, options.version);
    body(site);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

/**
 * Every substitute a resolving loader could pick, planted at once: JS and native fakes of the
 * 0.1.x platform package in an ancestor node_modules and on NODE_PATH (the env returned), a JS
 * fake at NAPI_RS_NATIVE_LIBRARY_PATH, the napi-rs WASI candidates and switches, and a JS file
 * posing as the addon (`polyjose.<host>.node.js`, what `require('./polyjose.<host>.node')`
 * resolves to when the addon is absent).
 */
function plantEverything(site: Site): Record<string, string> {
  plantFakePackage(path.join(site.root, "node_modules"), `@polyjose/node-${hostPlatform}`, site.marker);
  plantPlatformPackage(path.join(site.root, "node-path"), fakeBytes());
  plantFakePackage(path.join(site.root, "app", "node_modules"), "@polyjose/node-wasm32-wasi", site.marker);
  fs.writeFileSync(path.join(site.pkg, "polyjose.wasi.cjs"), fakeBackend(site.marker));
  fs.writeFileSync(path.join(site.pkg, "polyjose.wasm32-wasi.wasm"), "");
  fs.writeFileSync(path.join(site.pkg, `${hostAddon}.js`), fakeBackend(site.marker));
  fs.writeFileSync(path.join(site.pkg, "binding.cjs"), fakeBackend(site.marker));
  const override = path.join(site.root, "fake-backend.cjs");
  fs.writeFileSync(override, fakeBackend(site.marker));
  return {
    NODE_PATH: path.join(site.root, "node-path"),
    NAPI_RS_NATIVE_LIBRARY_PATH: override,
    NAPI_RS_FORCE_WASI: "true",
    NAPI_RS_WASI_FLAVOR: "wasm32-wasi",
  };
}

test("the installed package loads a private copy of its own addon and leaves the environment alone", () => {
  withSite({ addon: true }, (site) => {
    const outcome = importInChild(site.pkg, { NAPI_RS_NATIVE_LIBRARY_PATH: "" });
    loadedPrivateCopy(site.pkg, outcome, "installed package");
    assert.equal(outcome.overrideAfter, "", "NAPI_RS_NATIVE_LIBRARY_PATH is the caller's, untouched");
  });
});

test("M1/N-M1: with every substitute planted, the genuine addon loads and no substitute runs", () => {
  withSite({ addon: true }, (site) => {
    const env = plantEverything(site);
    const outcome = importInChild(site.pkg, env);
    loadedPrivateCopy(site.pkg, outcome, "everything planted");
    assert.ok(!fs.existsSync(site.marker), "no substitute backend ran");
    assert.equal(outcome.overrideAfter, env["NAPI_RS_NATIVE_LIBRARY_PATH"], "the caller's override is untouched");
  });
});

test("M1/N-M1: with the addon missing and every substitute planted, the import is refused and nothing runs", () => {
  withSite({ addon: false }, (site) => {
    const outcome = importInChild(site.pkg, plantEverything(site));
    refused(outcome, new RegExp(`polyjose\\.${hostPlatform}\\.node is missing from this package`), "addon missing");
    assert.ok(!fs.existsSync(site.marker), "no substitute backend ran");
  });
});

test("F07: a tampered addon in the package is refused by its hash, naming the platform and both hashes", () => {
  withSite({ addon: false }, (site) => {
    fs.writeFileSync(path.join(site.pkg, hostAddon), fakeBytes());
    const outcome = importInChild(site.pkg);
    refused(outcome, /refusing to load it/, "tampered addon");
    const pins = JSON.parse(fs.readFileSync(path.join(pkgDir, PINS), "utf8")) as Record<string, string>;
    for (const part of [hostPlatform, `./${hostAddon}`, sha256(fakeBytes()), pins[hostPlatform] ?? "?"]) {
      assert.ok((outcome.error ?? "").includes(part), `the refusal names ${part} (${outcome.error ?? ""})`);
    }
  });
});

test("F07: build.sh pinned exactly the host addon's SHA-256 in addon-sha256.json", () => {
  const pins = JSON.parse(fs.readFileSync(path.join(pkgDir, PINS), "utf8")) as Record<string, unknown>;
  assert.deepEqual(pins, { [hostPlatform]: sha256(genuineBytes()) });
});

test("F07: no addon-sha256.json, one without this platform, or a malformed one: nothing loads", () => {
  const pins = JSON.parse(fs.readFileSync(path.join(pkgDir, PINS), "utf8")) as Record<string, string>;
  const other = hostPlatform === "darwin-x64" ? "darwin-arm64" : "darwin-x64";
  const cases: [string, string | null, RegExp][] = [
    ["no map", null, /addon-sha256\.json is missing/],
    ["another platform only", JSON.stringify({ [other]: "0".repeat(64) }), new RegExp(`no pinned SHA-256 for ${hostPlatform}`)],
    ["not JSON", "{", /addon-sha256\.json is not/],
    ["an array", "[]", /addon-sha256\.json is not/],
    ["an unknown platform", JSON.stringify({ [hostPlatform]: pins[hostPlatform], "freebsd-x64": "0".repeat(64) }), /addon-sha256\.json is not/],
    ["an upper-case hash", JSON.stringify({ [hostPlatform]: String(pins[hostPlatform]).toUpperCase() }), /addon-sha256\.json is not/],
    ["a short hash", JSON.stringify({ [hostPlatform]: "00" }), /addon-sha256\.json is not/],
    ["a __proto__ key", `{"__proto__": "${"0".repeat(64)}"}`, /addon-sha256\.json is not/],
  ];
  for (const [what, map, message] of cases) {
    withSite({ addon: true }, (site) => {
      if (map === null) fs.rmSync(path.join(site.pkg, PINS), { recursive: true, force: true });
      else fs.writeFileSync(path.join(site.pkg, PINS), map);
      refused(importInChild(site.pkg), message, what);
    });
  }
});

test("an addon whose version() is not the package version is refused", () => {
  withSite({ addon: true, version: "0.0.0-mismatch" }, (site) => {
    const outcome = importInChild(site.pkg);
    assert.equal(outcome.loaded, false);
    assert.equal(outcome.code, REFUSED);
    assert.match(outcome.error ?? "", /0\.0\.0-mismatch/);
  });
});

test("an unsupported platform is refused by name, pointing at @polyjose/wasm", () => {
  withSite({ addon: true }, (site) => {
    const preload = path.join(site.root, "fake-platform.mjs");
    fs.writeFileSync(preload, 'Object.defineProperty(process, "platform", { value: "freebsd" });\n');
    const outcome = importInChild(site.pkg, {}, preload);
    refused(outcome, /freebsd-/, "freebsd");
    assert.match(outcome.error ?? "", /@polyjose\/wasm/, "names the WASM package");
    for (const p of PLATFORMS) assert.ok((outcome.error ?? "").includes(p), `lists ${p}`);
  });
});

test("two copies of the package in one process each load their own private copy", () => {
  withSite({ addon: true }, (site) => {
    const second = path.join(site.root, "app", "node_modules", "dep", "node_modules", "@polyjose", "node");
    copyPackageFiles(second, true);
    const script = [
      'import { createRequire } from "node:module";',
      'import { pathToFileURL } from "node:url";',
      'import { join } from "node:path";',
      "const out = { versions: [], addons: 0 };",
      "for (const dir of process.argv.slice(1)) {",
      '  try { const api = await import(pathToFileURL(join(dir, "index.js")).href); out.versions.push(await api.version()); }',
      "  catch (e) { out.versions.push(e instanceof Error ? e.message : String(e)); }",
      "}",
      'out.addons = Object.keys(createRequire(join(process.argv[1], "probe.cjs")).cache).filter((f) => f.endsWith(".node")).length;',
      "process.stdout.write(JSON.stringify(out));",
    ].join("\n");
    const r = cp.spawnSync(host.execPath, ["--input-type=module", "-e", script, site.pkg, second], {
      env: childEnv({}),
      encoding: "utf8",
      cwd: os.tmpdir(),
    });
    assert.equal(r.status, 0, `the probe exits 0 (stderr: ${r.stderr})`);
    const version = (JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8")) as { version: string }).version;
    assert.deepEqual(JSON.parse(r.stdout), { versions: [version, version], addons: 2 });
  });
});
