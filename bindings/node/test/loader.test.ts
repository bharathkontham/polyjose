// The generated napi-rs loader and how @polyjose/node wraps it (feature 0007 F02; review-code.md
// SF-4 and N7; ADR 0031 §2), run with `node --test` against the built package (ADR 0047):
//   - the load surface: the exact set of `require(...)` targets and environment variables of the
//     built binding.cjs (napi-rs CLI 3.10.12) is pinned, and none is absolute or CWD-derived, so a
//     CLI bump that changes what the loader can load fails here instead of passing review unseen;
//   - the loader side effects the README documents (N7) are still the loader's;
//   - fail closed: polyjose publishes no WASI build, so the package refuses the napi-rs WASI
//     variables and never reaches the loader's WASI chain when the native load fails. Each case
//     runs in a child process on a temporary copy of the package, with a planted WASI sentinel
//     that records being loaded; a control run of the raw loader proves the sentinel is reachable.
import { assert, path, test } from "../../js/dist/node/builtins.js";
import { backend } from "../backend.js";

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
  writeFileSync(path: string, data: string): void;
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
}
interface NodeOs {
  tmpdir(): string;
}
interface Host {
  readonly execPath: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  getBuiltinModule(id: "node:child_process"): NodeChildProcess;
  getBuiltinModule(id: "node:fs"): NodeFs;
  getBuiltinModule(id: "node:os"): NodeOs;
  getBuiltinModule(id: "node:url"): NodeUrl;
}
const host = (globalThis as unknown as { process: Host }).process;
const cp = host.getBuiltinModule("node:child_process");
const fs = host.getBuiltinModule("node:fs");
const os = host.getBuiltinModule("node:os");
const thisFile = host.getBuiltinModule("node:url").fileURLToPath((import.meta as unknown as { url: string }).url);
/** bindings/node: this file is bindings/node/dist/loader.test.js. */
const pkgDir = path.resolve(path.dirname(thisFile), "..");
const loaderSource = fs.readFileSync(path.join(pkgDir, "binding.cjs"), "utf8");

/** The eight prebuilds polyjose publishes (ADR 0031 §2, option 5a): Rust target → napi platform. */
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

/**
 * The platform names the napi-rs 3.10.12 template probes although polyjose never builds or
 * publishes them (SF-4 item 2). The `@polyjose` npm scope is what keeps them from being squatted.
 */
const TEMPLATE_EXTRA = [
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

/** What the loader requires for one platform: the local addon, then the platform package. */
const platformTargets = (p: string): string[] => [
  `require:'./polyjose.${p}.node'`,
  `require:'@polyjose/node-${p}'`,
  `require:'@polyjose/node-${p}/package.json'`,
];

/**
 * The WASI chain (SF-4 item 1): the local `./polyjose.wasi.cjs` (only when a `.wasm` artifact
 * resolves next to it), then the package `@polyjose/node-wasm32-wasi`. `backend.ts` refuses to load
 * when any of these resolves, so the chain can never find anything.
 */
const WASI_TARGETS = [
  "require:'./polyjose.wasi.cjs'",
  "require:'@polyjose/node-wasm32-wasi'",
  "require:'@polyjose/node-wasm32-wasi/package.json'",
  "candidate:'./polyjose.wasi.cjs', false, ['./polyjose.wasm32-wasi.debug.wasm', './polyjose.wasm32-wasi.wasm']",
  "candidate:'@polyjose/node-wasm32-wasi', true, undefined",
  "resolve:specifier",
  "resolve:specifier + '/package.json'",
  "resolve:localArtifacts[i]",
];

/** Node built-ins: `fs` (musl probe through /usr/bin/ldd) and `child_process` (`ldd --version`). */
const BUILTIN_TARGETS = ["require:'fs'", "require:'child_process'"];

/** The override: the native library at this path is loaded instead of the bundled addon. */
const OVERRIDE_TARGETS = ["require:process.env.NAPI_RS_NATIVE_LIBRARY_PATH"];

/** Every environment variable the loader reads (README, "Loading the addon"). */
const LOADER_ENV = [
  "NAPI_RS_ENFORCE_VERSION_CHECK",
  "NAPI_RS_FORCE_WASI",
  "NAPI_RS_NATIVE_LIBRARY_PATH",
  "NAPI_RS_WASI_FLAVOR",
];

/** The loader's code lines: `//` and block-comment lines dropped (their prose says "require"). */
const loaderCode = loaderSource
  .split("\n")
  .filter((line) => !/^\s*(\/\/|\/\*|\*)/.test(line))
  .join("\n");

/** Every load the loader can make, as `kind:argument-text`, sorted and without duplicates. */
function loadTargets(): string[] {
  const found = new Set<string>();
  for (const m of loaderCode.matchAll(/\brequire(\.resolve)?\(([^()]*)\)/g)) {
    found.add(`${m[1] === undefined ? "require" : "resolve"}:${(m[2] ?? "").trim()}`);
  }
  for (const m of loaderCode.matchAll(/__napiWasiResolveCandidate\(('[^()]*)\)/g)) {
    found.add(`candidate:${(m[1] ?? "").trim()}`);
  }
  return [...found].sort();
}

test("the loader's require targets are exactly the pinned set (SF-4 a)", () => {
  // Every `require` in the code is a call this scan sees: no aliasing such as `const r = require`.
  for (const m of loaderCode.matchAll(/\brequire\b(.{0,9})/g)) {
    assert.match(m[1] ?? "", /^(\(|\.resolve\()/, `a bare \`require${m[1] ?? ""}\` in binding.cjs`);
  }
  const expected = [
    ...Object.values(SHIPPED).flatMap(platformTargets),
    ...TEMPLATE_EXTRA.flatMap(platformTargets),
    ...WASI_TARGETS,
    ...BUILTIN_TARGETS,
    ...OVERRIDE_TARGETS,
  ].sort();
  assert.deepEqual(loadTargets(), [...new Set(expected)].sort());
});

test("the eight pinned platforms are package.json's napi.targets", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8")) as {
    napi: { targets: string[] };
  };
  assert.deepEqual([...pkg.napi.targets].sort(), Object.keys(SHIPPED).sort());
  for (const extra of TEMPLATE_EXTRA) {
    assert.ok(!Object.values(SHIPPED).includes(extra), `${extra} is listed as both shipped and extra`);
  }
});

test("no load target is absolute or derived from the working directory (SF-4 a)", () => {
  for (const target of loadTargets()) {
    const arg = target.slice(target.indexOf(":") + 1);
    for (const lit of arg.matchAll(/'([^']*)'/g)) {
      const spec = lit[1] ?? "";
      // `./x` in a CommonJS require resolves against the loader's own directory, never the CWD.
      const ok =
        spec === "fs" ||
        spec === "child_process" ||
        spec === "/package.json" || // the suffix of `specifier + '/package.json'`
        /^\.\/polyjose\.[a-z0-9-]+(\.debug)?\.(node|cjs|wasm)$/.test(spec) ||
        /^@polyjose\/node-[a-z0-9-]+(\/package\.json)?$/.test(spec);
      assert.ok(ok, `unexpected specifier '${spec}' in ${target}`);
    }
  }
  for (const banned of ["process.cwd", "__dirname", "__filename", "path.resolve", "import(", "process.dlopen"]) {
    assert.ok(!loaderCode.includes(banned), `binding.cjs uses ${banned}`);
  }
});

test("the loader reads exactly the pinned environment variables", () => {
  const read = new Set([...loaderCode.matchAll(/process\.env\.([A-Za-z0-9_]+)/g)].map((m) => m[1] ?? ""));
  assert.deepEqual([...read].sort(), LOADER_ENV);
  assert.ok(!/process\.env\[/.test(loaderCode), "binding.cjs indexes process.env dynamically");
});

test("the loader side effects the README documents are still the loader's (N7)", () => {
  // isMuslFromReport sets this process-wide before calling process.report.getReport().
  assert.ok(loaderCode.includes("process.report.excludeNetwork = true"), "the musl report probe");
  // Windows x64 embedders (node_target_type 'shared_library') are sent to win32-x64-gnu only.
  const gnu = loaderCode.indexOf("require('./polyjose.win32-x64-gnu.node')");
  const embedder = loaderCode.lastIndexOf("node_target_type === 'shared_library'", gnu);
  assert.ok(gnu > 0 && embedder > 0 && gnu - embedder < 400, "the shared_library branch picks win32-x64-gnu");
  // The loaded binding is stamped with __napiBindingTarget ('native' for the addon).
  assert.ok(loaderCode.includes("module.exports.__napiBindingTarget = __napiStampBindingTarget("), "the stamp");
});

test("the in-process backend is the native addon", () => {
  assert.equal((backend as unknown as { __napiBindingTarget?: unknown }).__napiBindingTarget, "native");
});

// ---- Fail closed, in child processes on a temporary copy of the package ----

/** The host's built addon, `polyjose.<platform>.node` (scripts/build.sh builds the host only). */
const hostAddon = ((): string => {
  const addons = fs.readdirSync(pkgDir).filter((f) => /^polyjose\.[a-z0-9-]+\.node$/.test(f));
  assert.equal(addons.length, 1, `exactly one built addon in bindings/node (found ${addons.join(", ")})`);
  return addons[0] ?? "";
})();

/** Marker files the sentinels write when they are loaded; none is ever written by a real build. */
const LOCAL_SENTINEL = "local-wasi-sentinel-loaded";
const PACKAGE_SENTINEL = "package-wasi-sentinel-loaded";

interface CopyOptions {
  /** Copy the host addon next to the loader (the native load then succeeds). */
  readonly addon: boolean;
  /** Plant `./polyjose.wasi.cjs` and a `.wasm` artifact, the loader's local WASI candidate. */
  readonly localWasi?: boolean;
  /** Plant `node_modules/@polyjose/node-wasm32-wasi`, the loader's WASI package candidate. */
  readonly packageWasi?: boolean;
  /** Overrides package.json's version (the load-time version check). */
  readonly version?: string;
}

/** Copies the main package's load path (no addon) into `dir`, optionally with another version. */
function copyPackageFiles(dir: string, version?: string): void {
  fs.mkdirSync(dir, { recursive: true });
  for (const f of ["index.js", "backend.js", "binding.cjs"]) fs.copyFileSync(path.join(pkgDir, f), path.join(dir, f));
  fs.cpSync(path.join(pkgDir, "facade"), path.join(dir, "facade"), { recursive: true });
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8")) as Record<string, unknown>;
  if (version !== undefined) pkg["version"] = version;
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(pkg, null, 2));
}

/**
 * A temporary copy of what the package ships that the load path reads: index.js, backend.js,
 * facade/, binding.cjs, package.json and optionally the addon and WASI sentinels. Real path, since
 * `require.cache` keys are real paths (macOS's tmpdir is a symlink).
 */
function packageCopy(options: CopyOptions): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "polyjose-node-loader-")));
  copyPackageFiles(dir, options.version);
  if (options.addon) fs.copyFileSync(path.join(pkgDir, hostAddon), path.join(dir, hostAddon));
  const sentinel = (marker: string): string =>
    `require("fs").writeFileSync(${JSON.stringify(path.join(dir, marker))}, "loaded");\nmodule.exports = {};\n`;
  if (options.localWasi === true) {
    fs.writeFileSync(path.join(dir, "polyjose.wasi.cjs"), sentinel(LOCAL_SENTINEL));
    fs.writeFileSync(path.join(dir, "polyjose.wasm32-wasi.wasm"), "");
  }
  if (options.packageWasi === true) {
    const p = path.join(dir, "node_modules", "@polyjose", "node-wasm32-wasi");
    fs.mkdirSync(p, { recursive: true });
    fs.writeFileSync(path.join(p, "package.json"), JSON.stringify({ name: "@polyjose/node-wasm32-wasi", version: "0.1.0", main: "index.js" }));
    fs.writeFileSync(path.join(p, "index.js"), sentinel(PACKAGE_SENTINEL));
  }
  return dir;
}

/** The parent's environment without any NAPI_RS_* variable, plus `extra`. */
function childEnv(extra: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(host.env)) if (v !== undefined && !k.startsWith("NAPI_RS_")) env[k] = v;
  return { ...env, ...extra };
}

/** What a child that imported the package saw. */
interface ImportOutcome {
  readonly loaded: boolean;
  readonly error: string | null;
  /** The package copy's files in the CommonJS module cache: what was loaded through `require`. */
  readonly required: string[];
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
 * import succeeded) tries to verify FORGED_TOKEN through the public jwsVerifyCompact.
 */
function importInChild(dir: string, env: Record<string, string> = {}): ImportOutcome {
  const script = [
    'import { createRequire } from "node:module";',
    'import { pathToFileURL } from "node:url";',
    'import { join, sep } from "node:path";',
    "const dir = process.argv[1];",
    "const out = { loaded: false, error: null, required: [], forged: false, forgeryRejectedWith: null };",
    "let api = null;",
    'try { api = await import(pathToFileURL(join(dir, "index.js")).href); out.loaded = true; }',
    "catch (e) { out.error = e instanceof Error ? e.message : String(e); }",
    "if (api !== null) {",
    `  try { await api.jwsVerifyCompact(${JSON.stringify(FORGED_TOKEN)}, { kty: "oct", k: "AAAA" }, { allowedAlgs: ["HS256"] }); out.forged = true; }`,
    '  catch (e) { out.forgeryRejectedWith = e instanceof Error ? e.name : "non-Error"; }',
    "}",
    'out.required = Object.keys(createRequire(join(dir, "probe.cjs")).cache)',
    "  .filter((k) => k.startsWith(dir + sep)).map((k) => k.slice(dir.length + 1)).sort();",
    "process.stdout.write(JSON.stringify(out));",
  ].join("\n");
  const r = cp.spawnSync(host.execPath, ["--input-type=module", "-e", script, dir], {
    env: childEnv(env),
    encoding: "utf8",
    cwd: os.tmpdir(),
  });
  assert.equal(r.error, undefined, "spawn node");
  assert.equal(r.status, 0, `the probe exits 0 (stderr: ${r.stderr})`);
  return JSON.parse(r.stdout) as ImportOutcome;
}

/** Requires the copy's raw binding.cjs in a fresh `node`; returns its exit status. */
function requireRawLoader(dir: string, env: Record<string, string> = {}): number | null {
  const r = cp.spawnSync(host.execPath, ["-e", 'require(require("path").join(process.argv[1], "binding.cjs"))', dir], {
    env: childEnv(env),
    encoding: "utf8",
    cwd: os.tmpdir(),
  });
  assert.equal(r.error, undefined, "spawn node");
  return r.status;
}

/** Runs `body` on a fresh copy and removes it afterwards. */
function withCopy(options: CopyOptions, body: (dir: string) => void): void {
  const dir = packageCopy(options);
  try {
    body(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Neither sentinel ran, and neither the loader nor the addon nor a sentinel was required. */
function nothingLoaded(dir: string, outcome: ImportOutcome, what: string): void {
  assert.equal(outcome.loaded, false, `${what}: the import throws`);
  assert.ok(!fs.existsSync(path.join(dir, LOCAL_SENTINEL)), `${what}: the local WASI sentinel did not load`);
  assert.ok(!fs.existsSync(path.join(dir, PACKAGE_SENTINEL)), `${what}: the WASI package sentinel did not load`);
  assert.deepEqual(
    outcome.required.filter((f) => f === "binding.cjs" || f.endsWith(".node") || f.includes("wasi")),
    [],
    `${what}: no loader, addon or WASI file was required`,
  );
}

test("the copy harness: with the addon and nothing planted, the package loads the native addon", () => {
  withCopy({ addon: true }, (dir) => {
    const outcome = importInChild(dir);
    assert.equal(outcome.error, null);
    assert.equal(outcome.loaded, true);
    assert.ok(outcome.required.includes("binding.cjs") && outcome.required.includes(hostAddon), "loader and addon loaded");
  });
});

test("control: with no addon, the raw loader does reach a planted WASI sentinel (both candidates)", () => {
  withCopy({ addon: false, localWasi: true }, (dir) => {
    assert.equal(requireRawLoader(dir), 0, "the raw loader loads ./polyjose.wasi.cjs");
    assert.ok(fs.existsSync(path.join(dir, LOCAL_SENTINEL)), "the local sentinel ran");
  });
  withCopy({ addon: false, packageWasi: true }, (dir) => {
    assert.equal(requireRawLoader(dir), 0, "the raw loader loads @polyjose/node-wasm32-wasi");
    assert.ok(fs.existsSync(path.join(dir, PACKAGE_SENTINEL)), "the package sentinel ran");
  });
});

test("a failed native load never reaches the WASI chain: the package throws, the sentinel does not load", () => {
  withCopy({ addon: false, localWasi: true }, (dir) => {
    const outcome = importInChild(dir);
    nothingLoaded(dir, outcome, "local ./polyjose.wasi.cjs");
    assert.match(outcome.error ?? "", /polyjose\.wasi\.cjs/);
  });
  withCopy({ addon: false, packageWasi: true }, (dir) => {
    const outcome = importInChild(dir);
    nothingLoaded(dir, outcome, "@polyjose/node-wasm32-wasi");
    assert.match(outcome.error ?? "", /@polyjose\/node-wasm32-wasi/);
  });
});

test("a planted WASI candidate is refused even when the native addon is present", () => {
  withCopy({ addon: true, localWasi: true, packageWasi: true }, (dir) => {
    nothingLoaded(dir, importInChild(dir), "addon present");
  });
});

test("with no addon and no WASI candidate, the import throws the loader's own error", () => {
  withCopy({ addon: false }, (dir) => {
    const outcome = importInChild(dir);
    assert.equal(outcome.loaded, false);
    assert.match(outcome.error ?? "", /Cannot find native binding/);
  });
});

test("the WASI variables are refused, whatever their value, and nothing loads", () => {
  const cases: Record<string, string>[] = [
    { NAPI_RS_FORCE_WASI: "true" },
    { NAPI_RS_FORCE_WASI: "1" },
    { NAPI_RS_FORCE_WASI: "error" },
    { NAPI_RS_FORCE_WASI: "false" },
    { NAPI_RS_FORCE_WASI: "" },
    { NAPI_RS_WASI_FLAVOR: "wasm32-wasi" },
    { NAPI_RS_WASI_FLAVOR: "" },
  ];
  for (const env of cases) {
    const [name, value] = Object.entries(env)[0] ?? ["", ""];
    // The addon is present: without the refusal, `true`, `error` and the flavor would skip it.
    withCopy({ addon: true }, (dir) => {
      const outcome = importInChild(dir, env);
      nothingLoaded(dir, outcome, `${name}=${JSON.stringify(value)}`);
      assert.match(outcome.error ?? "", new RegExp(name), `${name}=${JSON.stringify(value)}: the error names it`);
    });
  }
});

test("NAPI_RS_NATIVE_LIBRARY_PATH: the addon at that path loads; a WASI-stamped module there is refused", () => {
  withCopy({ addon: true }, (dir) => {
    const outcome = importInChild(dir, { NAPI_RS_NATIVE_LIBRARY_PATH: path.join(dir, hostAddon) });
    assert.equal(outcome.error, null);
    assert.equal(outcome.loaded, true);
  });
  withCopy({ addon: true }, (dir) => {
    // A generated WASI loader stamps itself; the napi loader adopts that flavor (binding.cjs).
    const fake = path.join(dir, "fake-wasi-loader.cjs");
    const marker = path.join(dir, "fake-wasi-loader-ran");
    fs.writeFileSync(
      fake,
      `require("fs").writeFileSync(${JSON.stringify(marker)}, "x");\n` +
        'module.exports = { __napiBindingTarget: "wasm32-wasi", version: () => "0.1.0" };\n',
    );
    const outcome = importInChild(dir, { NAPI_RS_NATIVE_LIBRARY_PATH: fake });
    assert.equal(outcome.loaded, false);
    assert.match(outcome.error ?? "", /NAPI_RS_NATIVE_LIBRARY_PATH/);
    assert.ok(!fs.existsSync(marker), "the module at the override path never ran");
  });
});

test("an addon whose version() is not the package version is refused", () => {
  withCopy({ addon: true, version: "0.0.0-mismatch" }, (dir) => {
    const outcome = importInChild(dir);
    assert.equal(outcome.loaded, false);
    assert.match(outcome.error ?? "", /0\.0\.0-mismatch/);
  });
});

// ---- review-security.md M1: a substitute backend is never selected ----
//
// An installed layout: <site>/app/node_modules/@polyjose/node holds the main package with no addon
// (a registry install without its platform package, M1's precondition). A fake backend is planted
// where the loader's `require('@polyjose/node-<platform>')` would find it. Each fake is M1's PoC
// (`evil/fake-binding.cjs`): it claims this version and "verifies" any token. It also writes a
// marker when it runs, so the tests prove it was never even executed.

/** The host's napi platform name, e.g. `darwin-arm64`, from the built addon's file name. */
const hostPlatform = hostAddon.replace(/^polyjose\./, "").replace(/\.node$/, "");

/** M1's substitute backend, as a CommonJS module that records running at `marker`. */
const fakeBackend = (marker: string): string =>
  [
    `require("fs").writeFileSync(${JSON.stringify(marker)}, "ran");`,
    'const known = { errorCodes: () => ["InvalidSignature"], version: () => "0.1.0" };',
    "module.exports = new Proxy(known, { get(t, k) {",
    "  if (k in t) return t[k];",
    '  if (k === "jwsVerifyCompact" || k === "jwsVerifyJson")',
    '    return async () => ({ alg: "HS256", payload: new TextEncoder().encode(\'{"admin":true}\'), signatureIndex: 0, protectedHeader: \'{"alg":"HS256"}\' });',
    "  return undefined;",
    "} });",
    "",
  ].join("\n");

/** Writes a fake package `name` (version 0.1.0, JS main) under `nodeModules`. */
function plantFakePackage(nodeModules: string, name: string, marker: string): void {
  const dir = path.join(nodeModules, ...name.split("/"));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name, version: "0.1.0", main: "index.js" }));
  fs.writeFileSync(path.join(dir, "index.js"), fakeBackend(marker));
}

interface Site {
  readonly root: string;
  /** The main package: <root>/app/node_modules/@polyjose/node. */
  readonly pkg: string;
  /** Written by a fake backend when it runs. */
  readonly marker: string;
}

interface SiteOptions {
  /** Install the genuine platform package next to the main one (what SF-8 makes the default). */
  readonly genuine?: boolean;
  /** Plant a fake in <root>/node_modules, an ancestor of the install. */
  readonly ancestorFake?: "platform" | "wasi";
  /** Plant a fake platform package in <root>/node-path, for NODE_PATH. */
  readonly nodePathFake?: boolean;
}

function withSite(options: SiteOptions, body: (site: Site) => void): void {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "polyjose-node-site-")));
  try {
    const appModules = path.join(root, "app", "node_modules");
    const site: Site = { root, pkg: path.join(appModules, "@polyjose", "node"), marker: path.join(root, "fake-ran") };
    copyPackageFiles(site.pkg);
    if (options.genuine === true) {
      const p = path.join(appModules, "@polyjose", `node-${hostPlatform}`);
      fs.mkdirSync(p, { recursive: true });
      fs.copyFileSync(path.join(pkgDir, "npm", hostPlatform, "package.json"), path.join(p, "package.json"));
      fs.copyFileSync(path.join(pkgDir, hostAddon), path.join(p, hostAddon));
    }
    if (options.ancestorFake !== undefined) {
      const name = options.ancestorFake === "wasi" ? "@polyjose/node-wasm32-wasi" : `@polyjose/node-${hostPlatform}`;
      plantFakePackage(path.join(root, "node_modules"), name, site.marker);
    }
    if (options.nodePathFake === true) {
      plantFakePackage(path.join(root, "node-path"), `@polyjose/node-${hostPlatform}`, site.marker);
    }
    body(site);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

/** The fake never ran, the import threw, and no forged token was verified. */
function substituteRefused(site: Site, outcome: ImportOutcome, what: string): void {
  assert.equal(outcome.loaded, false, `${what}: the import throws`);
  assert.equal(outcome.forged, false, `${what}: no forged token verified`);
  assert.ok(!fs.existsSync(site.marker), `${what}: the substitute backend never ran`);
  assert.deepEqual(
    outcome.required.filter((f) => f === "binding.cjs" || f.endsWith(".node")),
    [],
    `${what}: neither the loader nor an addon was required`,
  );
  assert.match(outcome.error ?? "", /@polyjose\/node: /, `${what}: the package's own refusal`);
}

test("M1 control: the raw loader picks each planted substitute backend", () => {
  withSite({ ancestorFake: "platform" }, (site) => {
    assert.equal(requireRawLoader(site.pkg), 0);
    assert.ok(fs.existsSync(site.marker), "ancestor @polyjose/node-<platform>");
  });
  withSite({ nodePathFake: true }, (site) => {
    assert.equal(requireRawLoader(site.pkg, { NODE_PATH: path.join(site.root, "node-path") }), 0);
    assert.ok(fs.existsSync(site.marker), "NODE_PATH @polyjose/node-<platform>");
  });
  withSite({ ancestorFake: "wasi" }, (site) => {
    assert.equal(requireRawLoader(site.pkg), 0);
    assert.ok(fs.existsSync(site.marker), "ancestor @polyjose/node-wasm32-wasi");
  });
  withSite({}, (site) => {
    const fake = path.join(site.root, "fake-backend.cjs");
    fs.writeFileSync(fake, fakeBackend(site.marker));
    assert.equal(requireRawLoader(site.pkg, { NAPI_RS_NATIVE_LIBRARY_PATH: fake }), 0);
    assert.ok(fs.existsSync(site.marker), "NAPI_RS_NATIVE_LIBRARY_PATH to a JS file");
  });
});

test("M1: a fake platform package in an ancestor node_modules is refused before it runs", () => {
  withSite({ ancestorFake: "platform" }, (site) => {
    substituteRefused(site, importInChild(site.pkg), "ancestor fake");
  });
});

test("M1: a fake platform package on NODE_PATH is refused before it runs", () => {
  withSite({ nodePathFake: true }, (site) => {
    const outcome = importInChild(site.pkg, { NODE_PATH: path.join(site.root, "node-path") });
    substituteRefused(site, outcome, "NODE_PATH fake");
  });
});

test("M1: a fake WASI package in an ancestor node_modules is refused before it runs", () => {
  withSite({ ancestorFake: "wasi" }, (site) => {
    substituteRefused(site, importInChild(site.pkg), "ancestor WASI fake");
  });
});

test("M1 and I1: NAPI_RS_NATIVE_LIBRARY_PATH naming a JS file is refused before it runs", () => {
  withSite({ genuine: true }, (site) => {
    const fake = path.join(site.root, "fake-backend.cjs");
    fs.writeFileSync(fake, fakeBackend(site.marker));
    const outcome = importInChild(site.pkg, { NAPI_RS_NATIVE_LIBRARY_PATH: fake });
    substituteRefused(site, outcome, "override to a JS file");
    assert.match(outcome.error ?? "", /NAPI_RS_NATIVE_LIBRARY_PATH/);
  });
});

/**
 * M1's substitute backend as an ES module. The package is `"type": "module"`, so a `.js` file in it
 * is ESM, and the loader's `require` loads it through require(esm).
 */
const fakeEsmBackend = (marker: string): string =>
  [
    'import { writeFileSync } from "node:fs";',
    `writeFileSync(${JSON.stringify(marker)}, "ran");`,
    'export const version = () => "0.1.0";',
    'export const errorCodes = () => ["InvalidSignature"];',
    'export const jwsVerifyCompact = async () => ({ alg: "HS256", payload: new TextEncoder().encode(\'{"admin":true}\'), signatureIndex: 0, protectedHeader: \'{"alg":"HS256"}\' });',
    "",
  ].join("\n");

test("M1: a JS file posing as the local addon (polyjose.<platform>.node.js) is refused before it runs", () => {
  // require('./polyjose.<p>.node') resolves to './polyjose.<p>.node.js' when the addon is absent.
  const plant = (site: Site): void => fs.writeFileSync(path.join(site.pkg, `${hostAddon}.js`), fakeEsmBackend(site.marker));
  withSite({}, (site) => {
    plant(site);
    assert.equal(requireRawLoader(site.pkg), 0, "control: the raw loader loads it");
    assert.ok(fs.existsSync(site.marker), "control: the fake ran");
  });
  withSite({}, (site) => {
    plant(site);
    substituteRefused(site, importInChild(site.pkg), "local .node.js");
  });
});

test("M1: the genuine install loads, rejects the forged token, and shadows an ancestor fake", () => {
  for (const ancestorFake of [undefined, "platform"] as const) {
    withSite(ancestorFake === undefined ? { genuine: true } : { genuine: true, ancestorFake }, (site) => {
      const what = ancestorFake === undefined ? "genuine install" : "genuine install, ancestor fake";
      const outcome = importInChild(site.pkg);
      assert.equal(outcome.error, null, what);
      assert.equal(outcome.loaded, true, what);
      assert.equal(outcome.forged, false, `${what}: the forged token is rejected`);
      assert.equal(outcome.forgeryRejectedWith, "PolyjoseError", `${what}: by the core`);
      assert.ok(!fs.existsSync(site.marker), `${what}: the fake never ran`);
    });
  }
});
