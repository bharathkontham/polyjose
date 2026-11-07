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
const fs = host.getBuiltinModule("node:fs");
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
