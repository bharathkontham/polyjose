/**
 * [WASM-pkg-node] Load-time integrity of the installed package (feature 0006 F05, security
 * audit L1; ADR 0031 §3): only the shipped `.wasm`, of this package's version, backs the API.
 *
 * The audit's scenario is a co-installed module that reaches the package's internal files by
 * file URL (the `exports` map hides them from specifiers, not from paths):
 * - it initialises the glue `polyjose_wasm.js` with its own module before the app's first call
 *   (the glue's first initialisation wins for every importer), or
 * - it imports `backend.js` and calls `setLoader` with its own loader.
 * The audit's module was a planted build whose `jwsVerifyCompact` accepts any token. That
 * 720 KB build isn't reproduced here. The package refuses any module other than the one it
 * checked, at `ready()`, before any operation runs, so the stand-in is the shipped module plus
 * one custom section: a different, valid module whose imports match the glue's. Each case runs
 * in a child process (the glue's state is per process): this file, run with `child <case>`. The
 * same cases run in workerd too [WASM-pkg-workerd], one fresh miniflare each, with
 * `loader-integrity-worker.ts` as the worker: there the forged module is a second compiled
 * module of the bundle, and the glue and `backend.js` are reached by their module names.
 *
 * The integrity check itself runs on a scratch copy of the installed package: one flipped
 * `.wasm` byte is refused by the SHA-384 comparison before anything is compiled, and a changed
 * baked version is refused by the version check.
 */
import { outcome, refusedCalls, verifies } from "./loader-integrity-worker.js";
import { assert, childProcess, fs, path, process, resolveFrom, stageRoot, test, url } from "./node.js";

type Api = typeof import("@polyjose/wasm");

/** The glue, as a file-URL importer sees it (wasm-bindgen 0.2.130 `--target web`). */
interface Glue {
  initSync(module: unknown): unknown;
  default(moduleOrPath: unknown): Promise<unknown>;
}

/** `backend.js`, as a file-URL importer sees it. */
interface BackendFile {
  setLoader(load: () => unknown): void;
}

/** The fs members this file needs beyond `node.ts`'s. */
interface CopyFs {
  cpSync(from: string, to: string, options: { recursive: true }): void;
  writeFileSync(path: string, data: Uint8Array | string): void;
}

const copyFs = process.getBuiltinModule("node:fs") as unknown as CopyFs;
const RESULT = "RESULT ";

/** The installed package's directory (the `node` entry's parent). */
function packageDir(): string {
  return path.dirname(url.fileURLToPath(resolveFrom(import.meta, "@polyjose/wasm")));
}

function fileUrl(dir: string, file: string): string {
  return new URL(file, `file://${dir}/`).href;
}

/** The shipped module plus an empty custom section named "polyjose-f05-forged" (WebAssembly core §5.5.3). */
function forgedBytes(dir: string): Uint8Array<ArrayBuffer> {
  const shipped = fs.readFileSync(path.join(dir, "polyjose_wasm_bg.wasm"));
  const name = new TextEncoder().encode("polyjose-f05-forged");
  const section = new Uint8Array([0, 1 + name.length, name.length, ...name]);
  const out = new Uint8Array(shipped.length + section.length);
  out.set(shipped);
  out.set(section, shipped.length);
  return out;
}

/** One child case; prints one `RESULT <json>` line. */
async function child(name: string, dir: string): Promise<void> {
  const report: Record<string, unknown> = { case: name };
  switch (name) {
    case "clean": {
      const api = (await import("@polyjose/wasm")) as Api;
      Object.assign(report, await verifies(api));
      break;
    }
    case "pre-init-sync":
    case "pre-init-async": {
      // The audit's innocent-dep: the glue by file URL, initialised with another module first.
      const glue = (await import(fileUrl(dir, "polyjose_wasm.js"))) as Glue;
      const forged = new WebAssembly.Module(forgedBytes(dir));
      if (name === "pre-init-sync") glue.initSync({ module: forged });
      else void glue.default({ module_or_path: forged }).catch(() => undefined); // still pending
      Object.assign(report, await refusedCalls((await import("@polyjose/wasm")) as Api));
      break;
    }
    case "set-loader-after": {
      // The genuine entry registered its loader when it was evaluated; another one is refused,
      // before and after the first call.
      const api = (await import("@polyjose/wasm")) as Api;
      const backend = (await import(fileUrl(dir, "backend.js"))) as BackendFile;
      let called = false;
      const evil = (): unknown => {
        called = true;
        return new WebAssembly.Module(forgedBytes(dir));
      };
      report["beforeFirstCall"] = await outcome(async () => backend.setLoader(evil));
      Object.assign(report, await verifies(api));
      report["afterFirstCall"] = await outcome(async () => backend.setLoader(evil));
      report["evilCalled"] = called;
      break;
    }
    case "set-loader-first": {
      // Registered before the genuine entry is evaluated: importing the package then fails.
      const backend = (await import(fileUrl(dir, "backend.js"))) as BackendFile;
      let called = false;
      backend.setLoader(() => {
        called = true;
        return new WebAssembly.Module(forgedBytes(dir));
      });
      report["import"] = await outcome(() => import("@polyjose/wasm"));
      report["evilCalled"] = called;
      break;
    }
    case "copy": {
      // A scratch copy (flipped byte or changed version), loaded through its own node entry.
      const api = (await import(fileUrl(dir, "node.mjs"))) as Api;
      report["first"] = await outcome(() => api.base64urlEncode(new Uint8Array([1])));
      report["second"] = await outcome(() => api.base64urlEncode(new Uint8Array([1])));
      // Was the copy's glue instantiated? Its initSync reads the argument only if it wasn't.
      const glue = (await import(fileUrl(dir, "polyjose_wasm.js"))) as Glue;
      let read = false;
      try {
        glue.initSync({
          get module(): unknown {
            read = true;
            throw new Error("probe");
          },
        });
      } catch {
        // the probe's own throw
      }
      report["glueWasUninitialised"] = read;
      break;
    }
    default:
      throw new Error(`unknown child case ${name}`);
  }
  process.stdout.write(`${RESULT}${JSON.stringify(report)}\n`);
}

/** Runs `child <name> <dir>` in a fresh Node process and returns its report. */
function runChild(name: string, dir: string): Record<string, unknown> {
  const stage = stageRoot(import.meta);
  const run = childProcess.spawnSync(process.execPath, [url.fileURLToPath(import.meta.url), "child", name, dir], {
    cwd: stage,
    encoding: "utf8",
    timeout: 60_000,
  });
  if (run.error !== undefined) throw run.error;
  assert.equal(run.status, 0, `child ${name} failed: ${run.stderr}`);
  const line = run.stdout.split("\n").find((l) => l.startsWith(RESULT));
  assert.ok(line !== undefined, `child ${name} printed no result: ${run.stdout}${run.stderr}`);
  return JSON.parse(line.slice(RESULT.length)) as Record<string, unknown>;
}

/** A scratch copy of the installed package, changed by `edit`, under a fresh temp directory. */
function scratchCopy(edit: (dir: string) => void): { dir: string; done: () => void } {
  const root = fs.mkdtempSync(path.join(stageRoot(import.meta), "f05-copy-"));
  const dir = path.join(root, "wasm");
  copyFs.cpSync(packageDir(), dir, { recursive: true });
  edit(dir);
  return { dir, done: () => fs.rmSync(root, { recursive: true, force: true }) };
}

const REFUSED_FOREIGN = /^Error: polyjose: the WebAssembly module was initialised by other code/;
const REFUSED_LOADER = /^Error: polyjose: the WebAssembly loader is already registered/;
const CASES = ["clean", "pre-init-sync", "pre-init-async", "set-loader-after", "set-loader-first"] as const;

/** The expectations of one audit case, the same in Node and workerd. */
function expectCase(runtime: string, r: Record<string, unknown>): void {
  const what = `${runtime} ${String(r["case"])}`;
  switch (r["case"]) {
    case "clean":
      assert.equal(r["genuine"], "resolved", `${what}: a genuine token verifies`);
      assert.equal(r["otherKey"], "InvalidSignature", `${what}: another key's token is refused`);
      return;
    case "pre-init-sync":
    case "pre-init-async":
      // The glue initialised (or being initialised) by other code first: refused for good.
      for (const call of ["first", "second", "verify"]) assert.match(String(r[call]), REFUSED_FOREIGN, `${what}: ${call}`);
      return;
    case "set-loader-after":
      // The genuine entry registered its loader; another one is refused, before and after the
      // first call, and the API still runs on the checked module.
      for (const when of ["beforeFirstCall", "afterFirstCall"]) assert.match(String(r[when]), REFUSED_LOADER, `${what}: ${when}`);
      assert.equal(r["evilCalled"], false, `${what}: the other loader never runs`);
      assert.equal(r["genuine"], "resolved", what);
      assert.equal(r["otherKey"], "InvalidSignature", what);
      return;
    case "set-loader-first":
      // Registered before the genuine entry is evaluated: the entry's own registration throws, so
      // importing the package fails and the other loader never backs its API.
      assert.match(String(r["import"]), REFUSED_LOADER, what);
      assert.equal(r["evilCalled"], false, `${what}: the other loader never runs`);
      return;
    default:
      assert.fail(`${what}: unexpected report ${JSON.stringify(r)}`);
  }
}

/** The parts of miniflare's API used here, typed by hand (as `workerd.ts` does). */
interface ModuleDefinition {
  readonly type: "ESModule" | "CompiledWasm";
  readonly path: string;
}
interface Miniflare {
  dispatchFetch(url: string): Promise<{ readonly status: number; text(): Promise<string> }>;
  dispose(): Promise<void>;
}
interface MiniflareModule {
  Miniflare: new (options: { modules: readonly ModuleDefinition[]; modulesRoot: string; compatibilityDate: string }) => Miniflare;
}

/** Every module file of the installed package, as wrangler uploads it (`workerd.ts`). */
function packageModules(dir: string, out: ModuleDefinition[]): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) packageModules(full, out);
    else if (entry.isFile() && /\.m?js$/.test(entry.name)) out.push({ type: "ESModule", path: full });
    else if (entry.isFile() && entry.name.endsWith(".wasm")) out.push({ type: "CompiledWasm", path: full });
  }
}

/**
 * Runs one case in a fresh workerd: miniflare with `loader-integrity-worker.ts` as the entry, the
 * installed package's modules, and the forged module at `/f05/forged.wasm`.
 */
async function runWorkerd(name: string, forgedWasm: string): Promise<Record<string, unknown>> {
  const stage = stageRoot(import.meta);
  const modules: ModuleDefinition[] = [
    { type: "ESModule", path: path.join(stage, "dist", "loader-integrity-worker.js") },
    { type: "CompiledWasm", path: forgedWasm },
  ];
  packageModules(path.join(stage, "node_modules", "@polyjose", "wasm"), modules);
  const specifier = "miniflare";
  const { Miniflare } = (await import(specifier)) as MiniflareModule;
  // The workerd release miniflare 4.20260730.0 pins, as in workerd.ts.
  const mf = new Miniflare({ modules, modulesRoot: stage, compatibilityDate: "2026-07-30" });
  try {
    const response = await mf.dispatchFetch(`http://localhost/${name}`);
    const text = await response.text();
    assert.equal(response.status, 200, `workerd ${name}: ${text}`);
    return JSON.parse(text) as Record<string, unknown>;
  } finally {
    await mf.dispose();
  }
}

if (process.argv[2] === "child") {
  await child(process.argv[3] ?? "", process.argv[4] ?? "");
} else {
  const dir = packageDir();

  await test("L1 in Node: the audit's by-path glue and backend.js routes are refused; the genuine path works", () => {
    for (const name of CASES) expectCase("node", runChild(name, dir));
  });

  await test("L1 in workerd: the same routes are refused there too (no byte check on workerd, by decision)", async () => {
    const stage = stageRoot(import.meta);
    const forgedDir = path.join(stage, "f05");
    fs.mkdirSync(forgedDir, { recursive: true });
    const forgedWasm = path.join(forgedDir, "forged.wasm");
    copyFs.writeFileSync(forgedWasm, forgedBytes(dir));
    try {
      for (const name of CASES) expectCase("workerd", await runWorkerd(name, forgedWasm));
    } finally {
      fs.rmSync(forgedDir, { recursive: true, force: true });
    }
  });

  await test("L1: a .wasm with one flipped byte is refused by its SHA-384, and nothing is instantiated", () => {
    const copy = scratchCopy((d) => {
      const file = path.join(d, "polyjose_wasm_bg.wasm");
      const bytes = fs.readFileSync(file);
      const at = Math.floor(bytes.length / 2);
      bytes[at] = (bytes[at] ?? 0) ^ 0x01;
      copyFs.writeFileSync(file, bytes);
    });
    try {
      const r = runChild("copy", copy.dir);
      const refused = /^Error: polyjose: polyjose_wasm_bg\.wasm does not have the SHA-384 this package was built with/;
      assert.match(String(r["first"]), refused);
      assert.match(String(r["second"]), refused);
      assert.equal(r["glueWasUninitialised"], true, "the glue must not have been initialised");
    } finally {
      copy.done();
    }
  });

  await test("L1: a module whose version() differs from the version baked into the package is refused", () => {
    const copy = scratchCopy((d) => {
      const file = path.join(d, "integrity.js");
      const text = fs.readFileSync(file, "utf8");
      const changed = text.replace(/PACKAGE_VERSION = "[^"]*"/, 'PACKAGE_VERSION = "0.0.0-f05-mismatch"');
      assert.notEqual(changed, text, "integrity.js has no PACKAGE_VERSION");
      copyFs.writeFileSync(file, changed);
    });
    try {
      const r = runChild("copy", copy.dir);
      const refused = /^Error: polyjose: the WebAssembly module is version [^ ]+, but this package is 0\.0\.0-f05-mismatch; refusing/;
      assert.match(String(r["first"]), refused);
      assert.match(String(r["second"]), refused, "a version refusal is final");
    } finally {
      copy.done();
    }
  });
}
