/**
 * [WASM-pkg-workerd] The workerd run of the installed package (ADR 0031 §3 "Runtimes": Cloudflare
 * Workers through the pinned `miniflare` dev-dependency; ADR 0034 §2 runner `wasm-pkg-workerd`):
 * 1. resolves the entry the package's exports give under wrangler's conditions (`workerd`,
 *    `worker`, `browser`, then `import`/`default`), which must be `workerd.mjs`;
 * 2. starts miniflare with the worker (`worker.ts`), its imports, every module of the staged
 *    shared facade and runner (`js/`, so a file added there can't break this run; 0006 F08),
 *    and every module of the installed package (`.js`/`.mjs` as ES modules, the `.wasm` as a
 *    compiled module, as wrangler uploads it). workerd has no `node_modules` resolution, so, as a
 *    bundler does, the name `@polyjose/wasm` is one module re-exporting the resolved entry;
 * 3. runs the security checks first (`GET /security`, `security-checks.ts`, review N8: the
 *    worker's first API call, so its input-copy check is cold), then the probe and the vectors
 *    (sent as the request body), and writes `target/conformance/wasm-pkg-workerd.json` from the
 *    response (`host.ts`). A failing security check fails the run but never changes that file.
 * Miniflare starts and stops its own workerd process (`dispose()`). Exit 1 on any failure.
 */
import { collectVectors, reportProbe, resolveEntry, writeResults } from "./host.js";
import { fs, path, process, repoRoot, stageRoot } from "./node.js";
import { securityLines } from "./security-checks.js";

const RUNNER = "wasm-pkg-workerd";
/** The workerd release miniflare 4.20260730.0 pins (workerd 1.20260730.1). */
const COMPATIBILITY_DATE = "2026-07-30";
/** A real-time bound on each request to the worker. */
const REQUEST_TIMEOUT_MS = 600_000;

/** The parts of miniflare's API used here, typed by hand (no @types/node for its declarations). */
interface ModuleDefinition {
  readonly type: "ESModule" | "CompiledWasm";
  readonly path: string;
  readonly contents?: string;
}
interface MiniflareResponse {
  readonly status: number;
  text(): Promise<string>;
}
interface MiniflareInstance {
  dispatchFetch(url: string, init?: { method: string; body: string; headers: Record<string, string> }): Promise<MiniflareResponse>;
  dispose(): Promise<void>;
}
interface MiniflareModule {
  Miniflare: new (options: {
    modules: readonly ModuleDefinition[];
    modulesRoot: string;
    compatibilityDate: string;
  }) => MiniflareInstance;
}

/**
 * Every module file under `dir`, by its path under the staging root, in name order (so the list
 * is the same on every run): `.js`/`.mjs` as ES modules, `.wasm` as a compiled module. A module
 * that nothing imports is registered but never evaluated.
 */
function modulesUnder(dir: string, out: ModuleDefinition[]): void {
  const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) modulesUnder(full, out);
    else if (entry.isFile() && /\.m?js$/.test(entry.name)) out.push({ type: "ESModule", path: full });
    else if (entry.isFile() && entry.name.endsWith(".wasm")) out.push({ type: "CompiledWasm", path: full });
  }
}

function withTimeout<T>(what: string, promise: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${what}: no response within ${REQUEST_TIMEOUT_MS} ms`));
    }, REQUEST_TIMEOUT_MS);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}

/** The JSON body of a 200 response, or an error with the worker's message. */
async function jsonBody(what: string, response: MiniflareResponse): Promise<unknown> {
  const text = await response.text();
  if (response.status !== 200) throw new Error(`${what}: HTTP ${response.status}: ${text.slice(0, 2000)}`);
  return JSON.parse(text);
}

async function main(): Promise<number> {
  const root = repoRoot();
  const stage = stageRoot(import.meta);
  const packageDir = path.join(stage, "node_modules", "@polyjose", "wasm");
  const entry = resolveEntry(packageDir, ["workerd", "worker", "browser", "import", "default"]);
  if (entry !== "./workerd.mjs") throw new Error(`the workerd condition resolves ${entry}, expected ./workerd.mjs (ADR 0031 §3)`);

  // The worker is the first module (the entry point), then its own imports. The shared facade
  // and runner (js/) and the package come from walking their directories: workerd fails to start
  // if an imported module is missing, and a hand-kept list missed one (0013 F13's own.js).
  const modules: ModuleDefinition[] = [
    { type: "ESModule", path: path.join(stage, "dist", "worker.js") },
    { type: "ESModule", path: path.join(stage, "dist", "results.js") },
    { type: "ESModule", path: path.join(stage, "dist", "security-checks.js") },
    // workerd resolves an import as a module name relative to the importing module's name, so the
    // worker's `@polyjose/wasm` is `dist/@polyjose/wasm`; it re-exports the resolved entry by its
    // absolute name.
    {
      type: "ESModule",
      path: path.join(stage, "dist", "@polyjose", "wasm"),
      contents: `export * from "/node_modules/@polyjose/wasm/${entry.slice(2)}";\n`,
    },
  ];
  modulesUnder(path.join(stage, "js"), modules);
  modulesUnder(packageDir, modules);

  const specifier = "miniflare";
  const { Miniflare } = (await import(specifier)) as MiniflareModule;
  const mf = new Miniflare({ modules, modulesRoot: stage, compatibilityDate: COMPATIBILITY_DATE });
  try {
    const security = await jsonBody("GET /security", await withTimeout("GET /security", mf.dispatchFetch("http://localhost/security")));
    const sec = securityLines(RUNNER, security);
    for (const line of sec.lines) process.stdout.write(`${line}\n`);
    const probe = await jsonBody("GET /probe", await withTimeout("GET /probe", mf.dispatchFetch("http://localhost/probe")));
    const probeOk = reportProbe(RUNNER, probe);
    const body = JSON.stringify(collectVectors(root));
    const doc = await jsonBody(
      "POST /run",
      await withTimeout(
        "POST /run",
        mf.dispatchFetch("http://localhost/run", { method: "POST", body, headers: { "content-type": "application/json" } }),
      ),
    );
    const code = writeResults(root, RUNNER, doc);
    return probeOk && sec.ok && code === 0 ? 0 : 1;
  } finally {
    await mf.dispose();
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stderr.write(`conformance (${RUNNER}): ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 1;
  },
);
