/**
 * [WASM-pkg-chrome] The headless Chrome run of the installed package (ADR 0031 §3 "Runtimes",
 * ADR 0034 §2 runner `wasm-pkg-chrome`):
 * 1. resolves the entry the package's `browser` condition selects (`browser.mjs`);
 * 2. serves the page, the vectors (as JSON), the compiled page and runner, and the installed
 *    package from a tiny `node:http` server on 127.0.0.1 (`server.ts`);
 * 3. runs Chrome with `--headless=new --dump-dom --virtual-time-budget=<ms>` and a throwaway
 *    profile; the page (`page.ts`) writes the results into `<pre id="results">`;
 * 4. extracts the document and writes `target/conformance/wasm-pkg-chrome.json` (`host.ts`).
 *
 * Chrome is `POLYJOSE_CHROME` if set, else the installed macOS app. Without it this prints
 * `SKIPPED (...)` and exits 0, writing no results file; `run.sh` then prints the waiver
 * `SKIPPED-RUNNER (wasm-pkg-chrome: host:no-chrome)`, and scripts/test-all.sh reports the runner
 * SKIPPED, never passing (ADR 0060 §7, pipeline rule 9). Exit 1 on any failure.
 */
import { collectVectors, reportProbe, resolveEntry, writeResults } from "./host.js";
import { childProcess, fs, path, process, repoRoot, stageRoot } from "./node.js";
import { startServer } from "./server.js";

const RUNNER = "wasm-pkg-chrome";
const MAC_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
/** Chrome's virtual-time budget: the page's work never waits on a timer, so this only bounds it. */
const VIRTUAL_TIME_BUDGET_MS = 600_000;
/** A real-time bound on the Chrome process, which is killed (by its PID) past it. */
const CHROME_TIMEOUT_MS = 600_000;

/** Undoes the escaping of text inside an element in Chrome's serialized DOM (HTML §13.3). */
function unescapeText(text: string): string {
  return text.replace(/&(amp|lt|gt|nbsp);/g, (_, name: string) =>
    name === "amp" ? "&" : name === "lt" ? "<" : name === "gt" ? ">" : " ",
  );
}

/** The text of every `<pre id="...">` in the dumped DOM. */
function preTexts(dom: string): Map<string, string> {
  const found = new Map<string, string>();
  for (const m of dom.matchAll(/<pre id="(results|probe|error)">([\s\S]*?)<\/pre>/g)) {
    if (m[1] !== undefined && m[2] !== undefined) found.set(m[1], unescapeText(m[2]));
  }
  return found;
}

/** Runs Chrome on `url`; resolves with its stdout (the DOM) once it exits. */
function dumpDom(chrome: string, profile: string, url: string): Promise<{ code: number | null; dom: string; log: string }> {
  const child = childProcess.spawn(
    chrome,
    [
      "--headless=new",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--disable-gpu",
      `--virtual-time-budget=${VIRTUAL_TIME_BUDGET_MS}`,
      "--dump-dom",
      url,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let dom = "";
  let log = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    dom += chunk;
  });
  child.stderr.on("data", (chunk) => {
    log += chunk;
  });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      // Only the process we started, by its handle (its PID); never by pattern.
      child.kill("SIGTERM");
      reject(new Error(`Chrome did not exit within ${CHROME_TIMEOUT_MS} ms (killed pid ${String(child.pid)})`));
    }, CHROME_TIMEOUT_MS);
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, dom, log });
    });
  });
}

async function main(): Promise<number> {
  const chrome = process.env["POLYJOSE_CHROME"] ?? MAC_CHROME;
  if (!fs.existsSync(chrome)) {
    process.stdout.write(`SKIPPED (Chrome not found: ${chrome}; set POLYJOSE_CHROME to its binary)\n`);
    return 0;
  }
  const root = repoRoot();
  const stage = stageRoot(import.meta);
  const packageDir = path.join(stage, "node_modules", "@polyjose", "wasm");
  const entry = resolveEntry(packageDir, ["browser", "import", "default"]);
  if (entry !== "./browser.mjs") throw new Error(`the browser condition resolves ${entry}, expected ./browser.mjs (ADR 0031 §3)`);

  const importMap = JSON.stringify({ imports: { "@polyjose/wasm": `/node_modules/@polyjose/wasm/${entry.slice(2)}` } });
  const page = `<!doctype html>
<html><head><meta charset="utf-8"><title>polyjose ${RUNNER}</title>
<script type="importmap">${importMap}</script>
<script type="module" src="/dist/page.js"></script>
</head><body></body></html>
`;
  const server = await startServer(stage, ["/dist/", "/js/", "/node_modules/@polyjose/wasm/"], {
    "/": { type: "text/html; charset=utf-8", body: page },
    "/vectors.json": { type: "application/json; charset=utf-8", body: JSON.stringify(collectVectors(root)) },
  });
  const profile = fs.mkdtempSync(path.join(stage, "chrome-profile-"));
  try {
    const run = await dumpDom(chrome, profile, `${server.origin}/`);
    const pres = preTexts(run.dom);
    const error = pres.get("error");
    if (error !== undefined) throw new Error(`the page threw: ${error}`);
    const results = pres.get("results");
    if (results === undefined) {
      throw new Error(`no <pre id="results"> in the page (Chrome exit ${String(run.code)}); DOM: ${run.dom.slice(0, 2000)}\nChrome log: ${run.log.slice(-2000)}`);
    }
    const probe = pres.get("probe");
    const probeOk = reportProbe(RUNNER, probe === undefined ? null : JSON.parse(probe));
    const code = writeResults(root, RUNNER, JSON.parse(results));
    return probeOk && code === 0 ? 0 : 1;
  } finally {
    await server.close();
    fs.rmSync(profile, { recursive: true, force: true });
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
