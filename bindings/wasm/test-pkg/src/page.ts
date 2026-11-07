/**
 * [WASM-pkg-chrome] The page script of the Chrome run (`chrome.ts`). It imports
 * `@polyjose/wasm`, which the page's import map points at the installed package's `browser.mjs`
 * (the entry its `browser` condition selects; ADR 0031 §3), fetches the vectors the host serves
 * as JSON, runs the shared runner over them (`results.ts`), and writes:
 * - `<pre id="security">`: the security checks of `security-checks.ts` (review N8), run first, so
 *   the input-copy check sees a cold module;
 * - `<pre id="probe">`: the error-shape probe;
 * - `<pre id="results">`: the ADR 0034 §2 results document, last, so its presence means done;
 * - or `<pre id="error">` if anything threw.
 * Chrome's `--dump-dom` prints the DOM, from which the host extracts them.
 */
import * as api from "@polyjose/wasm";
import { errorShapeProbe, resultsDocument, type VectorInput } from "./results.js";
import { securityReport } from "./security-checks.js";

function show(id: string, text: string): void {
  const pre = document.createElement("pre");
  pre.id = id;
  pre.textContent = text;
  document.body.append(pre);
}

async function run(): Promise<void> {
  // The page's first API call: nothing has instantiated the module yet.
  show("security", JSON.stringify(await securityReport(api, true)));
  const response = await fetch("/vectors.json");
  if (!response.ok) throw new Error(`GET /vectors.json: ${response.status}`);
  const input = (await response.json()) as VectorInput;
  show("probe", JSON.stringify(await errorShapeProbe(api)));
  show("results", JSON.stringify(await resultsDocument(api, "wasm-pkg-chrome", input)));
}

run().catch((e: unknown) => {
  show("error", e instanceof Error ? `${e.name}: ${e.message}\n${e.stack ?? ""}` : String(e));
});
