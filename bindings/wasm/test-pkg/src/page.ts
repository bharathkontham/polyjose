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
 *
 * Whether the security checks run cold is read from the page's state, not assumed (0006 F04
 * tester finding A): every call goes through {@link tracked}, which records it, as the worker's
 * `apiCalled` does, and the module's `.wasm` must not have been fetched yet (the browser entry
 * fetches it inside the first call, ADR 0062 §1). Moving any call before the checks makes their
 * cold input-copy check fail instead of silently testing a warm module.
 */
import * as raw from "@polyjose/wasm";
import type { PolyjoseApi } from "../js/src/api.js";
import { errorShapeProbe, resultsDocument, type VectorInput } from "./results.js";
import { securityReport } from "./security-checks.js";

/** `raw` with every operation call recorded; the error class and constants pass through as they are. */
function tracked(target: PolyjoseApi): { api: PolyjoseApi; called: () => boolean } {
  let called = false;
  const api = new Proxy(target, {
    get(t, key, receiver): unknown {
      const value: unknown = Reflect.get(t, key, receiver);
      if (typeof value !== "function" || key === "PolyjoseError") return value;
      return (...args: unknown[]): unknown => {
        called = true;
        return Reflect.apply(value, t, args);
      };
    },
  });
  return { api, called: () => called };
}

const { api, called } = tracked(raw);

/** Whether the page has fetched a `.wasm` (Resource Timing records each completed fetch). */
function wasmFetched(): boolean {
  return performance.getEntriesByType("resource").some((e) => new URL(e.name).pathname.endsWith(".wasm"));
}

function show(id: string, text: string): void {
  const pre = document.createElement("pre");
  pre.id = id;
  pre.textContent = text;
  document.body.append(pre);
}

async function run(): Promise<void> {
  show("security", JSON.stringify(await securityReport(api, !called() && !wasmFetched())));
  const response = await fetch("/vectors.json");
  if (!response.ok) throw new Error(`GET /vectors.json: ${response.status}`);
  const input = (await response.json()) as VectorInput;
  show("probe", JSON.stringify(await errorShapeProbe(api)));
  show("results", JSON.stringify(await resultsDocument(api, "wasm-pkg-chrome", input)));
}

run().catch((e: unknown) => {
  show("error", e instanceof Error ? `${e.name}: ${e.message}\n${e.stack ?? ""}` : String(e));
});
