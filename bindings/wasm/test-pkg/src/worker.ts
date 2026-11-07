/**
 * [WASM-pkg-workerd] The worker of the workerd run (`workerd.ts`, miniflare). It imports
 * `@polyjose/wasm` as a Worker would; the driver maps that name to the entry the package's
 * `workerd` condition selects (`workerd.mjs`, which imports the `.wasm` as a compiled
 * `WebAssembly.Module`; ADR 0031 §3), as wrangler's bundler does.
 * - `GET /security`: the security checks of `security-checks.ts` (review N8). The host calls it
 *   first; its input-copy check is cold only if no other route ran an API call before, which the
 *   worker tracks, so a reordering fails instead of silently testing a warm module;
 * - `GET /probe`: the error-shape probe (`results.ts`);
 * - `POST /run` with the vectors (JSON, from the host): the ADR 0034 §2 results document.
 */
import * as api from "@polyjose/wasm";
import { errorShapeProbe, resultsDocument, type VectorInput } from "./results.js";
import { securityReport } from "./security-checks.js";

/** Whether a route of this isolate has already called the API (so the module may be instantiated). */
let apiCalled = false;

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json; charset=utf-8" } });
}

export default {
  async fetch(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);
    try {
      const cold = !apiCalled;
      apiCalled = true;
      if (request.method === "GET" && pathname === "/security") return json(await securityReport(api, cold));
      if (request.method === "GET" && pathname === "/probe") return json(await errorShapeProbe(api));
      if (request.method === "POST" && pathname === "/run") {
        const input = (await request.json()) as VectorInput;
        return json(await resultsDocument(api, "wasm-pkg-workerd", input));
      }
      return json({ error: `no route ${request.method} ${pathname}` }, 404);
    } catch (e) {
      return json({ error: e instanceof Error ? `${e.name}: ${e.message}\n${e.stack ?? ""}` : String(e) }, 500);
    }
  },
};
