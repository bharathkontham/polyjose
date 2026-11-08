/**
 * A tiny static HTTP server for the Chrome run (`chrome.ts`), on `node:http` alone (no npm
 * dependency). It listens on 127.0.0.1 on a free port and serves, read-only:
 * - the fixed routes it is given (the page and the vectors document), and
 * - files under `root` whose path starts with one of `prefixes` and whose type it knows.
 * Anything else, any method but GET, and any path that leaves `root` is 404/405. The `.wasm` is
 * served as `application/wasm`, which `WebAssembly.instantiateStreaming` (the glue's `init()`)
 * requires.
 */
import { fs, http, path, type IncomingMessage, type ServerResponse } from "./node.js";

const TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
};

/** A fixed route: its content type and body. */
export interface Route {
  readonly type: string;
  readonly body: string;
}

export interface StaticServer {
  /** `http://127.0.0.1:<port>`. */
  readonly origin: string;
  close(): Promise<void>;
}

function send(res: ServerResponse, status: number, type: string, body: string | Uint8Array): void {
  res.writeHead(status, { "content-type": type, "cache-control": "no-store", "x-content-type-options": "nosniff" });
  res.end(body);
}

function handle(root: string, prefixes: readonly string[], routes: Readonly<Record<string, Route>>, req: IncomingMessage, res: ServerResponse): void {
  if (req.method !== "GET") return send(res, 405, "text/plain", "method not allowed");
  let pathname: string;
  try {
    pathname = decodeURIComponent(new URL(req.url ?? "/", "http://127.0.0.1").pathname);
  } catch {
    return send(res, 400, "text/plain", "bad request");
  }
  const route = routes[pathname];
  if (route !== undefined) return send(res, 200, route.type, route.body);
  const type = TYPES[path.extname(pathname)];
  const segments = pathname.split("/");
  if (
    type === undefined ||
    pathname.includes("\0") ||
    segments.includes("..") ||
    segments.includes(".") ||
    !prefixes.some((p) => pathname.startsWith(p))
  ) {
    return send(res, 404, "text/plain", "not found");
  }
  const file = path.join(root, ...segments.filter((s) => s !== ""));
  const rel = path.relative(root, file);
  if (rel.startsWith("..") || path.resolve(root, rel) !== file) return send(res, 404, "text/plain", "not found");
  let body: Uint8Array;
  try {
    body = fs.readFileSync(file);
  } catch {
    return send(res, 404, "text/plain", "not found");
  }
  send(res, 200, type, body);
}

/** Starts the server; resolves once it listens. */
export function startServer(root: string, prefixes: readonly string[], routes: Readonly<Record<string, Route>>): Promise<StaticServer> {
  const server = http.createServer((req, res) => {
    handle(root, prefixes, routes, req, res);
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("the server has no TCP port"));
        return;
      }
      resolve({
        origin: `http://127.0.0.1:${address.port}`,
        close: () =>
          new Promise<void>((done) => {
            server.closeAllConnections();
            server.close(() => {
              done();
            });
          }),
      });
    });
  });
}
