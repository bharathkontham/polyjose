/**
 * Typed access to the Node built-ins the test-pkg drivers and tests use.
 *
 * test-pkg has one npm dependency, `miniflare` (0006 T04), so there is no `@types/node`. As in
 * `bindings/js/node/builtins.ts`, each module is fetched with `process.getBuiltinModule`
 * (Node >= 22.3, inside the ADR 0031 floor of 22.12) and typed here with only the members we
 * call. The browser page (`page.ts`), the worker (`worker.ts`) and `results.ts` never import
 * this file: they run in Chrome and workerd.
 */

export interface Dirent {
  readonly name: string;
  isDirectory(): boolean;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}

export interface NodeFs {
  readFileSync(path: string, encoding: "utf8"): string;
  readFileSync(path: string): Uint8Array;
  writeFileSync(path: string, data: string): void;
  readdirSync(path: string, options: { withFileTypes: true }): Dirent[];
  mkdirSync(path: string, options: { recursive: true }): string | undefined;
  mkdtempSync(prefix: string): string;
  rmSync(path: string, options: { recursive: true; force: true }): void;
  existsSync(path: string): boolean;
  realpathSync(path: string): string;
}

export interface NodePath {
  join(...parts: string[]): string;
  resolve(...parts: string[]): string;
  relative(from: string, to: string): string;
  dirname(path: string): string;
  extname(path: string): string;
  readonly sep: string;
}

export interface NodeUrl {
  fileURLToPath(url: string | URL): string;
}

export interface IncomingMessage {
  readonly method?: string;
  readonly url?: string;
}

export interface ServerResponse {
  writeHead(status: number, headers: Record<string, string>): void;
  end(body?: string | Uint8Array): void;
}

export interface Server {
  listen(port: number, host: string, callback: () => void): void;
  address(): { port: number } | string | null;
  close(callback?: (err?: Error) => void): void;
  closeAllConnections(): void;
  on(event: "error", listener: (err: Error) => void): void;
}

export interface NodeHttp {
  createServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Server;
}

export interface Readable {
  setEncoding(encoding: "utf8"): void;
  on(event: "data", listener: (chunk: string) => void): void;
}

export interface ChildProcess {
  readonly pid?: number;
  readonly stdout: Readable;
  readonly stderr: Readable;
  kill(signal?: string): boolean;
  on(event: "close", listener: (code: number | null, signal: string | null) => void): void;
  on(event: "error", listener: (err: Error) => void): void;
}

export interface SpawnSyncResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: Error;
}

export interface NodeChildProcess {
  spawn(command: string, args: readonly string[], options: { stdio: ["ignore", "pipe", "pipe"] }): ChildProcess;
  spawnSync(
    command: string,
    args: readonly string[],
    options: { cwd: string; encoding: "utf8"; timeout: number },
  ): SpawnSyncResult;
}

export type NodeRequire = ((id: string) => unknown) & { resolve(id: string): string };

export interface NodeModule {
  createRequire(from: string | URL): NodeRequire;
}

export interface TestContext {
  readonly name: string;
}

export interface NodeTest {
  test(name: string, fn: (t: TestContext) => void | Promise<void>): Promise<void>;
}

export interface NodeAssert {
  ok(value: unknown, message?: string): asserts value;
  equal(actual: unknown, expected: unknown, message?: string): void;
  notEqual(actual: unknown, expected: unknown, message?: string): void;
  deepEqual(actual: unknown, expected: unknown, message?: string): void;
  match(value: string, pattern: RegExp, message?: string): void;
  rejects(promise: Promise<unknown> | (() => Promise<unknown>), expected?: unknown, message?: string): Promise<void>;
  fail(message?: string): never;
}

export interface NodeProcess {
  readonly argv: readonly string[];
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly execPath: string;
  readonly platform: string;
  exitCode: number | undefined;
  readonly stderr: { write(text: string): boolean };
  readonly stdout: { write(text: string): boolean };
  getBuiltinModule(id: "node:fs"): NodeFs;
  getBuiltinModule(id: "node:path"): NodePath;
  getBuiltinModule(id: "node:url"): NodeUrl;
  getBuiltinModule(id: "node:http"): NodeHttp;
  getBuiltinModule(id: "node:child_process"): NodeChildProcess;
  getBuiltinModule(id: "node:module"): NodeModule;
  getBuiltinModule(id: "node:test"): NodeTest;
  getBuiltinModule(id: "node:assert/strict"): NodeAssert;
}

/** Node's `process`, typed with only what we use. */
export const process: NodeProcess = (globalThis as unknown as { process: NodeProcess }).process;

export const fs: NodeFs = process.getBuiltinModule("node:fs");
export const path: NodePath = process.getBuiltinModule("node:path");
export const url: NodeUrl = process.getBuiltinModule("node:url");
export const http: NodeHttp = process.getBuiltinModule("node:http");
export const childProcess: NodeChildProcess = process.getBuiltinModule("node:child_process");
export const nodeModule: NodeModule = process.getBuiltinModule("node:module");
export const assert: NodeAssert = process.getBuiltinModule("node:assert/strict");
export const test: NodeTest["test"] = process.getBuiltinModule("node:test").test;

/** `import.meta.resolve` (Node >= 20.6), which the ES2022/DOM libraries don't declare. */
export function resolveFrom(meta: ImportMeta, specifier: string): string {
  return (meta as unknown as { resolve(specifier: string): string }).resolve(specifier);
}

/**
 * The polyjose repository root, which `run.sh` passes as `POLYJOSE_REPO`: the vectors, the
 * schema and `target/conformance/` are under it (ADR 0034 §2).
 */
export function repoRoot(): string {
  const root = process.env["POLYJOSE_REPO"];
  if (root === undefined || root === "") {
    throw new Error("POLYJOSE_REPO is not set: run bindings/wasm/test-pkg/run.sh from the repository");
  }
  return root;
}

/** The staging project `run.sh` assembled (`<repo>/target/wasm-test-pkg`): `dist/`'s parent. */
export function stageRoot(meta: ImportMeta): string {
  return path.dirname(path.dirname(url.fileURLToPath(meta.url)));
}
