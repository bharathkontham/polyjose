/**
 * Typed access to the few Node built-ins the tests, `conformance/node-main.ts` and the
 * build tools use.
 *
 * `bindings/js` has exactly one dev-dependency, `typescript` (ADR 0047), so there is no
 * `@types/node`. Instead of hand-written ambient declarations, each module is fetched with
 * `process.getBuiltinModule` (Node >= 22.3, inside the ADR 0031 floor of 22.12) and typed
 * here with only the members we call. Nothing under `src/` or `conformance/runner.ts`
 * imports this file: the facade and the runner must also run in browsers and workerd.
 */

export interface Dirent {
  readonly name: string;
  isDirectory(): boolean;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}

export interface NodeFs {
  readFileSync(path: string, encoding: "utf8"): string;
  writeFileSync(path: string, data: string): void;
  readdirSync(path: string, options: { withFileTypes: true }): Dirent[];
  mkdirSync(path: string, options: { recursive: true }): string | undefined;
  mkdtempSync(prefix: string): string;
  rmSync(path: string, options: { recursive: true; force: true }): void;
  symlinkSync(target: string, path: string): void;
  existsSync(path: string): boolean;
}

export interface NodePath {
  join(...parts: string[]): string;
  resolve(...parts: string[]): string;
  relative(from: string, to: string): string;
  dirname(path: string): string;
  readonly sep: string;
}

export interface NodeOs {
  tmpdir(): string;
}

export interface TestContext {
  readonly name: string;
}

export type TestFn = (t: TestContext) => void | Promise<void>;

export interface NodeTest {
  test(name: string, fn: TestFn): Promise<void>;
}

export interface NodeAssert {
  ok(value: unknown, message?: string): asserts value;
  equal(actual: unknown, expected: unknown, message?: string): void;
  notEqual(actual: unknown, expected: unknown, message?: string): void;
  deepEqual(actual: unknown, expected: unknown, message?: string): void;
  notDeepEqual(actual: unknown, expected: unknown, message?: string): void;
  match(value: string, pattern: RegExp, message?: string): void;
  doesNotMatch(value: string, pattern: RegExp, message?: string): void;
  throws(fn: () => unknown, expected?: unknown, message?: string): void;
  rejects(promise: Promise<unknown> | (() => Promise<unknown>), expected?: unknown, message?: string): Promise<void>;
  fail(message?: string): never;
}

export interface NodeProcess {
  readonly argv: readonly string[];
  cwd(): string;
  exitCode: number | undefined;
  readonly stderr: { write(text: string): boolean };
  readonly stdout: { write(text: string): boolean };
  getBuiltinModule(id: "node:fs"): NodeFs;
  getBuiltinModule(id: "node:path"): NodePath;
  getBuiltinModule(id: "node:os"): NodeOs;
  getBuiltinModule(id: "node:test"): NodeTest;
  getBuiltinModule(id: "node:assert/strict"): NodeAssert;
}

/** Node's `process`, typed with only what we use. */
export const process: NodeProcess = (globalThis as unknown as { process: NodeProcess }).process;

export const fs: NodeFs = process.getBuiltinModule("node:fs");
export const path: NodePath = process.getBuiltinModule("node:path");
export const os: NodeOs = process.getBuiltinModule("node:os");
export const assert: NodeAssert = process.getBuiltinModule("node:assert/strict");
export const test: NodeTest["test"] = process.getBuiltinModule("node:test").test;
