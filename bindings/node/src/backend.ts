/**
 * The napi-rs backend of `@polyjose/node` (ADR 0031 §1-§2, `bindings/js/BACKEND.md`).
 *
 * The generated loader `binding.cjs` (`napi build --platform --js binding.cjs`) already is the
 * backend contract: one function per ADR 0030 §4 operation, camelCase, in the ADR's argument
 * order, rejecting with an `Error` whose `code` is one of `errorCodes()` (ADR 0030 §5). So this
 * module only loads it and gives it the facade's `Backend` type; it adds no logic and renames
 * nothing.
 *
 * The loader is CommonJS (it picks the platform's `.node` file at run time), loaded here through
 * `createRequire`, so the package stays ESM-only (ADR 0031 §3). Its types come from the generated
 * `binding.d.ts`.
 */

import type { Backend } from "./facade/backend.js";
import type * as Binding from "./binding.js";

interface NodeModule {
  createRequire(from: string): (id: string) => unknown;
}

// Node built-ins without @types/node (ADR 0047: typescript is the only dev-dependency), as in
// bindings/js/node/builtins.ts; process.getBuiltinModule exists from Node 22.3, under the 22.12 floor.
const host = (globalThis as unknown as { process: { getBuiltinModule(id: "node:module"): NodeModule } }).process;
const moduleUrl = (import.meta as unknown as { url: string }).url;
const binding = host.getBuiltinModule("node:module").createRequire(moduleUrl)("./binding.cjs") as typeof Binding;

/**
 * Every `Backend` operation exists in the binding, under the same name, and accepts the arguments
 * the facade passes (checked at compile time against the generated `binding.d.ts`). The binding
 * declares its results as `Promise<unknown>` (its tasks resolve through a conversion trait), so
 * the result types are the contract's (BACKEND.md), proven by the conformance run.
 */
type AcceptsFacadeArguments = {
  readonly [K in Exclude<keyof Backend, "ready">]: (...args: Parameters<Backend[K]>) => unknown;
};

/** The napi loader, typed as the facade's backend. */
export const backend: Backend = (binding satisfies AcceptsFacadeArguments) as unknown as Backend;
