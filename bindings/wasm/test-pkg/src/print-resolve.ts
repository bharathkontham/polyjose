/**
 * Prints what Node resolves `@polyjose/wasm` to, under the conditions this process was started
 * with (`node -C workerd print-resolve.js`). `resolution.test.ts` runs it as a child process,
 * because the conditions are fixed per process (ADR 0031 §3 and ADR 0063, the `exports` order).
 *
 * `print-resolve.js --exact-conditions worker,browser,import` resolves with exactly those
 * conditions instead. Node always adds `node` (and `import` or `require`) to its own set, so a
 * bundler's set without `node`, such as webpack's for `target: "webworker"`, can't be given with
 * `-C`. A synchronous `module.registerHooks` resolve hook (Node >= 22.15; the workflow and the
 * host run Node 24.21.0) hands Node's own resolver the replaced set, so the `exports` algorithm
 * is Node's, not a copy (Node "Conditional exports": the first key in the map's order that is
 * one of the conditions, `default` always matching).
 */
import { process, resolveFrom } from "./node.js";

interface ResolveContext {
  readonly conditions: readonly string[];
}
type NextResolve = (specifier: string, context: ResolveContext) => unknown;
interface ModuleHooks {
  registerHooks?(hooks: {
    resolve(specifier: string, context: ResolveContext, nextResolve: NextResolve): unknown;
  }): unknown;
}

const args = process.argv.slice(2);
if (args.length === 2 && args[0] === "--exact-conditions") {
  const conditions = (args[1] ?? "").split(",").filter((c) => c !== "");
  const nodeModule = process.getBuiltinModule("node:module") as unknown as ModuleHooks;
  if (typeof nodeModule.registerHooks !== "function") {
    throw new Error(`${process.execPath} has no module.registerHooks (Node >= 22.15): can't resolve exact conditions`);
  }
  nodeModule.registerHooks({
    resolve: (specifier, context, nextResolve) => nextResolve(specifier, { ...context, conditions }),
  });
} else if (args.length !== 0) {
  throw new Error(`usage: print-resolve.js [--exact-conditions a,b,c] (got ${args.join(" ")})`);
}

process.stdout.write(resolveFrom(import.meta, "@polyjose/wasm"));
