/**
 * Prints what Node resolves `@polyjose/wasm` to, under the conditions this process was started
 * with (`node -C workerd print-resolve.js`). `resolution.test.ts` runs it as a child process,
 * because the conditions are fixed per process (ADR 0031 §3, the `exports` order).
 */
import { process, resolveFrom } from "./node.js";

process.stdout.write(resolveFrom(import.meta, "@polyjose/wasm"));
