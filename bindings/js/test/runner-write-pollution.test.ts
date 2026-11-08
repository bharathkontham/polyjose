// The conformance runner builds the option records it hands the facade (`aad`, `detachedPayload`,
// `apu`, `apv`, headers, policy members, the `JweRecipient` list with its keys) and its own
// output record (`plaintext_b64u`, `jwk`, `claims`, ...). It is a caller of the facade, so it is
// held to the facade's rule (0013 F13): none of those members is created by an assignment that a
// setter on `Object.prototype` or `Array.prototype` could see.
//
// Every fixture vector runs through the real facade and the toy backend with recording,
// pass-through accessors planted on Object.prototype for every record field of
// bindings/api-inventory.txt and every member name the fixtures expect, and on the first array
// indices. A write made by the runner (`dist/conformance/`) or the facade (`dist/src/`) must never
// reach one; the results must be those of an unpolluted run.
import { assert, fs, path, process, test } from "../node/builtins.js";
import { createApi } from "../src/api.js";
import { runVectors, type VectorFile } from "../conformance/runner.js";
import { toyBackend } from "./toy-backend.js";
import { plant } from "./traps.js";

const FIXTURES = path.resolve(process.cwd(), "test/fixtures/vectors");
const SCHEMA: unknown = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), "../../conformance/schema.json"), "utf8"));

function fixtureFiles(dir = FIXTURES): VectorFile[] {
  const out: VectorFile[] = [];
  const walk = (d: string): void => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".json")) out.push({ path: path.relative(dir, p).split(path.sep).join("/"), json: fs.readFileSync(p, "utf8") });
    }
  };
  walk(dir);
  return out.sort((a, b) => (a.path < b.path ? -1 : 1));
}

/** Every `field` name of every record in bindings/api-inventory.txt (options and results). */
function inventoryFields(): string[] {
  const text = fs.readFileSync(path.resolve(process.cwd(), "../api-inventory.txt"), "utf8");
  const out = new Set<string>();
  for (const line of text.split("\n")) {
    const m = /^\s*field (\w+)/.exec(line);
    if (m?.[1] !== undefined) out.add(m[1]);
  }
  return [...out];
}

/** Every member name in the fixtures' expectations, at any depth: the runner's output names. */
function expectedNames(files: readonly VectorFile[]): string[] {
  const out = new Set<string>();
  const walk = (v: unknown): void => {
    if (typeof v !== "object" || v === null) return;
    if (!Array.isArray(v)) for (const k of Object.keys(v)) out.add(k);
    for (const x of Object.values(v)) walk(x);
  };
  for (const f of files) walk((JSON.parse(f.json) as { expect?: unknown }).expect);
  return [...out];
}

/** Names whose traps would change the runtime itself, not the code under test. */
const RUNTIME = new Set(["then", "constructor", "toString", "valueOf", "toJSON", "length", "name", "message", "stack", "code", "cause"]);

test("the runner creates every member it hands the facade or records as an output as an own property", async () => {
  const files = fixtureFiles();
  const clean = await runVectors(createApi(toyBackend().backend), files, { schema: SCHEMA, features: [] });
  const names = [...new Set([...inventoryFields(), ...expectedNames(files)])].filter((n) => !RUNTIME.has(n));
  // The members the audit names are among them.
  for (const n of ["aad", "detachedPayload", "apu", "apv", "header", "protectedHeader", "kid", "plaintext_b64u", "jwk", "claims"]) {
    assert.ok(names.includes(n), n);
  }
  const named = plant(Object.prototype, names, "accessor", () => undefined, { passThrough: true });
  let indexed: ReturnType<typeof plant> | undefined;
  let results: Awaited<ReturnType<typeof runVectors>> | undefined;
  try {
    indexed = plant(Array.prototype, ["0", "1", "2", "3"], "accessor", () => undefined, { passThrough: true });
    results = await runVectors(createApi(toyBackend().backend), files, { schema: SCHEMA, features: [] });
  } finally {
    indexed?.remove();
    named.remove();
  }
  const ours = [...named.ours(), ...(indexed?.ours() ?? [])].map((w) => `${String(w.member)} at ${w.site.replace(/^.*\/dist\//, "dist/")}`);
  assert.deepEqual([...new Set(ours)], [], "no runner or facade write reached a setter on a prototype");
  assert.deepEqual(results, clean, "every vector has its unpolluted result");
});
