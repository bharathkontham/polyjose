/**
 * The Node side of the Chrome and workerd runs (`chrome.ts`, `workerd.ts`): it reads the vectors
 * the way `bindings/js/conformance/node-main.ts` does, resolves the package entry the runtime
 * would pick, and checks and writes the results document the runtime returns
 * (`target/conformance/<runner>.json`, ADR 0034 §2).
 */
import type { VectorResult } from "../js/conformance/runner.js";
import { fs, path, process } from "./node.js";
import type { ProbeReport, VectorBytes, VectorInput } from "./results.js";

/** Standard base64 (RFC 4648 §4) of `bytes`, so the raw file bytes cross JSON unchanged. */
function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

/** Every `*.json` under `dir`, recursively, as `/`-separated paths relative to `base`. */
function collect(dir: string, base: string, files: string[], links: string[]): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(base, full).split(path.sep).join("/");
    if (entry.isSymbolicLink()) links.push(rel);
    else if (entry.isDirectory()) collect(full, base, files, links);
    else if (entry.isFile() && entry.name.endsWith(".json")) files.push(rel);
  }
}

/**
 * `conformance/vectors/**\/*.json` and `conformance/schema.json` under `root`, as node-main reads
 * them (conformance/README.md "Rules for every runner"): an unreadable file or a symbolic link
 * is a `fail`, never skipped, and gets no digest line (ADR 0060 §2). Each file is read once, as
 * bytes, and handed to the runtime as those bytes (base64), which it both hashes for
 * `vectors_digest` and decodes for the runner (`results.ts`; ADR 0060 §2, §5). Throws when there
 * is nothing to run.
 */
export function collectVectors(root: string): VectorInput {
  const vectorsDir = path.join(root, "conformance", "vectors");
  const schema: unknown = JSON.parse(fs.readFileSync(path.join(root, "conformance", "schema.json"), "utf8"));
  const names: string[] = [];
  const links: string[] = [];
  collect(vectorsDir, vectorsDir, names, links);
  if (names.length + links.length === 0) throw new Error(`${vectorsDir}: no vector files (*.json) found`);
  names.sort();
  const files: VectorBytes[] = [];
  const failures: VectorResult[] = [];
  for (const name of names) {
    try {
      files.push({ path: name, base64: toBase64(fs.readFileSync(path.join(vectorsDir, name))) });
    } catch (e) {
      failures.push({ id: `${name}#0`, op: "unknown", status: "fail", reason: `${name}: cannot read: ${String(e)}` });
    }
  }
  for (const name of links) {
    failures.push({ id: `${name}#0`, op: "unknown", status: "fail", reason: `${name}: symbolic links are not allowed` });
  }
  return { schema, files, failures };
}

/**
 * The file the installed package's `exports["."]` maps to under `conditions`, as Node, browsers'
 * bundlers and wrangler resolve it: the first key, in the map's order, that is one of the
 * conditions (Node "Conditional exports"; ADR 0031 §3 fixes the order). The value is checked
 * to be a relative path inside the package.
 */
export function resolveEntry(packageDir: string, conditions: readonly string[]): string {
  const manifest = JSON.parse(fs.readFileSync(path.join(packageDir, "package.json"), "utf8")) as {
    exports?: Record<string, unknown>;
  };
  const dot = manifest.exports?.["."];
  if (dot === null || typeof dot !== "object" || Array.isArray(dot)) throw new Error(`${packageDir}: no exports["."] object`);
  for (const [condition, target] of Object.entries(dot as Record<string, unknown>)) {
    if (!conditions.includes(condition)) continue;
    if (typeof target !== "string" || !/^\.\/[A-Za-z0-9_.-]+$/.test(target)) {
      throw new Error(`${packageDir}: exports["."].${condition} is not a file in the package: ${String(target)}`);
    }
    return target;
  }
  throw new Error(`${packageDir}: no exports["."] condition among ${conditions.join(", ")}`);
}

/** Prints the probe's checks; returns whether it passed. */
export function reportProbe(runner: string, probe: unknown): boolean {
  const report = probe as Partial<ProbeReport> | null;
  if (report === null || typeof report !== "object" || !Array.isArray(report.checks)) {
    process.stderr.write(`${runner}: error-shape probe: no report (${JSON.stringify(probe)})\n`);
    return false;
  }
  for (const c of report.checks) {
    process.stdout.write(`${runner}: error shape: ${c.ok ? "ok" : "FAIL"} ${c.what} (${c.detail})\n`);
  }
  return report.ok === true && report.checks.length > 0;
}

/**
 * Checks the document a runtime returned (its runner, results and ADR 0060 `vectors_digest`),
 * writes `target/conformance/<runner>.json` and prints a summary as node-main does, with the digest. Returns the exit code: 0 only if every vector passed or was skipped.
 */
export function writeResults(root: string, runner: string, doc: unknown): number {
  const d = doc as { runner?: unknown; vectors_digest?: unknown; results?: unknown } | null;
  if (d === null || typeof d !== "object" || d.runner !== runner || !Array.isArray(d.results) || d.results.length === 0) {
    process.stderr.write(`conformance (${runner}): the runtime returned no results document for ${runner}\n`);
    return 1;
  }
  // ADR 0060 §1: parity rejects a file without it too; failing here names the runtime's run.
  if (typeof d.vectors_digest !== "string" || !/^[0-9a-f]{64}$/.test(d.vectors_digest)) {
    process.stderr.write(`conformance (${runner}): the runtime's results document has no valid vectors_digest\n`);
    return 1;
  }
  const results = d.results as VectorResult[];
  const outDir = path.join(root, "target", "conformance");
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, `${runner}.json`);
  fs.writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
  const failures = results.filter((r) => r.status === "fail");
  for (const f of failures) process.stderr.write(`  FAIL ${f.reason ?? f.id}\n`);
  const passed = results.filter((r) => r.status === "pass").length;
  const skipped = results.filter((r) => r.status === "skipped").length;
  process.stdout.write(
    `conformance (${runner}): ${passed} passed, ${failures.length} failed, ${skipped} skipped of ${results.length}; vectors_digest ${d.vectors_digest}; wrote ${file}\n`,
  );
  return failures.length === 0 && passed + skipped === results.length ? 0 : 1;
}
