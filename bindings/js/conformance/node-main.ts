/**
 * Node driver of the shared JS conformance runner (ADR 0034 §2): reads every
 * `conformance/vectors/**\/*.json` (recursively, sorted; conformance/README.md "Rules for every
 * runner"), runs them through `runVectors`, and writes `target/conformance/<runner>.json`.
 *
 * Each package calls it with its bound API, for example `@polyjose/node`'s test:
 *
 * ```ts
 * import * as api from "@polyjose/node";
 * import { main } from "<bindings/js>/dist/conformance/node-main.js";
 * process.exitCode = await main(api, { runner: "node", root: "<repo root>" });
 * // A CI matrix run: target/conformance/node-x86_64-unknown-linux-musl.json, runner "node".
 * process.exitCode = await main(api, { runner: "node", suffix: "x86_64-unknown-linux-musl", root });
 * ```
 *
 * The results file is `{ runner, polyjose, vectors_digest, features, error_codes, results }`
 * (ADR 0034 §2, §8; ADR 0060 §1). Its `runner` member is always the bare ADR 0034 §2 name; a CI
 * matrix suffix appears only in the file name (conformance/README.md "Runner names and results
 * files", B01). `vectors_digest` is computed from the bytes of each file read, with `node:crypto`
 * (ADR 0060 §5): each file is read once as bytes, hashed, and only then decoded as UTF-8 for the
 * runner.
 */

import { crypto, fs, path, process } from "../node/builtins.js";
import type { PolyjoseApi } from "../src/api.js";
import { runVectors, vectorsDigest, type DigestInput, type Sha256, type VectorFile, type VectorResult } from "./runner.js";

/** `node:crypto`'s SHA-256, the Node path's digest (ADR 0060 §5); never polyjose. */
const nodeSha256: Sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest();

/** The runner names of ADR 0034 §2: the `runner` enum of `conformance/schema/results.schema.json`. */
export const RUNNER_NAMES = [
  "rust-core",
  "rust-surface",
  "wasm-node",
  "wasm-chrome",
  "wasm-pkg-node",
  "wasm-pkg-chrome",
  "wasm-pkg-workerd",
  "node",
  "jvm",
  "android-emulator",
  "swift-macos",
  "swift-ios-sim",
  "swift-tvos-sim",
] as const;

export type RunnerName = (typeof RUNNER_NAMES)[number];

export interface ConformanceOptions {
  /** The bare runner name of ADR 0034 §2 (`node`, `wasm-pkg-node`, ...); written as the `runner` member. */
  readonly runner: RunnerName;
  /**
   * A CI matrix target (`x86_64-unknown-linux-musl`), appended to the file name only:
   * `target/conformance/<runner>-<suffix>.json` (ADR 0034 §2).
   */
  readonly suffix?: string;
  /** The polyjose repository root: vectors, schema and `target/` are found under it. */
  readonly root: string;
  /** The vector-file feature names this build enables; the bindings enable none (ADR 0034 §3). */
  readonly features?: readonly string[];
}

export interface ConformanceSummary {
  /** The results file written. */
  readonly file: string;
  readonly total: number;
  readonly passed: number;
  readonly failed: number;
  readonly skipped: number;
  /** One message per failing vector. */
  readonly failures: readonly string[];
}

/** A file-name suffix: lowercase target-triple characters, never a path. */
const SUFFIX = /^[a-z0-9][a-z0-9_.-]*$/;

/** Every `*.json` under `dir`, recursively, as paths relative to `dir`; symlinks are reported. */
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
 * Runs the vectors and writes the results file. Throws, writing nothing, when there is nothing to
 * run or no vector file could be read (an empty corpus has no digest, ADR 0060 §3).
 */
export async function runConformance(api: PolyjoseApi, options: ConformanceOptions): Promise<ConformanceSummary> {
  if (!(RUNNER_NAMES as readonly string[]).includes(options.runner)) {
    throw new TypeError(`polyjose: runner must be one of the ADR 0034 §2 names (${RUNNER_NAMES.join(", ")})`);
  }
  if (options.suffix !== undefined && !SUFFIX.test(options.suffix)) {
    throw new TypeError("polyjose: suffix must be a CI target name (lowercase letters, digits, '_', '.', '-')");
  }
  const vectorsDir = path.join(options.root, "conformance", "vectors");
  const schema: unknown = JSON.parse(fs.readFileSync(path.join(options.root, "conformance", "schema.json"), "utf8"));
  const names: string[] = [];
  const links: string[] = [];
  collect(vectorsDir, vectorsDir, names, links);
  if (names.length + links.length === 0) throw new Error(`${vectorsDir}: no vector files (*.json) found`);

  const files: VectorFile[] = [];
  const read: DigestInput[] = [];
  const unreadable: VectorResult[] = [];
  for (const name of names) {
    let bytes;
    try {
      bytes = fs.readFileSync(path.join(vectorsDir, name));
    } catch (e) {
      // A `fail` with no digest line (ADR 0060 §2).
      unreadable.push({ id: `${name}#0`, op: "unknown", status: "fail", reason: `${name}: cannot read: ${String(e)}` });
      continue;
    }
    // The digest is over these very bytes; the runner gets them decoded exactly as
    // readFileSync(…, "utf8") would decode them.
    read.push({ id: `${name}#0`, bytes });
    files.push({ path: name, json: bytes.toString("utf8") });
  }
  if (read.length === 0) throw new Error(`${vectorsDir}: no vector file could be read`);
  const digest = await vectorsDigest(read, nodeSha256);
  const features = [...(options.features ?? [])];
  const results = [
    ...(await runVectors(api, files, { schema, features })),
    ...unreadable,
    ...links.map(
      (name): VectorResult => ({ id: `${name}#0`, op: "unknown", status: "fail", reason: `${name}: symbolic links are not allowed` }),
    ),
  ].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const outDir = path.join(options.root, "target", "conformance");
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, `${options.runner}${options.suffix === undefined ? "" : `-${options.suffix}`}.json`);
  const report = {
    runner: options.runner,
    polyjose: await api.version(),
    vectors_digest: digest,
    features,
    error_codes: await api.errorCodes(),
    results,
  };
  fs.writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`);

  const failures = results.filter((r) => r.status === "fail").map((r) => r.reason ?? r.id);
  return {
    file,
    total: results.length,
    passed: results.filter((r) => r.status === "pass").length,
    failed: failures.length,
    skipped: results.filter((r) => r.status === "skipped").length,
    failures,
  };
}

/** {@link runConformance}, printing a summary; returns the process exit code (0 only if nothing failed). */
export async function main(api: PolyjoseApi, options: ConformanceOptions): Promise<number> {
  let summary: ConformanceSummary;
  try {
    summary = await runConformance(api, options);
  } catch (e) {
    process.stderr.write(`conformance (${options.runner}): ${e instanceof Error ? e.message : String(e)}\n`);
    return 1;
  }
  for (const failure of summary.failures) process.stderr.write(`  FAIL ${failure}\n`);
  process.stdout.write(
    `conformance (${options.runner}): ${summary.passed} passed, ${summary.failed} failed, ${summary.skipped} skipped of ${summary.total}; wrote ${summary.file}\n`,
  );
  return summary.failed === 0 ? 0 : 1;
}
