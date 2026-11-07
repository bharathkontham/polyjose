// The node conformance run (ADR 0034 §2): every conformance/vectors/**/*.json through the built
// @polyjose/node API, by the shared runner of bindings/js (conformance/node-main.ts), writing
// target/conformance/node.json for scripts/conformance-parity.sh (ADR 0034 §5).
//
// A CI matrix run (scripts/ci-build.sh, T05) sets POLYJOSE_CONFORMANCE_SUFFIX to its matrix label,
// e.g. `x86_64-unknown-linux-musl`; the file is then target/conformance/node-<label>.json, the
// `<runner>-<suffix>` name of ADR 0034 §2, and its `runner` member stays `node`. Unset, the name is
// node.json. A set but malformed label (empty, a path, upper case) fails the test.
import { assert, fs, path, test } from "../../js/dist/node/builtins.js";
import * as api from "@polyjose/node";
import { main, type ConformanceOptions } from "../../js/dist/conformance/node-main.js";

interface NodeUrl {
  fileURLToPath(url: string): string;
}
const host = (
  globalThis as unknown as {
    process: { readonly env: Record<string, string | undefined>; getBuiltinModule(id: "node:url"): NodeUrl };
  }
).process;
const thisFile = host.getBuiltinModule("node:url").fileURLToPath((import.meta as unknown as { url: string }).url);
/** The repository root: this file is bindings/node/dist/conformance.test.js. */
const repo = path.resolve(path.dirname(thisFile), "..", "..", "..");

/** The CI matrix label (ADR 0034 §2 suffix), or undefined for the local run. */
const suffix = host.env["POLYJOSE_CONFORMANCE_SUFFIX"];
const fileName = suffix === undefined ? "node.json" : `node-${suffix}.json`;

test(`every conformance vector passes through @polyjose/node; results in target/conformance/${fileName}`, async () => {
  if (suffix !== undefined) {
    // The shared runner's own rule for a suffix (node-main.ts); checked here first so a bad label
    // reads as one, not as a vector failure.
    assert.match(suffix, /^[a-z0-9][a-z0-9_.-]*$/, "POLYJOSE_CONFORMANCE_SUFFIX is a CI target label");
  }
  const file = path.join(repo, "target", "conformance", fileName);
  fs.rmSync(file, { recursive: true, force: true });
  // The bindings enable no vector feature (ADR 0034 §3): fixed-rng and deflate vectors are skipped.
  const options: ConformanceOptions =
    suffix === undefined ? { runner: "node", root: repo } : { runner: "node", suffix, root: repo };
  assert.equal(await main(api, options), 0, "no vector failed (see FAIL lines above)");
  assert.ok(fs.existsSync(file), `${file} was written`);

  const report = JSON.parse(fs.readFileSync(file, "utf8")) as {
    runner: unknown;
    polyjose: unknown;
    features: unknown;
    error_codes: unknown;
    results: { id: string; status: string; reason?: string }[];
  };
  assert.equal(report.runner, "node");
  assert.equal(report.polyjose, await api.version());
  assert.deepEqual(report.features, []);
  assert.deepEqual(report.error_codes, await api.errorCodes());
  assert.ok(report.results.length > 0, "vectors ran");
  assert.deepEqual(
    report.results.filter((r) => r.status === "fail"),
    [],
    "no fail entries",
  );
  for (const r of report.results.filter((r) => r.status === "skipped")) {
    assert.match(r.reason ?? "", /^feature:/, `${r.id}: a skip is only ever for a feature the build lacks`);
  }
});
