// The node conformance run (ADR 0034 §2): every conformance/vectors/**/*.json through the built
// @polyjose/node API, by the shared runner of bindings/js (conformance/node-main.ts), writing
// target/conformance/node.json for scripts/conformance-parity.sh (ADR 0034 §5).
import { assert, fs, path, test } from "../../js/dist/node/builtins.js";
import * as api from "@polyjose/node";
import { main } from "../../js/dist/conformance/node-main.js";

interface NodeUrl {
  fileURLToPath(url: string): string;
}
const host = (globalThis as unknown as { process: { getBuiltinModule(id: "node:url"): NodeUrl } }).process;
const thisFile = host.getBuiltinModule("node:url").fileURLToPath((import.meta as unknown as { url: string }).url);
/** The repository root: this file is bindings/node/dist/conformance.test.js. */
const repo = path.resolve(path.dirname(thisFile), "..", "..", "..");

test("every conformance vector passes through @polyjose/node; results in target/conformance/node.json", async () => {
  const file = path.join(repo, "target", "conformance", "node.json");
  fs.rmSync(file, { recursive: true, force: true });
  // The bindings enable no vector feature (ADR 0034 §3): fixed-rng and deflate vectors are skipped.
  assert.equal(await main(api, { runner: "node", root: repo }), 0, "no vector failed (see FAIL lines above)");

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
