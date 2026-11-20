// T14 tester: the committed 0015 thumbprint vectors that pin ADR 0022 (SHA-1) and ADR 0057 §2
// (import before hash) run through the real JS runner and the real facade, with the toy backend
// that models the core's nine-name parse. The toy keys are not the core's, so only vectors whose
// outcome does not depend on real curve checks are used here (rust-core and rust-surface run
// every vector against the real core).
import { assert, fs, path, process, test } from "../node/builtins.js";
import { createApi } from "../src/api.js";
import { runVectors, type VectorFile } from "../conformance/runner.js";
import { toyBackend } from "./toy-backend.js";

const VECTORS = path.resolve(process.cwd(), "../../conformance/vectors/jwk-thumbprint");
const SCHEMA: unknown = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), "../../conformance/schema.json"), "utf8"));

function real(name: string): VectorFile {
  return { path: `jwk-thumbprint/${name}`, json: fs.readFileSync(path.join(VECTORS, name), "utf8") };
}

for (const name of ["hash-reject-sha-1.json", "hash-reject-upper-sha-1.json"]) {
  test(`${name}: SHA-1 gives UnsupportedAlgorithm through the JS runner`, async () => {
    const file = real(name);
    const parsed = JSON.parse(file.json) as { expect: { error: string } };
    assert.equal(parsed.expect.error, "UnsupportedAlgorithm");
    const [r] = await runVectors(createApi(toyBackend().backend), [file], { schema: SCHEMA, features: [] });
    assert.ok(r !== undefined);
    assert.equal(r.status, "pass", JSON.stringify(r));
    assert.deepEqual(r.actual, { ok: false, error: "UnsupportedAlgorithm" });
  });
}
