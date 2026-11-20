// The runner's JSON Schema check, over the subset conformance/schema.json uses
// (conformance/README.md: every runner fails a file that is not schema-valid).
import { assert, fs, path, process, test } from "../node/builtins.js";
import { schemaViolation } from "../conformance/schema.js";

const REPO = path.resolve(process.cwd(), "../..");
const SCHEMA: unknown = JSON.parse(fs.readFileSync(path.join(REPO, "conformance/schema.json"), "utf8"));

function vectorFiles(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) vectorFiles(p, out);
    else if (e.name.endsWith(".json")) out.push(p);
  }
  return out;
}

test("every committed vector is valid against conformance/schema.json", () => {
  const files = vectorFiles(path.join(REPO, "conformance/vectors"));
  assert.ok(files.length > 800, `found ${files.length} vector files`);
  const invalid = files
    .map((f) => [path.relative(REPO, f), schemaViolation(SCHEMA, JSON.parse(fs.readFileSync(f, "utf8")))] as const)
    .filter(([, v]) => v !== undefined);
  assert.deepEqual(invalid, []);
});

const ok = (input: unknown, expect: unknown, operation = "b64url.encode") => ({
  source: "RFC 4648 §10",
  description: "a test vector",
  operation,
  input,
  expect,
});

test("schema-invalid vectors are reported with a JSON pointer", () => {
  const cases: [unknown, RegExp][] = [
    [[], /^\(root\): /],
    [{ ...ok({ bytes_hex: "66" }, { ok: true, b64u: "Zg" }), extra: 1 }, /^\/extra: /],
    [ok({ bytes_hex: "6" }, { ok: true, b64u: "Zg" }), /^\/input\/bytes_hex: /],
    [ok({ bytes_hex: "66", typo: 1 }, { ok: true, b64u: "Zg" }), /^\/input\/typo: /],
    [ok({ bytes_hex: "66" }, { ok: false, error: "InvalidBase64" }), /expect/],
    [ok({ b64u: "Zg" }, { ok: false, error: "NotACode" }, "b64url.decode"), /expect/],
    [ok({ bytes_hex: "66" }, { ok: true, b64u: "Zg" }, "jws.frobnicate"), /^\/operation: /],
    [{ ...ok({ bytes_hex: "66" }, { ok: true, b64u: "Zg" }), source: "  " }, /^\/source: /],
    [{ ...ok({ bytes_hex: "66" }, { ok: true, b64u: "Zg" }), features: ["deflate", "deflate"] }, /^\/features: /],
    [{ ...ok({ bytes_hex: "66" }, { ok: true, b64u: "Zg" }), features: ["test-vectors"] }, /^\/features\/0: /],
  ];
  for (const [vector, want] of cases) {
    const v = schemaViolation(SCHEMA, vector);
    assert.ok(v !== undefined, JSON.stringify(vector));
    assert.match(v, want);
  }
  assert.equal(schemaViolation(SCHEMA, ok({ bytes_hex: "66" }, { ok: true, b64u: "Zg" })), undefined);
});

test("integer, minimum and maximum follow the schema's count and seconds", () => {
  const verify = (extra: Record<string, unknown>) =>
    ok({ jws: "a.b.c", key: { kty: "oct" }, allowed_algs: ["HS256"], ...extra }, { ok: false, error: "InvalidSignature" }, "jws.verify");
  assert.equal(schemaViolation(SCHEMA, verify({ max_input_len: 4294967295 })), undefined);
  assert.match(schemaViolation(SCHEMA, verify({ max_input_len: 4294967296 })) ?? "", /max_input_len/);
  assert.match(schemaViolation(SCHEMA, verify({ max_input_len: -1 })) ?? "", /max_input_len/);
  assert.match(schemaViolation(SCHEMA, verify({ max_input_len: 1.5 })) ?? "", /max_input_len/);
});

test("a schema keyword the checker does not implement is an error, never ignored", () => {
  assert.throws(() => schemaViolation({ type: "object", patternProperties: {} }, {}), /patternProperties/);
  assert.throws(() => schemaViolation({ $ref: "#/$defs/missing" }, {}), /missing/);
});
