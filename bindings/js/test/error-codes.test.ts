// The generated ErrorCode union matches the core's Error::CODES (ADR 0047): the build
// regenerates src/error-codes.ts from crates/polyjose/src/error.rs, and this test re-reads
// error.rs with its own, independent scan so a generator bug or a stale file fails.
import { assert, fs, path, process, test } from "../node/builtins.js";
import { ERROR_CODES } from "../src/error-codes.js";
import { parseErrorCodes, renderErrorCodes } from "../tools/gen-error-codes.js";

const ERROR_RS = path.resolve(process.cwd(), "../../crates/polyjose/src/error.rs");

/** Error::CODES by a line scan (independent of the generator's regular expression). */
function codesByLineScan(source: string): string[] {
  const lines = source.split("\n");
  const start = lines.findIndex((l) => l.includes("pub const CODES: &'static [&'static str] = &["));
  assert.ok(start >= 0, "Error::CODES not found in error.rs");
  const codes: string[] = [];
  for (const line of lines.slice(start + 1)) {
    const trimmed = line.trim();
    if (trimmed === "];") return codes;
    const m = /^"([^"]+)",$/.exec(trimmed);
    assert.ok(m, `unexpected line in Error::CODES: ${trimmed}`);
    codes.push(m[1] ?? "");
  }
  return assert.fail("Error::CODES is not terminated");
}

test("ERROR_CODES equals Error::CODES in the core, in order", () => {
  const source = fs.readFileSync(ERROR_RS, "utf8");
  assert.deepEqual([...ERROR_CODES], codesByLineScan(source));
});

test("the generated file is what the generator renders from error.rs now", () => {
  const source = fs.readFileSync(ERROR_RS, "utf8");
  const generated = fs.readFileSync(path.resolve(process.cwd(), "src/error-codes.ts"), "utf8");
  assert.equal(generated, renderErrorCodes(parseErrorCodes(source)));
});

test("MultipleMatchingKeys (ADR 0054 §5) comes right after NoMatchingKey, last", () => {
  assert.deepEqual(ERROR_CODES.slice(-2), ["NoMatchingKey", "MultipleMatchingKeys"]);
});

test("a code added to the core changes the parsed list", () => {
  const source = fs.readFileSync(ERROR_RS, "utf8");
  const extended = source.replace('"MultipleMatchingKeys",', '"MultipleMatchingKeys",\n        "SomethingNew",');
  const parsed = parseErrorCodes(extended);
  assert.equal(parsed.at(-1), "SomethingNew");
  assert.notDeepEqual(parsed, [...ERROR_CODES]);
});

test("the generator refuses a source without Error::CODES", () => {
  assert.throws(() => parseErrorCodes("pub enum Error {}"), /Error::CODES/);
});

test("the generator refuses duplicate or malformed codes", () => {
  const block = (body: string) => `pub const CODES: &'static [&'static str] = &[\n${body}\n    ];`;
  assert.throws(() => parseErrorCodes(block('"InvalidKey",\n"InvalidKey",')), /twice/);
  assert.throws(() => parseErrorCodes(block('"invalid key",')), /not a code/);
  assert.throws(() => parseErrorCodes(block("")), /empty/);
});
