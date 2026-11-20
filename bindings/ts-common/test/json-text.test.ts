// The runner's JSON text scanner: strict RFC 8259 syntax, duplicate members refused (vector
// files are I-JSON, RFC 7493 §2.3), and order-preserving compact text of any value.
import { assert, fs, path, process, test } from "../node/builtins.js";
import { compactText, scanJson, textAt } from "../conformance/json-text.js";

test("accepts RFC 8259 JSON text and keeps the spans of every value", () => {
  const text = ' { "a" : [1, -2.5e3, true, null, "x\\u0041"], "b": {"c": {}} } ';
  const tree = scanJson(text);
  assert.equal(textAt(text, tree, ["a"]), '[1,-2.5e3,true,null,"x\\u0041"]');
  assert.equal(textAt(text, tree, ["a", 4]), '"x\\u0041"');
  assert.equal(textAt(text, tree, ["b", "c"]), "{}");
  assert.equal(textAt(text, tree, ["missing"]), undefined);
  assert.equal(textAt(text, tree, ["a", 9]), undefined);
});

test("textAt keeps member order and number spelling, unlike a JS object", () => {
  const text = '{"claims": {"sub": "x", "2": 1, "1": 2.50, "exp": 1300819380}}';
  const tree = scanJson(text);
  assert.equal(textAt(text, tree, ["claims"]), '{"sub":"x","2":1,"1":2.50,"exp":1300819380}');
  // What JSON.stringify(JSON.parse(...)) would do instead: integer-like keys move first.
  assert.equal(JSON.stringify(JSON.parse(text).claims), '{"1":2.5,"2":1,"sub":"x","exp":1300819380}');
});

test("compactText drops only insignificant whitespace", () => {
  assert.equal(compactText('{ "a b" : "c\\" d",\n\t"e" : [ 1 , 2 ] }'), '{"a b":"c\\" d","e":[1,2]}');
});

test("refuses duplicate member names, also when spelled with escapes", () => {
  assert.throws(() => scanJson('{"a":1,"a":2}'), /duplicate member "a"/);
  assert.throws(() => scanJson('{"x":{"kty":1,"k\\u0074y":2}}'), /duplicate member "kty"/);
  assert.doesNotThrow(() => scanJson('{"a":{"a":1},"b":[{"a":1},{"a":2}]}'));
});

test("refuses what RFC 8259 does not allow", () => {
  for (const bad of ["", "{", '{"a":1,}', "[1,]", "01", "1.", ".5", "+1", "NaN", "'a'", '"\t"', '"\\x"', '{"a" 1}', "[1 2]", "true false", "{a:1}", '"unterminated']) {
    assert.throws(() => scanJson(bad), SyntaxError, JSON.stringify(bad));
  }
});

test("every committed vector file scans, with no duplicate member", () => {
  const repo = path.resolve(process.cwd(), "../..");
  const walk = (dir: string): string[] =>
    fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
      const p = path.join(dir, e.name);
      return e.isDirectory() ? walk(p) : e.name.endsWith(".json") ? [p] : [];
    });
  const files = walk(path.join(repo, "conformance/vectors"));
  assert.ok(files.length > 800);
  for (const f of files) {
    const text = fs.readFileSync(f, "utf8");
    const tree = scanJson(text);
    // The compact text of the whole file parses to the same value as the file.
    assert.deepEqual(JSON.parse(textAt(text, tree, []) ?? ""), JSON.parse(text), f);
  }
});
