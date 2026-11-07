// Differential tests of the F09 JSON serialiser against JSON.stringify (tester, 0013 F09 r1):
// byte-identical output for clean plain data, own-key order preserved, hostile prototype states
// and Proxy inputs never change or crash the text.
import { assert, test } from "../node/builtins.js";
import { json } from "../src/normalize.js";

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

const STRINGS = [
  "", "a", "\u2028\u2029", "\ud800", "\udc00", "a\ud800b", "\ud83d\ude00", "\u0000\u001f\u007f",
  "\"\\/\b\f\n\r\t", "__proto__", "toJSON", "\u00e9\u4e2d", "0", "10", "-1",
];
const NUMBERS = [0, -0, 1, -1, 1.5, 1e21, 1e-7, 123456789012345680000, 5e-324, Number.MAX_VALUE, 2 ** 53];

function gen(r: () => number, depth: number): unknown {
  const k = Math.floor(r() * (depth > 4 ? 5 : 7));
  switch (k) {
    case 0: return null;
    case 1: return r() < 0.5;
    case 2: return NUMBERS[Math.floor(r() * NUMBERS.length)];
    case 3: case 4: return STRINGS[Math.floor(r() * STRINGS.length)];
    case 5: {
      const a: unknown[] = [];
      for (let i = Math.floor(r() * 4); i > 0; i--) a.push(gen(r, depth + 1));
      return a;
    }
    default: {
      const o: Record<string, unknown> = {};
      for (let i = Math.floor(r() * 5); i > 0; i--) {
        const key = STRINGS[Math.floor(r() * STRINGS.length)] ?? "k";
        // defineProperty so that an own "__proto__" key is an own data member
        Object.defineProperty(o, key, { value: gen(r, depth + 1), enumerable: true, writable: true, configurable: true });
      }
      return o;
    }
  }
}

test("1500 random plain objects serialise byte-identically to JSON.stringify", () => {
  const r = rng(0xf09);
  let n = 0;
  for (let i = 0; i < 1500; i++) {
    const v = { top: gen(r, 0), other: gen(r, 1) };
    assert.equal(json(v, "x"), JSON.stringify(v));
    n++;
  }
  assert.equal(n, 1500);
});

test("an own __proto__ key is written as a member, and key order is kept (integer keys first, as JSON.stringify)", () => {
  const o = JSON.parse('{"b":1,"__proto__":{"x":1},"a":2,"2":3,"1":4}') as object;
  assert.equal(json(o, "x"), JSON.stringify(o));
  assert.ok(json(o, "x").includes('"__proto__":{"x":1}'));
});

test("NaN, Infinity and -0 follow JSON.stringify (null, null, 0) and lone surrogates are escaped as it does", () => {
  const o = { a: NaN, b: Infinity, c: -Infinity, d: -0, e: ["\ud800", "\u2028"], f: undefined, g: [undefined] };
  assert.equal(json(o, "x"), JSON.stringify(o));
  assert.equal(json(o, "x"), '{"a":null,"b":null,"c":null,"d":0,"e":["\\ud800","\u2028"],"g":[null]}');
});

test("a polluted Object.prototype getter that throws, or a polluted index/key, never runs or leaks", () => {
  const touched: string[] = [];
  Object.defineProperty(Object.prototype, "toJSON", { configurable: true, get() { touched.push("toJSON"); throw new Error("boom"); } });
  Object.defineProperty(Object.prototype, "sub", { configurable: true, get() { touched.push("sub"); throw new Error("boom"); } });
  Object.defineProperty(Array.prototype, 0, { configurable: true, get() { touched.push("0"); throw new Error("boom"); } });
  try {
    const o = { a: [{ b: [1, 2] }], c: "x" };
    assert.equal(json(o, "x"), '{"a":[{"b":[1,2]}],"c":"x"}');
    assert.deepEqual(touched, []);
  } finally {
    delete (Object.prototype as Record<string, unknown>)["toJSON"];
    delete (Object.prototype as Record<string, unknown>)["sub"];
    delete (Array.prototype as unknown as Record<number, unknown>)[0];
  }
});

test("a Proxy input cannot make the serialiser throw anything but a TypeError, or smuggle toJSON", () => {
  const traps = new Proxy({ a: 1 }, { get(t, k) { if (k === "toJSON") return () => "evil"; return Reflect.get(t, k); } });
  const out = (() => { try { return json(traps, "x"); } catch (e) { return e; } })();
  assert.ok(typeof out === "string" ? !out.includes("evil") : out instanceof TypeError);
  const hostile = new Proxy({}, { ownKeys() { throw new RangeError("trap"); } });
  assert.throws(() => json(hostile, "x"), TypeError);
});

test("a hole deep inside nested arrays is a TypeError even with Array.prototype polluted", () => {
  const inner: unknown[] = [1, , 3];
  (Array.prototype as unknown as Record<number, unknown>)[1] = "evil";
  try {
    assert.throws(() => json({ a: [[[inner]]] }, "x"), TypeError);
    assert.throws(() => json({ a: new Array(3) }, "x"), TypeError);
  } finally {
    delete (Array.prototype as unknown as Record<number, unknown>)[1];
  }
});

test("Date, Map, class instances, BigInt and boxed values are TypeErrors at depth", () => {
  class C { x = 1; }
  for (const bad of [new Date(0), new Map(), new C(), 1n, Object(1), new Uint8Array(1), /x/]) {
    assert.throws(() => json({ a: [{ b: bad }] }, "x"), TypeError);
  }
});
