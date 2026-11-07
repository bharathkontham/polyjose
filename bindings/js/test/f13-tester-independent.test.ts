// Independent tester check for F13: every inventory member, planted as a recording setter and as
// a read-only member on Object.prototype (and index traps on Array.prototype), at once, over all
// result operations with every optional field present, and over the option records with caller
// data (aad, apu, apv, headers, recipients). Shares no helper with test/traps.ts.
import { assert, fs, path, process, test } from "../node/builtins.js";
import { createApi } from "../src/api.js";
import { fakeBackend, type Operation } from "./fake-backend.js";

let hits = 0;
function names(): string[] {
  const text = fs.readFileSync(path.resolve(process.cwd(), "../api-inventory.txt"), "utf8");
  return [...new Set([...text.matchAll(/^\s*field (\w+)/gm)].map((m) => m[1] ?? ""))];
}
function plant(keys: PropertyKey[], kind: "set" | "ro"): () => void {
  for (const k of keys) {
    const d: PropertyDescriptor =
      kind === "set"
        ? { configurable: true, get: () => undefined, set: () => void hits++ }
        : { configurable: true, writable: false, value: "trap" };
    Object.defineProperty(Object.prototype, k, d);
  }
  return () => {
    for (const k of keys) Reflect.deleteProperty(Object.prototype, k);
  };
}
const BV: Record<string, unknown> = {
  alg: "HS256", payload: new Uint8Array([1]), signatureIndex: 0, protectedHeader: '{"alg":"HS256"}', unprotectedHeader: '{"kid":"k"}',
  plaintext: new Uint8Array([2]), header: '{"alg":"dir"}', sharedUnprotectedHeader: '{"a":1}', recipientHeader: '{"kid":"r"}',
  aad: new Uint8Array([3]), recipientIndex: 0, claims: '{"sub":"a"}', keyIndex: 4, kid: "k1", outerHeader: '{"cty":"JWT"}',
};
const K = '{"kty":"oct","k":"AAAA"}';
const full = () => ({ ...BV });
const nested = () => ({ outerHeader: BV["outerHeader"], recipientIndex: 0, inner: { alg: "HS256", claims: '{"sub":"a"}', header: '{"alg":"HS256"}', keyIndex: 4, kid: "k1" } });
const D = { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] };
const V = { allowedAlgs: ["HS256"] };

for (const kind of ["set", "ro"] as const) {
  test(`F13 independent: all inventory members planted (${kind}) on Object.prototype; result members are own data`, async () => {
    hits = 0;
    const ops: [Operation, unknown, (a: any) => Promise<any>][] = [
      ["jwsVerifyCompact", full(), (a) => a.jwsVerifyCompact("a.b.c", K, V)],
      ["jwsVerifyJson", full(), (a) => a.jwsVerifyJson("{}", K, V)],
      ["jweDecryptCompact", full(), (a) => a.jweDecryptCompact("a.b.c.d.e", K, D)],
      ["jweDecryptJson", full(), (a) => a.jweDecryptJson("{}", K, D)],
      ["jwtVerify", full(), (a) => a.jwtVerify("a.b.c", K, V)],
      ["jwtVerifyWithJwks", full(), (a) => a.jwtVerifyWithJwks("a.b.c", '{"keys":[]}', V)],
      ["jwtDecryptNested", nested(), (a) => a.jwtDecryptNested("t", K, D, K, V)],
      ["jwtDecryptNestedWithJwks", nested(), (a) => a.jwtDecryptNestedWithJwks("t", K, D, '{"keys":[]}', V)],
    ];
    const all = names();
    for (const [op, value, call] of ops) {
      const api = createApi(fakeBackend({ handlers: { [op]: () => value } as never }).backend);
      const clean = await call(api);
      const un = plant(all, kind);
      let got: any;
      try {
        got = await call(api);
      } finally {
        un();
      }
      assert.equal(hits, 0, op);
      assert.equal(Object.getPrototypeOf(got), Object.prototype, op);
      const check = (g: any, c: any, at: string): void => {
        assert.deepEqual(Object.keys(g).sort(), Object.keys(c).sort(), at);
        for (const k of Object.keys(c)) {
          const d = Object.getOwnPropertyDescriptor(g, k)!;
          assert.ok("value" in d && d.enumerable && d.writable && d.configurable, `${at}.${k} own data`);
          if (k === "inner") check(g[k], c[k], `${at}.inner`);
          else assert.deepEqual(d.value, c[k], `${at}.${k}`);
        }
      };
      check(got, clean, op);
    }
  });

  test(`F13 independent: option records and byte copies under member + index traps (${kind})`, async () => {
    hits = 0;
    let seen: unknown;
    let n = 0;
    const be = { jweEncryptCompact: (...a: unknown[]) => (seen = [Uint8Array.from(a[0] as Uint8Array), a[1], (a[1] as any).recipients, (a[1] as any).aad && Uint8Array.from((a[1] as any).aad), Uint8Array.from((a[1] as any).recipients[0].apu), Uint8Array.from((a[1] as any).recipients[0].apv)], n++, "x.y.z.w.v") };
    const api = createApi(be as never) as any;
    const un = plant([...names(), 0, 1, 2, 3], kind);
    let pending: Promise<unknown> | undefined;
    const arr = Object.getOwnPropertyDescriptor(Array.prototype, 0);
    try {
      Object.defineProperty(Array.prototype, 0, kind === "set"
        ? { configurable: true, get: () => undefined, set: () => void hits++ }
        : { configurable: true, writable: false, value: "trap" });
      pending = api.jweEncryptCompact(new Uint8Array([9, 9]),
        { enc: "A128GCM", recipients: [{ alg: "dir", key: K, apu: new Uint8Array([7]), apv: new Uint8Array([8]), header: { kid: "r" } }], aad: new Uint8Array([5]), protectedHeader: { cty: "x" }, sharedUnprotectedHeader: { a: 1 }, compress: false });
    } finally {
      Reflect.deleteProperty(Array.prototype, 0);
      if (arr) Object.defineProperty(Array.prototype, 0, arr);
      un();
    }
    await pending;
    assert.equal(hits, 0);
    assert.equal(n, 1);
    const [pt, opts, , aadCopy, apuCopy, apvCopy] = seen as any[];
    const enc = opts.enc;
    const recips = opts.recipients;
    assert.deepEqual([...pt], [9, 9]);
    assert.equal(enc, "A128GCM");
    assert.equal(recips.length, 1);
    assert.deepEqual([...apuCopy], [7]);
    assert.deepEqual([...apvCopy], [8]);
    assert.ok(Object.hasOwn(recips[0], "header") && Object.hasOwn(opts, "aad") && Object.hasOwn(opts, "protectedHeader") && Object.hasOwn(opts, "sharedUnprotectedHeader"));
    assert.deepEqual([...aadCopy], [5]);
  });
}
