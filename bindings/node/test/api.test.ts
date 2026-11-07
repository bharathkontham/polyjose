// The built @polyjose/node package (ADR 0031 §1-§3, ADR 0034 §8), run with `node --test` against
// the compiled output: its ESM and CommonJS (require(esm)) entries, its error mapping, its
// manifest and the committed npm/<platform>/ directories.
import { assert, fs, path, test } from "../../js/dist/node/builtins.js";
import * as esm from "@polyjose/node";
import { ERROR_CODES, PolyjoseError, base64urlDecode, errorCodes, jwkParse } from "@polyjose/node";
import { backend } from "../backend.js";
import { createApi, PolyjoseError as FacadePolyjoseError } from "../facade/api.js";
import type { Backend } from "../facade/backend.js";

interface NodeModule {
  createRequire(from: string): (id: string) => unknown;
}
interface NodeUrl {
  fileURLToPath(url: string): string;
}
const host = (
  globalThis as unknown as {
    process: { getBuiltinModule(id: "node:module"): NodeModule; getBuiltinModule(id: "node:url"): NodeUrl };
  }
).process;
const thisFile = host.getBuiltinModule("node:url").fileURLToPath((import.meta as unknown as { url: string }).url);
/** bindings/node: this file is bindings/node/dist/api.test.js. */
const pkgDir = path.resolve(path.dirname(thisFile), "..");
const repo = path.resolve(pkgDir, "..", "..");

const readJson = (file: string): unknown => JSON.parse(fs.readFileSync(file, "utf8"));
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;
function record(v: unknown, what: string): Record<string, unknown> {
  assert.ok(isRecord(v), `${what} is an object`);
  return v;
}

/** The `op` names of bindings/api-inventory.txt (ADR 0030 §4), in its order. */
function inventoryOps(): string[] {
  return fs
    .readFileSync(path.join(repo, "bindings", "api-inventory.txt"), "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("op "))
    .map((line) => line.slice(3).trim());
}

/** Every inventory operation, plus the facade's PolyjoseError and ERROR_CODES (BACKEND.md). */
function expectedExports(): string[] {
  const ops = inventoryOps();
  assert.equal(ops.length, 32, "ADR 0030 §4 has 32 operations");
  return [...ops, "ERROR_CODES", "PolyjoseError"].sort();
}

test("the ESM entry exports every inventory operation, PolyjoseError and ERROR_CODES", () => {
  assert.deepEqual(Object.keys(esm).sort(), expectedExports());
  for (const op of inventoryOps()) {
    assert.equal(typeof (esm as unknown as Record<string, unknown>)[op], "function", op);
  }
  assert.equal(PolyjoseError, FacadePolyjoseError, "the facade's class, not a copy");
});

test("CommonJS require() of the package (require(esm), Node >= 22.12) exposes the same API", () => {
  const require = host.getBuiltinModule("node:module").createRequire(thisFile);
  const cjs = record(require("@polyjose/node"), "require('@polyjose/node')");
  assert.deepEqual(Object.keys(cjs).sort(), expectedExports());
  for (const name of expectedExports()) {
    assert.equal(cjs[name], (esm as unknown as Record<string, unknown>)[name], `${name}: one module instance`);
  }
});

test("a core failure rejects the Promise with a PolyjoseError whose code is in errorCodes()", async () => {
  const pending = base64urlDecode("a=");
  assert.ok(pending instanceof Promise, "operations return a Promise, never throw synchronously");
  const codes = await errorCodes();
  await assert.rejects(pending, (e: unknown) => {
    assert.ok(e instanceof PolyjoseError, "instanceof PolyjoseError");
    assert.ok(e instanceof Error);
    assert.equal(e.name, "PolyjoseError");
    assert.equal(e.code, "InvalidBase64");
    assert.ok(codes.includes(e.code), `${e.code} is in errorCodes()`);
    return true;
  });
});

test("errorCodes() equals the core's Error::CODES, as the rust-core reference run records it", async () => {
  const file = path.join(repo, "target", "conformance", "rust-core.json");
  assert.ok(
    fs.existsSync(file),
    `${file} missing: the reference run writes it (cargo test -p polyjose --test conformance; test.sh runs it)`,
  );
  const reference = record(readJson(file), "rust-core.json");
  assert.deepEqual(await errorCodes(), reference["error_codes"]);
  assert.deepEqual(await errorCodes(), [...ERROR_CODES], "the generated ErrorCode union matches the native list");
});

test("a napi argument error surfaces as a TypeError, never as a PolyjoseError", async () => {
  const codes = await errorCodes();
  // The raw napi layer throws its own Status code (StringExpected) synchronously ...
  assert.throws(
    () => backend.jwkParse(42 as unknown as string),
    (e: unknown) => {
      const code = record(e, "the napi error")["code"];
      assert.equal(typeof code, "string");
      assert.ok(!codes.includes(code as string), `napi's ${String(code)} is not a polyjose code`);
      return true;
    },
  );
  // ... which the facade maps to TypeError: the real napi error, through a backend that passes the
  // number on (the public API's own type check would stop it earlier).
  const wrapped: Backend = { ...backend, jwkParse: () => backend.jwkParse(42 as unknown as string) };
  await assert.rejects(createApi(wrapped).jwkParse("{}"), (e: unknown) => {
    assert.ok(e instanceof TypeError, "TypeError");
    assert.ok(!(e instanceof FacadePolyjoseError), "not a PolyjoseError");
    return true;
  });
  // The public API rejects a number for a JWK with a TypeError too.
  await assert.rejects(jwkParse(42 as never), (e: unknown) => e instanceof TypeError && !(e instanceof PolyjoseError));
});

test("package.json is the ADR 0031 ESM package with compiled output only (ADR 0047)", () => {
  const pkg = record(readJson(path.join(pkgDir, "package.json")), "package.json");
  assert.equal(pkg["name"], "@polyjose/node");
  assert.equal(pkg["type"], "module");
  assert.deepEqual(pkg["exports"], { ".": { types: "./index.d.ts", default: "./index.js" } });
  assert.deepEqual(pkg["engines"], { node: ">=22.12" });
  const files = pkg["files"];
  assert.ok(Array.isArray(files));
  for (const required of [
    "index.js",
    "index.d.ts",
    "backend.js",
    "binding.cjs",
    "binding.d.ts",
    "LICENSE",
    "README.md",
    "THIRD-PARTY-NOTICES.txt",
  ]) {
    assert.ok(files.includes(required), `files lists ${required}`);
  }
  for (const entry of files) {
    assert.equal(typeof entry, "string");
    assert.doesNotMatch(entry as string, /\.(ts|mts|cts)$|\.map$|\.node$/, `files never ships ${String(entry)}`);
  }
  const napi = record(pkg["napi"], "napi");
  assert.equal(napi["binaryName"], "polyjose");
  assert.deepEqual(record(pkg["devDependencies"], "devDependencies"), { "@napi-rs/cli": "3.10.12" });
  assert.equal(pkg["dependencies"], undefined, "no runtime dependencies");
  const scripts = record(pkg["scripts"], "scripts");
  assert.deepEqual(Object.keys(scripts).sort(), ["build", "test"], "no publish hooks (Gate 3)");
});

/** The napi platform name of a target triple (ADR 0031 §2), e.g. aarch64-unknown-linux-musl -> linux-arm64-musl. */
function platformOf(triple: string): { dir: string; os: string; cpu: string; libc?: string } {
  const cpu = { x86_64: "x64", aarch64: "arm64" }[triple.split("-")[0] ?? ""];
  assert.ok(cpu !== undefined, `${triple}: known architecture`);
  if (triple.endsWith("-apple-darwin")) return { dir: `darwin-${cpu}`, os: "darwin", cpu };
  if (triple.endsWith("-pc-windows-msvc")) return { dir: `win32-${cpu}-msvc`, os: "win32", cpu };
  const libc = /-unknown-linux-(gnu|musl)$/.exec(triple)?.[1];
  assert.ok(libc !== undefined, `${triple}: a darwin, linux gnu/musl or windows msvc target`);
  return { dir: `linux-${cpu}-${libc}`, os: "linux", cpu, libc: libc === "gnu" ? "glibc" : "musl" };
}

test("npm/<platform>/ holds exactly one package per napi.targets entry, each shipping its notices", () => {
  const pkg = record(readJson(path.join(pkgDir, "package.json")), "package.json");
  const targets = record(pkg["napi"], "napi")["targets"];
  assert.ok(Array.isArray(targets));
  assert.deepEqual(
    [...targets].sort(),
    [
      "aarch64-apple-darwin",
      "aarch64-pc-windows-msvc",
      "aarch64-unknown-linux-gnu",
      "aarch64-unknown-linux-musl",
      "x86_64-apple-darwin",
      "x86_64-pc-windows-msvc",
      "x86_64-unknown-linux-gnu",
      "x86_64-unknown-linux-musl",
    ],
    "the eight targets of ADR 0031 §2",
  );
  const platforms = targets.map((t) => platformOf(t as string));
  const dirs = fs
    .readdirSync(path.join(pkgDir, "npm"), { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
  assert.deepEqual(dirs, platforms.map((p) => p.dir).sort(), "npm/ directories equal napi.targets");
  for (const p of platforms) {
    const sub = record(readJson(path.join(pkgDir, "npm", p.dir, "package.json")), `npm/${p.dir}/package.json`);
    const binary = `polyjose.${p.dir}.node`;
    assert.equal(sub["name"], `@polyjose/node-${p.dir}`);
    assert.equal(sub["version"], pkg["version"], `${p.dir}: version`);
    assert.equal(sub["license"], pkg["license"], `${p.dir}: license`);
    assert.deepEqual(sub["engines"], pkg["engines"], `${p.dir}: engines`);
    assert.deepEqual(sub["os"], [p.os], `${p.dir}: os`);
    assert.deepEqual(sub["cpu"], [p.cpu], `${p.dir}: cpu`);
    assert.deepEqual(sub["libc"], p.libc === undefined ? undefined : [p.libc], `${p.dir}: libc`);
    assert.equal(sub["main"], binary, `${p.dir}: main`);
    assert.deepEqual(sub["files"], [binary, "THIRD-PARTY-NOTICES.txt"], `${p.dir}: files`);
  }
});
