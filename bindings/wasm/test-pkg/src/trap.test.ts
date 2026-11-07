/**
 * [WASM-pkg-node] A trap fails closed (feature 0006 F05, review S3): after a
 * `WebAssembly.RuntimeError` the instance is poisoned, and every later operation, `version()`,
 * `errorCodes()` and `ready()` reject with an `Error` that says to reload the module.
 * `PolyjoseError`s and the adapter's reader `TypeError`s don't poison.
 *
 * The trap is real, cheap and deterministic: a child `node --wasm-max-mem-pages=256` caps the
 * module's linear memory at 16 MiB (a V8 option of the test's own process; nothing in the
 * package changes), and `base64urlEncode` of a 32 MiB input can't be copied in. The allocation
 * fails, wasm32's allocation-failure handler aborts, and abort is `unreachable`, a
 * `WebAssembly.RuntimeError` thrown from the glue call. Peak memory is about 120 MB.
 *
 * Through the facade the trap is reported as a `TypeError` with the original message, because
 * the facade maps every error without a core `code` to a `TypeError` (`bindings/js/src/api.ts`
 * `mapError`). That is the facade's contract, so these checks go by message: the poisoned
 * calls carry the backend's "Reload" text, whatever class the facade gives them. The
 * `backend` case calls `backend.js` directly (by file URL, as the audit's scenario does), to
 * show the `RuntimeError` itself is rethrown unchanged.
 */
import { assert, childProcess, path, process, resolveFrom, stageRoot, test, url } from "./node.js";

type Api = typeof import("@polyjose/wasm");

/** `backend.js`, as a file-URL importer sees it. */
interface BackendFile {
  backend: {
    ready(): Promise<void>;
    version(): string;
    errorCodes(): readonly string[];
    base64urlEncode(bytes: Uint8Array): string;
    jwsVerifyCompact(token: string, key: string, options: unknown): unknown;
  };
}

const RESULT = "RESULT ";
const MAX_PAGES = 256; // 16 MiB of linear memory
const TOO_BIG = 32 * 1024 * 1024;
const POISONED = /^polyjose: the WebAssembly instance trapped in an earlier call and is unusable; .*Reload @polyjose\/wasm/;

interface Outcome {
  readonly ok: boolean;
  readonly name?: string;
  readonly message?: string;
  readonly runtimeError?: boolean;
  readonly polyjose?: boolean;
}

async function outcome(api: Api | undefined, call: () => unknown): Promise<Outcome> {
  try {
    await call();
    return { ok: true };
  } catch (e) {
    const err = e instanceof Error ? e : new Error(String(e));
    return {
      ok: false,
      name: err.name,
      message: err.message,
      runtimeError: e instanceof WebAssembly.RuntimeError,
      polyjose: api !== undefined && e instanceof api.PolyjoseError,
    };
  }
}

async function child(mode: string): Promise<void> {
  const api = (await import("@polyjose/wasm")) as Api;
  const dir = path.dirname(url.fileURLToPath(resolveFrom(import.meta, "@polyjose/wasm")));
  const { backend } = (await import(new URL("backend.js", `file://${dir}/`).href)) as BackendFile;
  const r: Record<string, Outcome> = {};
  r["warm"] = await outcome(api, () => api.base64urlEncode(new Uint8Array([1, 2, 3])));
  // A core failure (RFC 4648 §5: '!' is not in the alphabet), then a reader TypeError (an
  // allow-list that is not an array, reached only by calling the backend directly): neither
  // poisons, the next call works.
  r["polyjoseError"] = await outcome(api, () => api.base64urlDecode("!!!!"));
  r["readerTypeError"] = await outcome(api, () => backend.jwsVerifyCompact("e30.e30.AAAA", '{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAA"}', { allowedAlgs: "HS256" }));
  r["afterOrdinaryErrors"] = await outcome(api, () => api.base64urlEncode(new Uint8Array([1, 2, 3])));

  const big = new Uint8Array(TOO_BIG);
  r["trap"] = mode === "facade" ? await outcome(api, () => api.base64urlEncode(big)) : await outcome(api, () => backend.base64urlEncode(big));

  r["laterEncode"] = await outcome(api, () => api.base64urlEncode(new Uint8Array([1])));
  r["laterGenerate"] = await outcome(api, () => api.jwkGenerateOct(32));
  r["laterVersion"] = await outcome(api, () => api.version());
  r["laterErrorCodes"] = await outcome(api, () => api.errorCodes());
  r["laterReady"] = await outcome(api, () => backend.ready());
  r["laterBackendCall"] = await outcome(api, () => backend.base64urlEncode(new Uint8Array([1])));
  process.stdout.write(`${RESULT}${JSON.stringify(r)}\n`);
}

function runChild(mode: string): Record<string, Outcome> {
  const stage = stageRoot(import.meta);
  const run = childProcess.spawnSync(
    process.execPath,
    [`--wasm-max-mem-pages=${MAX_PAGES}`, url.fileURLToPath(import.meta.url), "child", mode],
    { cwd: stage, encoding: "utf8", timeout: 120_000 },
  );
  if (run.error !== undefined) throw run.error;
  assert.equal(run.status, 0, `child ${mode} failed: ${run.stderr}`);
  const line = run.stdout.split("\n").find((l) => l.startsWith(RESULT));
  assert.ok(line !== undefined, `child ${mode} printed no result: ${run.stdout}${run.stderr}`);
  return JSON.parse(line.slice(RESULT.length)) as Record<string, Outcome>;
}

function get(r: Record<string, Outcome>, key: string): Outcome {
  const o = r[key];
  assert.ok(o !== undefined, `no ${key} in the child's report`);
  return o;
}

function assertFailsClosed(r: Record<string, Outcome>, mode: string): void {
  assert.equal(get(r, "warm").ok, true, `${mode}: the first call works`);
  const pj = get(r, "polyjoseError");
  assert.equal(pj.ok, false);
  assert.equal(pj.polyjose, true, `${mode}: base64urlDecode('!!!!') is a PolyjoseError: ${pj.message}`);
  const reader = get(r, "readerTypeError");
  assert.equal(reader.ok, false);
  assert.equal(reader.name, "TypeError", `${mode}: the reader rejects a non-array allowedAlgs: ${reader.message}`);
  assert.equal(get(r, "afterOrdinaryErrors").ok, true, `${mode}: a PolyjoseError or a reader TypeError doesn't poison`);

  const trap = get(r, "trap");
  assert.equal(trap.ok, false, `${mode}: a 32 MiB input under a 16 MiB memory cap must trap`);
  assert.equal(trap.polyjose, false, `${mode}: a trap is never a PolyjoseError`);
  assert.ok(!POISONED.test(trap.message ?? ""), `${mode}: the trap itself is rethrown, not replaced: ${trap.message}`);

  for (const key of ["laterEncode", "laterGenerate", "laterVersion", "laterErrorCodes", "laterReady", "laterBackendCall"]) {
    const later = get(r, key);
    assert.equal(later.ok, false, `${mode}: ${key} must be refused after the trap`);
    assert.equal(later.polyjose, false, `${mode}: ${key} is not a PolyjoseError`);
    assert.match(later.message ?? "", POISONED, `${mode}: ${key}: ${later.message}`);
  }
}

if (process.argv[2] === "child") {
  await child(process.argv[3] ?? "");
} else {
  await test("S3: a trap through the API poisons the instance; every later call says to reload", () => {
    const r = runChild("facade");
    assertFailsClosed(r, "facade");
    // The facade's class for it today (mapError): recorded, not required.
    const trap = get(r, "trap");
    assert.match(trap.message ?? "", /unreachable/, `the trap's own message: ${trap.message}`);
  });

  await test("S3: the backend rethrows the WebAssembly.RuntimeError itself, unchanged", () => {
    const r = runChild("backend");
    assertFailsClosed(r, "backend");
    const trap = get(r, "trap");
    assert.equal(trap.runtimeError, true, `expected a WebAssembly.RuntimeError, got ${trap.name}: ${trap.message}`);
  });
}
