# @polyjose/wasm

**polyjose for Web (WASM).** JSON Object Signing and Encryption (JWS, JWE, JWK, JWT) from the pure-Rust [polyjose](https://github.com/bharathkontham/polyjose) core, compiled to WebAssembly. The same package runs in browsers, in Node.js and in Cloudflare Workers.

> Status: **pre-alpha**. Don't use it in production.

- **Pure Rust cryptography** (RustCrypto and dalek crates). There's no OpenSSL, `ring` or `aws-lc`, and the package has no runtime npm dependencies.
- **Misuse-resistant.** Verify and decrypt need an explicit allow-list of algorithms, and `none` is never accepted (RFC 8725).
- **The same API as `@polyjose/node`.** Both packages ship one TypeScript facade, so you can switch between them by changing the import.

## Install

```sh
npm install @polyjose/wasm
```

ESM only. CommonJS code can `require("@polyjose/wasm")` on Node ≥ 22.12 (`require(esm)`).

## Use

```ts
import { jwkGenerateForAlg, jwsSignCompact, jwsVerifyCompact, PolyjoseError } from "@polyjose/wasm";

const key = await jwkGenerateForAlg("ES256");
const token = await jwsSignCompact(new TextEncoder().encode("hello"), key, {
  protectedHeader: { alg: "ES256" },
});

try {
  const { payload } = await jwsVerifyCompact(token, key, { allowedAlgs: ["ES256"] });
  console.log(new TextDecoder().decode(payload));
} catch (e) {
  if (e instanceof PolyjoseError) console.error(e.code); // e.g. "AlgorithmNotAllowed"
  else throw e;
}
```

Every function returns a Promise. The WebAssembly module loads on the first call, and the package never uses top-level await.

## Runtimes

`package.json` `exports` picks the right entry for your runtime:

| Condition | Entry | Loads the module with |
|---|---|---|
| `workerd`, `worker` | `workerd.mjs` | a static `.wasm` import (a `WebAssembly.Module`) and `initSync` |
| `node` | `node.mjs` | `readFileSync` and `initSync` |
| `browser`, `import`, `default` | `browser.mjs` | `fetch` of `new URL("./polyjose_wasm_bg.wasm", import.meta.url)` |

- **Tested:** Node.js ≥ 22.12, headless Chrome and Cloudflare Workers (workerd).
- **Expected to work:** current Firefox and Safari, and bundlers that resolve `new URL(..., import.meta.url)` (webpack 5, Vite, esbuild).
- **Not tested in 0.1.0:** Deno and Bun. Both resolve the `node`/`default` conditions.

The work runs on the calling thread. To keep a page responsive during heavy operations, such as PBES2 with a high iteration count, call the package from a Web Worker.

## License

MIT. `THIRD-PARTY-NOTICES.txt` lists the Rust crates compiled into `polyjose_wasm_bg.wasm`, with their licenses.
