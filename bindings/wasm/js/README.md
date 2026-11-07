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
| `workerd` | `workerd.mjs` | a static `.wasm` import (a `WebAssembly.Module`) and `initSync` |
| `node` | `node.mjs` | `readFileSync` and `initSync` |
| `browser`, `import`, `default` | `browser.mjs` | `fetch` of `new URL("./polyjose_wasm_bg.wasm", import.meta.url)` |

- **Cloudflare Workers** use the `workerd` entry. Wrangler resolves the `workerd` condition.
- **Browser Web Workers** use the browser entry, `browser.mjs`, like a page does. That includes bundles built with webpack's `target: "webworker"`.

- **Tested:** Node.js ≥ 22.12, headless Chrome and Cloudflare Workers (workerd).
- **Expected to work:** current Firefox and Safari, and bundlers that resolve `new URL(..., import.meta.url)` (webpack 5, Vite, esbuild).
- **Not tested in 0.1.0:** Deno and Bun. Both resolve the `node`/`default` conditions.

The work runs on the calling thread. To keep a page responsive during heavy operations, such as PBES2 with a high iteration count, call the package from a Web Worker.

## Security notes

### Randomness

Every random byte (generated keys, content-encryption keys, IVs, salts, ephemeral keys, signing nonces) comes from `globalThis.crypto.getRandomValues`, looked up on every call. There is no fallback: if `crypto` or `getRandomValues` is missing or throws, the call rejects with `PolyjoseError` code `RandomnessUnavailable`.

Because the lookup happens at call time, whatever `globalThis.crypto` is at that moment replaces the operating system's random number generator:
- **A polyfill or test shim** (for example in some React Native or jsdom setups) that fills arrays from a weak source makes every generated key, content-encryption key and IV predictable, silently. ECDSA signatures stay safe, because their nonces are derived from the key and message as well (RFC 6979 with added randomness).
- **A replaced `getRandomValues` receives a view of the module's whole WebAssembly memory**, not only the bytes it is asked to fill. Code that plants one can read the keys and data held there.

Treat the host's `crypto` as part of what you trust. Use the platform's own `crypto.getRandomValues`, and don't let untrusted code run before or alongside this package in the same realm.

### Serving the module

- **MIME type.** Serve `polyjose_wasm_bg.wasm` as `application/wasm`. With another type, browsers can't compile it while it streams in. The glue then falls back to a slower, non-streaming load and logs a console warning.
- **Content Security Policy.** Allow the fetch of the `.wasm` file (`connect-src`) and WebAssembly compilation (`script-src 'wasm-unsafe-eval'`). Without `'wasm-unsafe-eval'`, a page with a CSP can't compile the module, and the first call rejects.
- **Serve it byte for byte.** A bundler or CDN that rewrites, re-encodes or inlines the `.wasm` will make the first call fail (see [Loader integrity](#loader-integrity)).

### Loader integrity

Each entry loads only the `polyjose_wasm_bg.wasm` shipped next to it, and checks it before first use:
- **Node:** the bytes read from disk must have the SHA-384 recorded in the package at build time. Otherwise the first call rejects.
- **Browsers and bundlers:** the module is fetched with Subresource Integrity (`fetch(url, { integrity: "sha384-…" })`). A bundler, CDN or optimiser that changes the file makes the first call reject.
- **Cloudflare Workers:** the module arrives precompiled in the same deploy bundle as the package's JavaScript, so there are no bytes to hash. The checks below bind it to the package.

In every runtime, the first call also refuses two kinds of module: one that other code initialised first (for example by importing the package's internal files by path), and one whose version differs from the package's. Both refusals are final for that process, worker or page.

### Trust model

Every script in the same JavaScript realm is trusted. Code that can patch `WebAssembly`, `fetch`, `crypto` or `TextEncoder` can subvert any JavaScript library, this one included.

### After a trap

If the module traps (a `WebAssembly.RuntimeError`, for example when it runs out of memory on a very large input), the instance is unusable. That call rejects, and every later call rejects with an error saying to reload. Secrets passed to the trapped call may remain in the module's memory. Restart the process or worker, or reload the page.

### What stays in memory

- **The Rust heap:** inside the WebAssembly module, secret inputs (keys, payloads, plaintexts, passwords) are wiped when a call finishes, and secret outputs are copied out without leaving a copy on the module's heap.
- **The stack is not scrubbed.** Short-lived fragments of keys and plaintext can stay in the module's stack memory after a call, until later calls overwrite them.
- **JWT claims are not treated as secret.** They are returned as plain strings and not wiped. Put secret data in a JWE payload, not in JWT claims.
- **JavaScript copies are yours.** JavaScript strings, such as JWKs, tokens and claims, are immutable, and the garbage collector frees them, so no library can wipe them. A returned `Uint8Array` (a payload, plaintext or DER key) is yours: overwrite it with `fill(0)` when you're done with it.

## License

MIT. `THIRD-PARTY-NOTICES.txt` lists the Rust crates compiled into `polyjose_wasm_bg.wasm`, with their licenses.
