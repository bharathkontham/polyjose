# @polyjose/wasm

**polyjose for Web (WASM).** JSON Object Signing and Encryption (JWS, JWE, JWK, JWT) from the pure-Rust [polyjose](https://github.com/bharathkontham/polyjose) core, compiled to WebAssembly. The same package runs in browsers, Web Workers, Node.js and Cloudflare Workers.

- **Pure Rust cryptography** (RustCrypto and dalek crates). There's no OpenSSL, `ring` or `aws-lc`, and the package has no runtime npm dependencies.
- **Misuse-resistant.** Verify and decrypt need an explicit allow-list of algorithms, and `none` is never accepted (RFC 8725).
- **The same API as `@polyjose/node`.** You can switch between them by changing the import.

## Install

```sh
npm install @polyjose/wasm
```

## Import

The package is ESM, and `exports` picks the right entry for browsers, Node.js and Cloudflare Workers:

```js
import { jwtSign, jwtVerify } from "@polyjose/wasm";
```

On Node.js 22.12 or later, CommonJS code can `require("@polyjose/wasm")` through `require(esm)`. Every function returns a Promise; the WebAssembly module loads on the first call, never at import time.

## Quick start

Sign a JWT, then verify it with an explicit algorithm allow-list and the issuer and audience you expect. `exp` is required and checked, with 60 seconds of leeway (RFC 8725 §3.8 to §3.10).

```js
import { jwkGenerateForAlg, jwkToPublic, jwtSign, jwtVerify, PolyjoseError } from "@polyjose/wasm";

// An ES256 key pair. The verifier needs only the public half.
const privateKey = await jwkGenerateForAlg("ES256");
const publicKey = await jwkToPublic(privateKey);

const now = Math.floor(Date.now() / 1000);
const token = await jwtSign(
  { iss: "https://issuer.example", sub: "user-123", aud: "https://api.example", exp: now + 300 },
  privateKey,
  { alg: "ES256" },
);

try {
  const verified = await jwtVerify(token, publicKey, {
    allowedAlgs: ["ES256"], // never trust the token's own `alg` (RFC 8725 §3.1)
    issuers: ["https://issuer.example"],
    audiences: ["https://api.example"],
  });
  console.log(verified.claims.sub); // "user-123"
} catch (err) {
  if (err instanceof PolyjoseError) console.error(err.code); // e.g. "TokenExpired"
  else throw err;
}
```

Encrypt to a recipient's public key, then decrypt, naming the algorithms you accept:

```js
import { jweDecryptCompact, jweEncryptCompact, jwkGenerateEc, jwkToPublic } from "@polyjose/wasm";

const recipientKey = await jwkGenerateEc("P-256");
const recipientPublicKey = await jwkToPublic(recipientKey);

const jwe = await jweEncryptCompact(new TextEncoder().encode("top secret"), {
  enc: "A256GCM",
  recipients: [{ alg: "ECDH-ES+A256KW", key: recipientPublicKey }],
});

const decrypted = await jweDecryptCompact(jwe, recipientKey, {
  allowedAlgs: ["ECDH-ES+A256KW"],
  allowedEnc: ["A256GCM"],
});
console.log(new TextDecoder().decode(decrypted.plaintext)); // "top secret"
decrypted.plaintext.fill(0); // results are plain data: wipe secret bytes, and never log them
```

In a browser, serve `polyjose_wasm_bg.wasm` byte for byte, and allow `script-src 'wasm-unsafe-eval'` in a Content Security Policy. Heavy calls, such as PBES2 with a high iteration count, run on the calling thread, so call them from a Web Worker.

## Documentation

- Getting started on the web: <https://polyjose.dev/start/web/>
- Runtimes, serving the module, randomness, loader integrity and secrets in memory: <https://polyjose.dev/reference/web/>
- Guides (sign and verify, encrypt and decrypt, validate a JWT, keys): <https://polyjose.dev>
- Error codes: <https://polyjose.dev/concepts/errors/>
- Source and issues: <https://github.com/bharathkontham/polyjose>

## License

MIT; see [LICENSE](https://github.com/bharathkontham/polyjose/blob/main/LICENSE). `THIRD-PARTY-NOTICES.txt` lists the Rust crates compiled into `polyjose_wasm_bg.wasm`, with their licenses.
