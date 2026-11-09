# @polyjose/node

polyjose for Node.js: JOSE (JWS, JWE, JWK and JWT; RFC 7515 to 7519) implemented in pure Rust and
loaded as a Node-API addon. All cryptography comes from the RustCrypto and dalek crates, with no
OpenSSL. Verify and decrypt always take an explicit algorithm allow-list, and `none` is never
accepted (RFC 8725).

## Install

```sh
npm install @polyjose/node
```

Prebuilt for macOS, Linux (glibc and musl) and Windows, see the docs for
[platform support](https://polyjose.dev/reference/node/). Needs Node.js 22.12 or later.

## Import

The package is ESM:

```js
import { jwtSign, jwtVerify } from "@polyjose/node";
```

CommonJS code can load it too, through Node's `require(esm)`:

```js
const { jwtSign, jwtVerify } = require("@polyjose/node");
```

Every function returns a Promise, and the work runs on the libuv thread pool, so it doesn't block
the event loop. The API is the same as `@polyjose/wasm`'s.

## Quick start

Sign a JWT, then verify it with an explicit algorithm allow-list and the issuer and audience you
expect. `exp` is required and checked, with 60 seconds of leeway (RFC 8725 §3.8 to §3.10).

```js
import { jwkGenerateForAlg, jwkToPublic, jwtSign, jwtVerify, PolyjoseError } from "@polyjose/node";

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
import { jweDecryptCompact, jweEncryptCompact, jwkGenerateEc, jwkToPublic } from "@polyjose/node";

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

## Documentation

- Getting started on Node.js: <https://polyjose.dev/start/node/>
- Platform support, how the addon is loaded, and handling secrets in results:
  <https://polyjose.dev/reference/node/>
- Guides (sign and verify, encrypt and decrypt, validate a JWT, keys): <https://polyjose.dev>
- Error codes: <https://polyjose.dev/concepts/errors/>
- Source and issues: <https://github.com/bharathkontham/polyjose>

## License

MIT; see [LICENSE](https://github.com/bharathkontham/polyjose/blob/main/LICENSE).
`THIRD-PARTY-NOTICES.txt` in the package lists the third-party code it contains.
