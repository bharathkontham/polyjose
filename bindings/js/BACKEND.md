# The JS backend contract

`bindings/js` is the one TypeScript facade that `@polyjose/node` and `@polyjose/wasm` both ship unchanged (ADR 0031 §1, ADR 0047). It's written against a small **backend**: the functions each native layer exports. The napi-rs loader (`binding.cjs`) and the wasm-bindgen glue each implement it. The typed form is `Backend` in [`src/backend.ts`](src/backend.ts); this page is its prose.

## Rules

- **Names and argument order.** Every ADR 0030 §4 operation, in camelCase, with the ADR's argument order. The table below lists them all.
- **JSON values are text.** JWKs, JWK Sets, headers, claims and JWS/JWE JSON serializations cross the boundary as JSON strings, in and out. The facade does the object↔JSON idiom (ADR 0030 §2). Rust parses everything with the core's strict I-JSON parser (ADR 0016).
- **Records are plain objects** with camelCase fields: `JwsVerifyOptions` is `{ allowedAlgs, detachedPayload?, maxInputLen?, maxSignatures? }`, and so on (ADR 0030 §3–§4).
  - The facade passes **only fields it has validated**.
  - It **leaves an absent optional field out**: it never passes `undefined` or `null`, because napi throws on `null` (0013 research §3).
- **Integers are checked before they reach you.** Sizes and counts are integers in 0..=2^32−1 (`u32`). `now` is a safe integer of whole seconds. wasm-bindgen would otherwise coerce `-1` to `4294967295`.
- **Bytes** are `Uint8Array` (a Node `Buffer` may arrive: it is a subclass).
- **Allow-lists always arrive.** `allowedAlgs` and `allowedEnc` are always present, possibly `[]` (the core then answers `AlgorithmNotAllowed`).
- **`now` always arrives** on the JWT verify options. The facade passes `Math.floor(Date.now() / 1000)` when the caller gives none (ADR 0028 §4, ADR 0030 §4). So no native layer reads a clock, and both packages behave the same.
- **Results** may be returned directly or as a Promise (napi `AsyncTask`). An optional result field may be absent, `undefined` or `null`.
- **Errors.** A core failure is thrown, or rejected, as an object whose `code` is one of `errorCodes()` and whose `message` is the core's text (ADR 0030 §5). The facade turns it into its own `PolyjoseError`, so `instanceof` works the same in both packages. Anything else, such as napi's `InvalidArg` or `StringExpected` or a reader `TypeError`, becomes a `TypeError` with the original message.
- **`version()` and `errorCodes()` are synchronous.** `errorCodes()` returns the core's `Error::CODES`, in order.
- **`ready(): Promise<void>` is optional.** The facade awaits it once, lazily, before the first call of any operation, so WASM initialises without top-level await (ADR 0031 §3). If it rejects, the call rejects with that error unchanged, and the next call tries again.

## Operations

| Backend function | Arguments | Returns |
|---|---|---|
| `version` | – | string |
| `errorCodes` | – | string[] |
| `base64urlEncode` | bytes | string |
| `base64urlDecode` | text | bytes |
| `jwkParse` | jwk | jwk |
| `jwkToPublic` | jwk | jwk |
| `jwkThumbprint` | jwk, hash | string |
| `jwkThumbprintUri` | jwk, hash | string |
| `jwksSelect` | jwks, `{ kid?, alg?, keyUse? }` | jwk |
| `jwkGenerateOct` | lenBytes | jwk |
| `jwkGenerateEc` | crv | jwk |
| `jwkGenerateOkp` | crv | jwk |
| `jwkGenerateForAlg` | alg | jwk |
| `jwkFromPem` | pem | jwk |
| `jwkFromDer` | bytes, format | jwk |
| `jwkToPem` | jwk, format | string |
| `jwkToDer` | jwk, format | bytes |
| `jwsSignCompact` | payload, key, `{ protectedHeader?, protectedB64u?, detached? }` | string |
| `jwsSignFlattened` | payload, `{ key, protectedHeader?, protectedB64u?, unprotectedHeader? }`, detached | JSON text |
| `jwsSignGeneral` | payload, signer[], detached | JSON text |
| `jwsVerifyCompact` | token, key, `JwsVerifyOptions` | `{ alg, payload, protectedHeader?, unprotectedHeader?, signatureIndex }` |
| `jwsVerifyJson` | jws (text), key, `JwsVerifyOptions` | as above |
| `jweEncryptCompact` | plaintext, `{ enc, recipients, protectedHeader?, sharedUnprotectedHeader?, aad?, compress? }` | string |
| `jweEncryptJson` | plaintext, options, form (`general` or `flattened`) | JSON text |
| `jweDecryptCompact` | token, key, `JweDecryptOptions` | `{ plaintext, header, protectedHeader?, sharedUnprotectedHeader?, recipientHeader?, aad?, recipientIndex }` |
| `jweDecryptJson` | jwe (text), key, `JweDecryptOptions` | as above |
| `jwtSign` | claims (text), key, `{ alg, typ?, omitTyp?, accessToken?, header? }` | string |
| `jwtVerify` | token, key, `JwtVerifyOptions` (with `now`) | `{ claims, header, alg, keyIndex?, kid? }` |
| `jwtVerifyWithJwks` | token, jwks, `JwtVerifyOptions` | as above |
| `jwtEncryptNested` | signed JWT, encrypt options | string |
| `jwtDecryptNested` | token, decrypt key, `JweDecryptOptions`, key, `JwtVerifyOptions` | `{ inner, outerHeader, recipientIndex }` |
| `jwtDecryptNestedWithJwks` | token, decrypt key, `JweDecryptOptions`, jwks, `JwtVerifyOptions` | as above |

In this table, "jwk", "jwks", "header" and "claims" are JSON text. A `JweRecipient` is `{ alg, key, header?, apu?, apv?, p2c?, p2sLen? }`. `JwtVerifyOptions` is `{ allowedAlgs, now, issuers?, audiences?, subject?, leeway?, maxAge?, requiredClaims?, allowMissingExp?, ignoreAudience?, typ?, anyTyp?, profile?, maxKeyCandidates?, maxInputLen? }`.

## A package entry

Each package binds the facade to its backend once and re-exports the bound functions:

```ts
import { createApi } from "./api.js"; // the compiled bindings/js facade
import { backend } from "./backend.js"; // this package's adapter over binding.cjs or the wasm glue

export const {
  version, errorCodes, base64urlEncode, base64urlDecode,
  jwkParse, jwkToPublic, /* ... every operation ... */ jwtDecryptNestedWithJwks,
  PolyjoseError,
} = createApi(backend);
export { ERROR_CODES } from "./api.js";
export type * from "./api.js";
```

[`test/fake-entry.ts`](test/fake-entry.ts) is the full list, and `test/entry.test.ts` checks it.

## The conformance runner

`conformance/runner.ts` exports `runVectors(api, files, { schema, features })`.
- It runs vector files through the bound API and returns the ADR 0034 §2 results.
- It has no Node-only imports, so a browser page or a workerd script can feed it the same files.

`conformance/node-main.ts` exports `main(api, { runner, suffix?, root })`.
- It reads `<root>/conformance/vectors/**/*.json`, runs them, and writes `<root>/target/conformance/<runner>.json`, or `<runner>-<suffix>.json` for a CI matrix run.
- `runner` must be one of the ADR 0034 §2 names (`RUNNER_NAMES`). The file's `runner` member is always that bare name.
- It returns the exit code.

The bindings enable no vector feature, so `fixed-rng` and `deflate` vectors are `skipped` with `reason: "feature:<name>"` (ADR 0034 §3).

## Building and testing

`./test.sh` does the following, in order:
1. Refuses any hand-written `.js`, `.mjs`, `.cjs` or `.d.ts`.
2. Runs `npm ci`. TypeScript 7.0.2 is the only dependency, and it is a dev-dependency.
3. Generates `src/error-codes.ts` from `crates/polyjose/src/error.rs`, then runs `tsc`.
4. Checks that the `test/misuse/` project fails to type-check against the generated declarations.
5. Runs `node --test` over the compiled tests in `dist/`.

Generating the error codes uses Node's built-in TypeScript type stripping, so building needs Node ≥ 22.18. The compiled output runs on Node ≥ 22.12, current browsers and workerd (ADR 0031).
