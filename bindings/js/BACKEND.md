# The JS backend contract

`bindings/js` is the one TypeScript facade that `@polyjose/node` and `@polyjose/wasm` both ship unchanged (ADR 0031 §1, ADR 0047). It's written against a small **backend**: the functions each native layer exports. The napi-rs loader (`binding.cjs`) and the wasm-bindgen glue each implement it. The typed form is `Backend` in [`src/backend.ts`](src/backend.ts); this page is its prose.

## Rules

- **Names and argument order.** Every ADR 0030 §4 operation, in camelCase, with the ADR's argument order. The table below lists them all.
- **JSON values are text.** JWKs, JWK Sets, headers, claims and JWS/JWE JSON serializations cross the boundary as JSON strings, in and out. The facade does the object↔JSON idiom (ADR 0030 §2). Rust parses everything with the core's strict I-JSON parser (ADR 0016).
  - A caller's string arrives unchanged. For a caller's plain object, the facade writes the text itself from the object's own plain data: the `JSON.stringify` text, but with no `toJSON` called at any depth (inherited or own) and nothing read through a prototype (0013 F09). A polluted `Object.prototype.toJSON` or `Array.prototype.toJSON`, or an `Array.prototype[i]` behind an array hole, therefore can't change the claims, key or header you receive. Array holes and values that aren't JSON data (a `Date`, `Map`, class instance, function, BigInt) are `TypeError`s before you are called.
- **Records are plain objects** with camelCase fields: `JwsVerifyOptions` is `{ allowedAlgs, detachedPayload?, maxInputLen?, maxSignatures? }`, and so on (ADR 0030 §3–§4).
  - The facade passes **only fields it has validated**.
  - It **leaves an absent optional field out**: it never passes `undefined` or `null`, because napi throws on `null` (0013 research §3).
  - Each record, including each `JwsSigner` and `JweRecipient` in a list, is a **prototype-less object** (`Object.create(null)`) built from the caller's own members only, so a polluted `Object.prototype` in the host app can't add a member you would read (0013 F04, security audit M1). Read fields by name; a member is present only if `in` says so. Don't call `Object.prototype` methods on a record (`rec.hasOwnProperty` is `undefined`); napi-rs `#[napi(object)]` and wasm-bindgen readers look fields up by name, which meets this.
- **An absent optional argument is `undefined`, never `null`.** The one optional positional argument is the thumbprint `hash` (ADR 0054 §9): `jwkThumbprint` and `jwkThumbprintUri` are always called with two arguments, and the second is `undefined` when the caller gave none or `null`. Map it to `None` (napi `Option<String>`, wasm-bindgen `Option<String>`), so the core's default, SHA-256, applies. A name arrives as the caller wrote it; the core parses it (`ThumbprintHash::from_name`, nine exact names), so the native layer passes it on unchanged.
- **Integers are checked before they reach you.** Sizes and counts are integers in 0..=2^32−1 (`u32`). `now` is a safe integer of whole seconds. wasm-bindgen would otherwise coerce `-1` to `4294967295`.
- **Bytes are fresh copies the facade wipes.** Every byte input (payloads, `detachedPayload`, plaintext, `aad`, `apu`, `apv`, DER, `base64urlEncode` input) arrives as a plain `Uint8Array` that the facade copied from the caller's array when the operation was called (ADR 0030 §7, 0013 B06).
  - The facade wipes each copy with `fill(0)` once your call settles: when you return, throw, or your Promise resolves or rejects.
  - So read or copy the bytes before you settle, and **never keep or return an input array**: it is zeros afterwards. napi-rs and wasm-bindgen copy the bytes into Rust memory during the call, which meets this.
  - The caller's own array is never passed to you and never wiped.
- **Inputs are taken at the call.** The facade validates and normalises every argument synchronously, when the operation is called: it copies bytes, serialises JSON objects and reads the clock for `now` before it awaits `ready()`. A caller that changes its array or object after starting a call can't change what you receive. Argument errors are `TypeError`s raised before `ready()` or your function is called.
- **Allow-lists always arrive.** `allowedAlgs` and `allowedEnc` are always present, possibly `[]` (the core then answers `AlgorithmNotAllowed`).
- **`now` always arrives** on the JWT verify options. The facade passes `Math.floor(Date.now() / 1000)`, read when the operation is called, when the caller gives none (ADR 0028 §4, ADR 0030 §4). So no native layer reads a clock, and both packages behave the same.
- **Results** may be returned directly or as a Promise (napi `AsyncTask`). An optional result field may be absent, `undefined` or `null`.
  - The facade reads a result's **own** members only (`Object.hasOwn`, 0013 F09), so a member a pollution bug put on `Object.prototype` never stands in for one you left out: an absent `kid` stays absent, and a missing required field is a `TypeError`. Return each field as an own data property of a plain or prototype-less object. napi-rs `#[napi(object)]` and an object built with `js_sys::Reflect::set` do this; a class instance whose fields are getters on its prototype would read as empty.
  - `errorCodes()` is read the same way: by own index, a hole being an error, never an `Array.prototype` element.
  - What the facade **hands the caller** is built the same way in reverse (0013 F13): each result member is created with `Object.defineProperty` as an own, enumerable, writable, configurable data property, never by assignment, and each array element at its index, never with `push`. Results still inherit from `Object.prototype`. So a setter or a read-only member that a pollution bug put on `Object.prototype` (`aad`, `kid`, a header) or on `Array.prototype[0]` never receives a value and never makes a call fail. The arrays you receive (byte copies, lists, signers and recipients) are built the same way.
- **Errors.** Throw, or reject with, an object whose `code` is one of `errorCodes()` and whose `message` is the core's text for a core failure (ADR 0030 §5). Set both as **own data properties**: napi-rs (`napi_create_error`) and wasm-bindgen (`Reflect::set`) do. The facade reads `code` and `message` as own data members only, never through a prototype or a getter (0013 F12), and maps what you throw in this order:

  | You throw | The caller gets |
  |---|---|
  | anything with an own `code` that is in the facade's generated `ERROR_CODES` and in your `errorCodes()` | a `PolyjoseError` with that `code` and your own `message` (or the code, if you set no message). So `instanceof` works the same in both packages, and a code from a newer core never escapes the `ErrorCode` type (0013 F04). |
  | a `TypeError` (for example the wasm reader's) | that `TypeError`, unchanged |
  | an `Error` whose own `code` is a napi-rs argument-conversion status: `InvalidArg`, `ObjectExpected`, `StringExpected`, `NameExpected`, `FunctionExpected`, `NumberExpected`, `BooleanExpected`, `ArrayExpected`, `BigintExpected`, `DateExpected`, `ArrayBufferExpected`, `DetachableArraybufferExpected` (napi 3.16 `Status`) | a `TypeError` with your own `message` |
  | **anything else** | **the same value, unchanged**: a `WebAssembly.RuntimeError` trap, your own "backend unusable, reload it" error, another napi status (`GenericFailure`, `PendingException`, ...), a code only one side knows, an `Error` without a code, a thrown string |

  - A `TypeError` says the caller passed a bad argument, so the facade uses it only for argument errors. A trap or an unusable backend isn't the caller's mistake; it reaches the caller as you threw it, still a rejection (fail-closed). There is no marker for "backend unusable": throw your own `Error` (no core `code`) and it arrives unchanged.
  - `errorCodes()` is asked only when an error's own `code` is in `ERROR_CODES`. If it then throws or returns no array, the failing call rejects with an `Error` naming that cause (0013 F04). A failure without such a code never calls it, so a backend whose `errorCodes()` refuses after a trap still reports its own error.
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
| `jwkThumbprint` | jwk, hash (a string or `undefined`) | string |
| `jwkThumbprintUri` | jwk, hash (a string or `undefined`) | string |
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
- It is a caller of the facade and follows the same rule (0013 F13): every option record, signer, recipient and output record it builds is prototype-less, and every list is filled by index (`conformance/own.ts`), so no inherited setter sees an `aad`, a key or a plaintext.

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
