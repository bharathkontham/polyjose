# jwt-oracle

`gen.mjs` turns a JWT vector **spec** into a **vector file** with `node:crypto`, an OpenSSL-backed implementation independent of polyjose (ADR 0008, PRD R9). It exists so that the `jwt.validate` and `jwt.issue` vectors (feature 0004 T11–T13) don't come from polyjose's own signer.

Each spec entry names a header, the raw payload octets, a signing key from [`keys.json`](keys.json) and, optionally, one or more JWE layers. Because the payload is raw octets, malformed claims (duplicate names, string dates, `1e400`, non-UTF-8 bytes) sit behind valid signatures, so each failure is reached past signature verification. The spec author writes the expected verdict; the generator never decides it.

**It is a generator only.** CI never runs it. Its output is committed, and every platform's conformance runner reads the committed files.

## Running it

```sh
node conformance/tools/jwt-oracle/gen.mjs <spec.json> <out.json>
node --test conformance/tools/jwt-oracle/test/      # the self-check
```

It needs Node 24 or later and imports only `node:crypto`, `node:fs` and `node:path`. The self-check adds `node:test` and `node:assert`. There is no `package.json` and no npm dependency. On any error it names the failing spec entry and writes nothing.

The test directory has an `index.js` only so that `node --test conformance/tools/jwt-oracle/test/` works: Node 24 loads a directory argument through its `index.js`. The checks live in `test/selfcheck.mjs`, which also runs on its own.

**Versions used for the committed keys and vectors:** Node v24.21.0, OpenSSL 3.5.8 (`process.versions.openssl`), on 2026-11-06.

## `source` in every vector

Every generated vector's `source` names this tool and the versions that produced it:

```
conformance/tools/jwt-oracle (node:crypto, Node v24.21.0, OpenSSL 3.5.8)
```

If the spec entry gives a `source` (for example `"RFC 7519 §3.1"`), that comes first: `RFC 7519 §3.1; conformance/tools/jwt-oracle (node:crypto, Node v24.21.0, OpenSSL 3.5.8)`.

## Reproducibility

- **HMAC (HS256/384/512) and EdDSA/Ed25519 entries are deterministic.** A re-run produces the same bytes; the self-check runs a spec twice and compares the files.
- **ECDSA (ES256/384/512) signatures and every JWE are randomized.** OpenSSL's ECDSA, the CEK, the IV and the ECDH ephemeral key come from OpenSSL's CSPRNG. A re-run gives different, equally valid bytes. Commit them once, and regenerate only on purpose.
- `source` contains the Node and OpenSSL versions, so a run on other versions changes that string even for deterministic entries.

## Spec format

A spec file is one of the following. The output keeps the same shape.

| Spec | Output |
|---|---|
| an array of entries | an array of vectors |
| `{ "vectors": [entries], ...other }` | the same object, `vectors` replaced, other members kept |
| a single entry | a single vector |

### Entry members

| Member | |
|---|---|
| `description`, `operation`, `input`, `expect` | **Required**, passed through (after reference resolution and token placement). `expect` is the spec author's verdict. |
| `source` | Optional; prefixed to the oracle's `source` (above). |
| `features` and any other member | Passed through unchanged. |
| `jws` | Optional: build a JWS ([below](#jws)). |
| `jwe` | Optional: an object or an array of objects, each encrypting the token so far ([below](#jwe)). |

Output member order: `source`, `description`, `operation`, `input`, `expect`, `features`, then any other members in spec order. `jws` and `jwe` are removed.

### Token placement

The built token replaces every **string** `"$token"` anywhere in the entry, for example `input.token` for `jwt.validate` or `expect.token` for an exact `jwt.issue`. For a flattened serialization, `"$token"` is its JSON text and `"$token_json"` is the same value as a JSON object. An entry that builds a token no `"$token"` uses, or that uses `"$token"` without building one, is an error. An entry with neither `jws` nor `jwe` is passed through, with `source` set as above.

### Key references

Anywhere in an entry (including `input.jwks`, a `jws.header`'s embedded `jwk`, and `key` members), these objects are replaced before anything is built:

| Reference | Becomes |
|---|---|
| `{ "$key": "<name>" }` | the JWK from `keys.json`, private members included |
| `{ "$public": "<name>" }` | its public part: `d` removed (EC, OKP; RFC 7518 §6.2.2, RFC 8037 §2), RSA private members removed (§6.3.2). An `oct` key has no public part; that is an error, so use `$key`. |
| `{ "$oct_from": "<name>", "encoding": "spki-pem" \| "spki-der" \| "jwk-n" }` | an `oct` JWK whose octets are that public key's SPKI PEM text, SPKI DER, or RSA modulus: the HMAC key of an RFC 8725 §2.1 algorithm-confusion token |

Each takes an optional `"with": { ... }` merged over the result; a `null` value deletes the member (for example `{"$public": "p256-kid-a", "with": {"use": "enc"}}` or `{"$key": "oct-32-kid-hs-32", "with": {"kid": null}}`). Other `$`-prefixed members are left alone.

### `jws`

Builds a compact JWS (RFC 7515 §7.1), or its flattened JSON rewrap (§7.2.2).

| Member | |
|---|---|
| `header` \| `header_text` \| `header_b64u` | Exactly one. The JWS Protected Header: an object written with `JSON.stringify` in insertion order, exact UTF-8 text (CRLFs, duplicate names, anything), or the exact encoded form, used verbatim. |
| `payload` \| `payload_b64u` \| `payload_json` | Exactly one. The payload octets: UTF-8 text, base64url octets (any bytes, including non-UTF-8), or a JSON value written with `JSON.stringify`. Use `payload` for exact octets: `payload_json` goes through `JSON.parse`, which loses large integers and `1e400`. |
| `key` | A `keys.json` name or a JWK object. Required, except with `alg: "none"` or `signature_b64u`. |
| `alg` | The signing algorithm, when the header names none or a different one. Defaults to the header's `alg`. |
| `corrupt_signature` | `true` flips the low bit of the last signature octet, after signing. |
| `signature_b64u` | Write this signature verbatim instead of signing, for example a forged signature on an `alg: "none"` token. Takes no `key`. |
| `replace_after_signing` | `{ header* , payload* }` (the same member names as above): swap the header and/or payload after signing, keeping the old signature (tampered tokens). |
| `serialization` | `"compact"` (default) or `"flattened"`. |
| `unprotected` | Flattened only: the unprotected `header` member, for example `{"typ": "at+jwt"}` (the ADR 0049 §2 vector). |

Signing:

- `HS256`, `HS384`, `HS512`: HMAC (RFC 7518 §3.2) with an `oct` key at least as long as the hash output. A shorter key is refused.
- `ES256`, `ES384`, `ES512`: ECDSA on P-256, P-384, P-521 with R ‖ S output (RFC 7518 §3.4, `dsaEncoding: "ieee-p1363"`). The generator checks each signature with `crypto.verify`.
- `EdDSA` (RFC 8037 §3.1) and `Ed25519` (RFC 9864 §2.2) with an Ed25519 key.
- `none`: an empty signature (RFC 7519 §6.1), no key.
- The signing input is ASCII(BASE64URL(protected) ‖ '.' ‖ BASE64URL(payload)) (RFC 7515 §5.1). When the protected header has `"b64": false`, it is BASE64URL(protected) ‖ '.' ‖ the payload octets, and the payload is written unencoded (RFC 7797 §3). A compact payload containing '.' is refused (RFC 7797 §5.2).
- **RSA signing is refused** by the oracle: any `RS*`/`PS*` alg, or any RSA key. RS256/PS256 tokens to validate are RFC-published (for example RFC 7515 A.2) and pass through as entries without `jws`; polyjose's own RSA issuance (ADR 0067) is checked by `jwt.issue` round trips (`positive/issue-ps256-round-trip.json`) and by `jwt/rfc7519/a2-rs256-issue-exact.json`, whose token is derived with Python integers.
- A key that doesn't match the alg (wrong `kty` or curve, a public key) is refused.

The flattened form has the members `payload`, `protected`, `header` (if `unprotected` is given) and `signature`, in RFC 7515 §7.2.2's order. Its `protected`, `payload` and `signature` are exactly the compact token's three parts. The unprotected header isn't signed, so the signature stays valid.

### `jwe`

Encrypts the previous token as a JWE (RFC 7516 §5.1): a nested JWT (RFC 7519 §5.2, §11.2). An array of layers applies them in order, so `[A, B]` gives a JWE inside a JWE. The first layer of an entry without `jws` encrypts its own `plaintext` (UTF-8 text) or `plaintext_b64u`, for example claims for an encrypt-only JWT.

| Member | |
|---|---|
| `alg` | `dir` (RFC 7518 §4.5), `A128KW` / `A192KW` / `A256KW` (§4.4, OpenSSL `id-aes*-wrap`), or `ECDH-ES+A128KW` / `+A192KW` / `+A256KW` (§4.6) on P-256, P-384 or P-521 |
| `enc` | `A128GCM`, `A192GCM`, `A256GCM` (§5.3; 96-bit IV, 128-bit tag) |
| `key` | A `keys.json` name or a JWK: the `oct` key (its length must match), or the recipient's EC key (only its public part is used to encrypt) |
| `header` | Merged over the protected header `{alg, enc, epk?, cty: "JWT"}`. A `null` value deletes a member (`{"cty": null}` for no `cty`). `alg`, `enc` and `epk` belong to the generator. `apu`/`apv` placed here are used in the Concat KDF (§4.6.1.2–§4.6.1.3). |
| `serialization` | `"compact"` (default; §7.1) or `"flattened"` (§7.2.2) |
| `unprotected`, `recipient_header` | Flattened only: the shared `unprotected` and per-recipient `header` members (for example `cty` only in `unprotected`, the ADR 0050 §3 vector) |
| `corrupt` | `"tag"` or `"ciphertext"`: flip the low bit of that part's last octet |

- The protected header gets `cty: "JWT"` (RFC 7519 §5.2) unless `header` overrides it (for example `"jwt"`) or removes it.
- ECDH-ES: the ephemeral key comes from `createECDH(...).generateKeys()`. Z comes from ECDH with the recipient's public point. The KEK is the RFC 7518 §4.6.2 Concat KDF (SHA-256, AlgorithmID = the `alg`, SuppPubInfo = the key size in bits). The `epk` holds the ephemeral public key only.
- The AAD is ASCII(BASE64URL(UTF8(protected))) (RFC 7516 §5.1 step 14). There is no JSON `aad` member.
- Flattened output: `protected`, `unprotected`?, `header`?, `encrypted_key` (absent when empty, as for `dir`; §7.2.1), `iv`, `ciphertext`, `tag`.
- Each layer checks its own key wrap (unwrap), ECDH agreement (from the recipient side, when `keys.json` has its `d`) and AES-GCM round trip before it is used.

### Example

```json
{
  "vectors": [
    {
      "description": "RFC 7519 §3.1 claims, HS256, accepted at iat (ADR 0027 §3)",
      "operation": "jwt.validate",
      "input": { "token": "$token", "now": 1300819320, "allowed_algs": ["HS256"], "key": { "$key": "oct-64" } },
      "expect": { "ok": true },
      "jws": {
        "header_text": "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}",
        "payload": "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}",
        "key": "oct-64"
      }
    },
    {
      "description": "exp as a string is not a NumericDate (ADR 0027 §2)",
      "operation": "jwt.validate",
      "input": { "token": "$token", "now": 0, "allowed_algs": ["ES256"], "key": { "$public": "p256" } },
      "expect": { "ok": false, "error": "InvalidClaim" },
      "jws": { "header": { "alg": "ES256", "typ": "JWT" }, "payload": "{\"exp\":\"1300819380\"}", "key": "p256" },
      "jwe": { "alg": "ECDH-ES+A128KW", "enc": "A128GCM", "key": "p256-ecdh" }
    }
  ]
}
```

The `input` members follow the `jwt.*` schema of `conformance/README.md` (0004 T10); the generator doesn't check them.

## `keys.json`

These are the fixed test keys that specs name. **They are test fixtures only.** Every private key in the file is public test data, used nowhere else. RSA keys are public only (ADR 0021), and no RSA private key is ever used for signing.

| Name | Key | Source |
|---|---|---|
| `oct-16`, `oct-32`, `oct-48` | oct, 16/32/48 octets | generated |
| `oct-64` | oct, 64 octets | RFC 7515 A.1.1 (also RFC 7519 §3.1's key) |
| `p256` | P-256 | RFC 7515 A.3.1 |
| `p384` | P-384 | RFC 7520 §5.4.1, with its `kid` and `use: enc` dropped |
| `p521` | P-521 | RFC 7515 A.4.1 |
| `ed25519` | Ed25519 | RFC 8037 A.1 |
| `ed25519-other` | Ed25519 | generated (the second key of selection tests) |
| `p256-kid-a`, `-b`, `-c` | P-256, `kid` `a`/`b`/`c` | generated (ADR 0029 selection) |
| `oct-32-kid-hs-32`, `oct-64-kid-hs-64` | oct, `kid` `hs-32`/`hs-64` | generated (ADR 0029 selection) |
| `p256-cand-1` … `p256-cand-9` | P-256, no `kid` | generated (nine candidates for the ADR 0029 §4 bound of 8) |
| `p256-attacker` | P-256 | generated (embedded-`jwk` header attacks, CVE-2018-0114) |
| `p256-ecdh` | P-256 | generated (ECDH-ES+A*KW recipient) |
| `rsa-2048` | RSA public, 2048 bits | RFC 7520 §3.3 Figure 3 |
| `rsa-2048-rfc7515-a2` | RSA public, 2048 bits | RFC 7515 A.2.1, `n` and `e` only |
| `rsa-8200` | RSA public, 8200 bits | generated; private half never written |

Every entry's `source` member gives the exact origin. The RFC keys were copied from the already vendored vectors (`conformance/vectors/jws-rfc7515/`, `third_party/rfc7520/jws/`, `jwe/ecdh-es/`), never typed in.

**How the generated keys were made.** A one-off script ran once on 2026-11-06 with Node v24.21.0 and OpenSSL 3.5.8. It isn't kept, because the keys are fixed and re-running it would change them. It used:

- `crypto.generateKeySync('hmac', { length })` for the oct keys
- `crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })` for the P-256 keys
- `crypto.generateKeyPairSync('ed25519')` for the Ed25519 key
- for `rsa-8200`, `crypto.generateKeyPairSync('rsa', { modulusLength: 8200, publicExponent: 0x10001 })`. Only `publicKey.export({ format: 'jwk' })` was written. The private key object was never exported or stored, and was discarded when the process exited.

`rsa-8200` is over the 8192-bit RSA import limit, for the ADR 0041 §2 / 0005 F02 vector: a JWK Set member that is skipped at import, leaving `NoMatchingKey`. Its modulus is exactly 8200 bits (1025 octets, top bit set). The self-check verifies that.

## Self-check (`test/selfcheck.mjs`)

- **RFC 7519 §3.1:** the HS256 token over the RFC's exact header and claims octets, with the RFC 7515 A.1 key, equals the RFC's token byte for byte. It also equals the vendored RFC 7515 A.1 `jws.sign` vector.
- **ECDSA:** ES256/384/512 tokens verify with `crypto.verify` and `dsaEncoding: 'ieee-p1363'`. EdDSA and Ed25519 tokens verify.
- **ECDH-ES+A128KW:** the nested token decrypts on a path the generator doesn't use: KeyObject `crypto.diffieHellman`, a separately written Concat KDF, `id-aes128-wrap` unwrap, AES-GCM. dir and A128KW tokens decrypt the same way.
- **Determinism:** HS256/384/512, EdDSA and Ed25519 generation is deterministic. Two runs of a spec write identical files.
- **Keys:** sources are present, EC/OKP private keys derive their public halves, RSA keys are public only, and `rsa-8200` is over 8192 bits.
- **Features and refusals:** reference resolution, pass-through and `source`, the negative-entry features (corruption, `none`, forged signatures, RFC 7797, tampering, the flattened rewraps), and the refusals (RSA signing, wrong curves, short HMAC keys, unknown members, missing `expect`).

panva/jose is deliberately not used, to keep the oracle dependency-free (feature 0004 research.md).
