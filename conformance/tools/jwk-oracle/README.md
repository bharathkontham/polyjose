# jwk-oracle

Two generators of JWK vectors, neither of which calls polyjose:

- `thumbprints.mjs` writes the SHA-384, SHA-512 and hash-name `jwk.thumbprint` vectors ([below](#thumbprintsmjs)).
- `select.mjs` writes the `jwks.select` vectors from a hand-written spec ([below](#selectmjs)).

## `thumbprints.mjs`

`thumbprints.mjs` generates the SHA-384, SHA-512 and hash-name `jwk.thumbprint` vectors in [`../../vectors/jwk-thumbprint/`](../../vectors/jwk-thumbprint/) (feature 0015 T03, ADR 0054 §8) with `node:crypto`, an OpenSSL-backed implementation independent of polyjose. No RFC prints a SHA-384 or SHA-512 JWK Thumbprint, so Node is the oracle, and panva/jose 6.2.15 (ADR 0035's pin) is the one-off cross-check.

**It is a generator only.** CI never runs it. Its output is committed, and every platform's conformance runner reads the committed files like any other vector.

### Running it

```sh
node conformance/tools/jwk-oracle/thumbprints.mjs conformance/vectors/jwk-thumbprint   # regenerate in place
node conformance/tools/jwk-oracle/thumbprints.mjs <dir>                                # write elsewhere, e.g. to diff against
```

It needs Node 24 or later and nothing else: no `package.json`, no npm dependencies, and it never calls polyjose. It writes only the 25 files below, and leaves the other files of the directory alone. Each oracle-derived `description` records the Node and OpenSSL versions that produced it; the committed files come from **Node.js 24.21.0 / OpenSSL 3.5.8**, and a re-run with those versions reproduces them byte for byte. Another version changes only that text.

### Inputs

The six keys are written into the script, each exactly as in its committed SHA-256 vector (same members, same order), so a new vector differs from its SHA-256 twin only in `hash` and `expect`:

| Slug | Key | Its SHA-256 vector |
|---|---|---|
| `rfc7638-3-1-rsa` | RFC 7638 §3.1 RSA public key, with `alg` and `kid` | `rfc7638-3-1-rsa.json` |
| `rfc8037-a3-ed25519-public` | RFC 8037 A.2 Ed25519 public key | `rfc8037-a3-ed25519-public.json` |
| `rfc8037-a3-ed25519-private` | RFC 8037 A.1 Ed25519 private key (`d` is not hashed, RFC 7638 §3.2.1) | `rfc8037-a3-ed25519-private.json` |
| `rfc7517-a1-p256-public` | RFC 7517 A.1 P-256 public key, with `use` and `kid` | `rfc7517-a1-p256-public.json` |
| `rfc7517-a3-oct-a128kw` | RFC 7517 A.3 AES key, with `alg` | `rfc7517-a3-oct-a128kw.json` |
| `rfc8037-a6-x25519-public` | RFC 8037 A.6 X25519 public key (Bob, RFC 7748 §6.1), with `kid` | `rfc8037-a6-x25519-public.json` |

### What it generates

| Files | `hash` | Expected |
|---|---|---|
| `sha384-<slug>.json` (6) | `sha-384` | the SHA-384 thumbprint and its `…:sha-384:…` URI |
| `sha512-<slug>.json` (6) | `sha-512` | the SHA-512 thumbprint and its `…:sha-512:…` URI |
| `hash-default-rfc7638-3-1-rsa.json` | absent | the core default, SHA-256: the RFC 7638 §3.1 value and the RFC 9278 §6 URI |
| `hash-alias-upper-sha-{256,384,512}-rfc7638-3-1-rsa.json` | `SHA-256`, `SHA-384`, `SHA-512` (ADR 0030 §4) | the same as the IANA-name vector, with the IANA name in the URI |
| `hash-alias-sha{256,384,512}-rfc7638-3-1-rsa.json` | `sha256`, `sha384`, `sha512` (panva/jose) | the same as the IANA-name vector, with the IANA name in the URI |
| `hash-reject-{upper-sha-1,sha-1,sha-256-128,sha3-256,mixed-case-sha-256,empty}.json` | `SHA-1`, `sha-1`, `sha-256-128`, `sha3-256`, `Sha-256`, `""` | `UnsupportedAlgorithm` (ADR 0022, ADR 0054 §8.2, RFC 9278 §4) |

The file names are lowercase, so `SHA-1` and `sha-1` can't collide on a case-insensitive file system.

### How the values are built

- **Hash input (RFC 7638 §3.2, §3.3).** The script builds it by hand: the required members of the key type only (`e`, `kty`, `n` for RSA; `crv`, `kty`, `x`, `y` for EC; `k`, `kty` for oct; `crv`, `kty`, `x` for OKP, RFC 8037 §2), in lexicographic order, without whitespace, each name and value as a JSON string. A value that would need escaping is refused, since RFC 7638 §3.3 leaves its thumbprint undefined.
- **Hash (RFC 7638 §3.4).** `createHash("sha256" | "sha384" | "sha512")` over the UTF-8 input, then unpadded base64url.
- **URI (RFC 9278 §3, §4).** `urn:ietf:params:oauth:jwk-thumbprint:` + the IANA Hash Name String (`sha-256`, `sha-384`, `sha-512`) + `:` + the thumbprint, whatever spelling the vector's `hash` uses.

### Self-checks

Before it writes anything the script checks that it reproduces:

- the RFC 7638 §3.1 hash input and thumbprint (`NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`)
- the RFC 9278 §6 URI
- the RFC 8037 A.3 thumbprint (`kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`) for both the A.2 public and the A.1 private Ed25519 key
- output lengths of 64 (SHA-384) and 86 (SHA-512) characters for every key

Any failed check stops the script before it writes anything.

### Cross-check (not committed)

The SHA-384 and SHA-512 values were checked once against panva/jose **6.2.15** (`calculateJwkThumbprint` and `calculateJwkThumbprintUri` with `sha256`, `sha384` and `sha512`), installed in a scratch directory outside the repository. Nothing from panva is committed (MIT, clean-room). The ten values that feature 0015's research.md §4 lists also agree; the two X25519 values are new and rest on the two oracles alone.

## `select.mjs`

`select.mjs` writes the `jwks.select` vectors in [`../../vectors/jwks-select/`](../../vectors/jwks-select/) (feature 0015 T04, ADR 0054 §1–§4), one file per entry of [`specs/select.json`](specs/select.json) (ADR 0045).

**The spec decides every outcome, never the script or polyjose.** Each entry's expected outcome was derived by hand from the ADR 0054 text, and its `rule` names the check that decides it. The script resolves the key references, checks the spec and the fixtures, and writes the files. When the Rust runner disagrees with an entry, the entry is re-derived from the ADR. It is never edited to match the code: a wrong rule in the code is a bug, and an ambiguous ADR is a question for the owner.

**It is a generator only.** CI never runs it.

### Running it

```sh
node conformance/tools/jwk-oracle/select.mjs conformance/tools/jwk-oracle/specs/select.json conformance/vectors/jwks-select   # regenerate in place
node conformance/tools/jwk-oracle/select.mjs conformance/tools/jwk-oracle/specs/select.json <dir>                             # write elsewhere, then diff -r
```

It needs Node 24 or later and only its built-ins (`node:crypto`, `node:fs`, `node:path`, `node:url`, `node:util`): no `package.json` and no npm dependencies. It writes one file per spec entry and leaves other files alone. A vector contains no Node or OpenSSL version and nothing random, so a rerun reproduces every file byte for byte (`diff -r` against the committed directory is empty). Any failed check stops it before it writes anything.

### Spec format

`specs/select.json` is `{ "comment": [...], "vectors": [entries] }`. Each entry has exactly these members:

| Member | |
|---|---|
| `id` | The file name without `.json`: lowercase words joined by `-`, starting with the outcome's prefix (`select-`, `no-match-`, `multiple-`, `unsupported-`, `invalid-key-`) or `precedence-` for an ADR 0054 §4 order case. |
| `source` | Must cite an ADR 0054 section and an RFC section. Copied to the vector. |
| `description` | What the vector checks. |
| `rule` | The ADR 0054 rule that decides the outcome, worked through for this set. The vector's `description` is `description; rule; outcome hand-derived …`. |
| `jwks` | The JWK Set: `{ "keys": [members] }`, or `{ "$set": "rfc7517-a1" \| "rfc7517-a2" \| "rfc7517-a3" }` for that RFC 7517 Appendix A set as printed, or any other object (a malformed set, passed through). |
| `selector` | Passed through: `kid`, `alg`, `key_use`, each a string. |
| `expect` | `{ "member": <n> }`: success with `keys[n]` (counting skipped entries); or `{ "error": <code> }`, one of `NoMatchingKey`, `MultipleMatchingKeys`, `UnsupportedAlgorithm`, `InvalidKey`. |

A member of `keys` is either a literal JSON object, passed through (for example `{ "kty": "XYZ" }`), or a key reference as in [`../jwt-oracle/README.md`](../jwt-oracle/README.md#key-references):

- `{ "$key": "<name>" }`: the key as stored, private members included
- `{ "$public": "<name>" }`: its public part (an `oct` key has none, so that's an error)

Either takes an optional `"with": { ... }` merged over the key, where `null` deletes a member. A positive's expected member must be a key reference, never a literal, and the script checks that the expected `jwk` is one of the input members.

### Keys

All committed fixtures, each checked before use:

| Name | Key | Check |
|---|---|---|
| the names of [`../jwt-oracle/keys.json`](../jwt-oracle/keys.json) | the shared JWT test keys, RFC keys and Node-generated ones | each entry's `source` there |
| `rsa1024` | `crates/polyjose/tests/data/jwe/rsa-bound/rsa1024.jwk.json`, a 1024-bit RSA public key that every set import skips (ADR 0021, ADR 0041 §2) | `n` is 128 octets, no `d` |
| `x25519-bob` | Bob's X25519 public key of RFC 8037 A.6 (RFC 7748 §6.1), with its `kid` `Bob` | Bob's RFC 7748 §6.1 private key gives this `x` |
| `secp256k1` | the fixed secp256k1 key of `../jws-oracle/gen.mjs` (`d` = SHA-256 of its label), rebuilt the same way | equals the public key in the committed `jws-oracle/es256k-*` vectors |
| `$set` `rfc7517-a1`, `-a2`, `-a3` | RFC 7517 Appendix A.1, A.2 and A.3, as printed (the transcription of `crates/polyjose/tests/jwk_rfc7517.rs`) | A.2's EC `d` gives A.1's point; A.2's RSA `p · q = n` and `n` is A.1's; A.3's HMAC key is RFC 7515 A.1.1's |

### Cross-check against panva/jose (not committed)

The vectors in panva's domain were checked once against panva/jose **6.2.15** (ADR 0035's pin). This was done with Node.js 24.21.0, in a scratch directory outside the repository, and nothing from it is committed. The domain is:

- a JWS `alg` other than HS\* and ES256K
- no `key_use: enc`
- a set of public members only (no `oct`, no `d`, no RSA private members)

For each of those vectors, `createLocalJWKSet(jwks)({ alg, kid })` gave the same key, compared by SHA-256 thumbprint, or `ERR_JWKS_NO_MATCHING_KEY` for `NoMatchingKey`, or `ERR_JWKS_MULTIPLE_MATCHING_KEYS` for `MultipleMatchingKeys`.

- **Result: 12 agree, 0 disagree, 52 not applicable.**
- The not-applicable vectors have no `alg`, a JWE or unsupported `alg`, HS\* or ES256K, `key_use: enc`, a malformed set, or a non-public member.
- A supplementary run that also admitted sets with a non-public member that is never selected agreed on three more vectors. The only difference was `select-ec-private-member-keeps-d`, where panva refuses a private member (`ERR_JWKS_INVALID`, "members must be public keys") and ADR 0054 §3 returns it as imported.
