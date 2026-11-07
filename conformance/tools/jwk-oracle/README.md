# jwk-oracle

`thumbprints.mjs` generates the SHA-384, SHA-512 and hash-name `jwk.thumbprint` vectors in [`../../vectors/jwk-thumbprint/`](../../vectors/jwk-thumbprint/) (feature 0015 T03, ADR 0054 §8) with `node:crypto`, an OpenSSL-backed implementation independent of polyjose. No RFC prints a SHA-384 or SHA-512 JWK Thumbprint, so Node is the oracle, and panva/jose 6.2.15 (ADR 0035's pin) is the one-off cross-check.

**It is a generator only.** CI never runs it. Its output is committed, and every platform's conformance runner reads the committed files like any other vector.

## Running it

```sh
node conformance/tools/jwk-oracle/thumbprints.mjs conformance/vectors/jwk-thumbprint   # regenerate in place
node conformance/tools/jwk-oracle/thumbprints.mjs <dir>                                # write elsewhere, e.g. to diff against
```

It needs Node 24 or later and nothing else: no `package.json`, no npm dependencies, and it never calls polyjose. It writes only the 25 files below, and leaves the other files of the directory alone. Each oracle-derived `description` records the Node and OpenSSL versions that produced it; the committed files come from **Node.js 24.21.0 / OpenSSL 3.5.8**, and a re-run with those versions reproduces them byte for byte. Another version changes only that text.

## Inputs

The six keys are written into the script, each exactly as in its committed SHA-256 vector (same members, same order), so a new vector differs from its SHA-256 twin only in `hash` and `expect`:

| Slug | Key | Its SHA-256 vector |
|---|---|---|
| `rfc7638-3-1-rsa` | RFC 7638 §3.1 RSA public key, with `alg` and `kid` | `rfc7638-3-1-rsa.json` |
| `rfc8037-a3-ed25519-public` | RFC 8037 A.2 Ed25519 public key | `rfc8037-a3-ed25519-public.json` |
| `rfc8037-a3-ed25519-private` | RFC 8037 A.1 Ed25519 private key (`d` is not hashed, RFC 7638 §3.2.1) | `rfc8037-a3-ed25519-private.json` |
| `rfc7517-a1-p256-public` | RFC 7517 A.1 P-256 public key, with `use` and `kid` | `rfc7517-a1-p256-public.json` |
| `rfc7517-a3-oct-a128kw` | RFC 7517 A.3 AES key, with `alg` | `rfc7517-a3-oct-a128kw.json` |
| `rfc8037-a6-x25519-public` | RFC 8037 A.6 X25519 public key (Bob, RFC 7748 §6.1), with `kid` | `rfc8037-a6-x25519-public.json` |

## What it generates

| Files | `hash` | Expected |
|---|---|---|
| `sha384-<slug>.json` (6) | `sha-384` | the SHA-384 thumbprint and its `…:sha-384:…` URI |
| `sha512-<slug>.json` (6) | `sha-512` | the SHA-512 thumbprint and its `…:sha-512:…` URI |
| `hash-default-rfc7638-3-1-rsa.json` | absent | the core default, SHA-256: the RFC 7638 §3.1 value and the RFC 9278 §6 URI |
| `hash-alias-upper-sha-{256,384,512}-rfc7638-3-1-rsa.json` | `SHA-256`, `SHA-384`, `SHA-512` (ADR 0030 §4) | the same as the IANA-name vector, with the IANA name in the URI |
| `hash-alias-sha{256,384,512}-rfc7638-3-1-rsa.json` | `sha256`, `sha384`, `sha512` (panva/jose) | the same as the IANA-name vector, with the IANA name in the URI |
| `hash-reject-{upper-sha-1,sha-1,sha-256-128,sha3-256,mixed-case-sha-256,empty}.json` | `SHA-1`, `sha-1`, `sha-256-128`, `sha3-256`, `Sha-256`, `""` | `UnsupportedAlgorithm` (ADR 0022, ADR 0054 §8.2, RFC 9278 §4) |

The file names are lowercase, so `SHA-1` and `sha-1` can't collide on a case-insensitive file system.

## How the values are built

- **Hash input (RFC 7638 §3.2, §3.3).** The script builds it by hand: the required members of the key type only (`e`, `kty`, `n` for RSA; `crv`, `kty`, `x`, `y` for EC; `k`, `kty` for oct; `crv`, `kty`, `x` for OKP, RFC 8037 §2), in lexicographic order, without whitespace, each name and value as a JSON string. A value that would need escaping is refused, since RFC 7638 §3.3 leaves its thumbprint undefined.
- **Hash (RFC 7638 §3.4).** `createHash("sha256" | "sha384" | "sha512")` over the UTF-8 input, then unpadded base64url.
- **URI (RFC 9278 §3, §4).** `urn:ietf:params:oauth:jwk-thumbprint:` + the IANA Hash Name String (`sha-256`, `sha-384`, `sha-512`) + `:` + the thumbprint, whatever spelling the vector's `hash` uses.

## Self-checks

Before it writes anything the script checks that it reproduces:

- the RFC 7638 §3.1 hash input and thumbprint (`NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`)
- the RFC 9278 §6 URI
- the RFC 8037 A.3 thumbprint (`kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`) for both the A.2 public and the A.1 private Ed25519 key
- output lengths of 64 (SHA-384) and 86 (SHA-512) characters for every key

Any failed check stops the script before it writes anything.

## Cross-check (not committed)

The SHA-384 and SHA-512 values were checked once against panva/jose **6.2.15** (`calculateJwkThumbprint` and `calculateJwkThumbprintUri` with `sha256`, `sha384` and `sha512`), installed in a scratch directory outside the repository. Nothing from panva is committed (MIT, clean-room). The ten values that feature 0015's research.md §4 lists also agree; the two X25519 values are new and rest on the two oracles alone.
