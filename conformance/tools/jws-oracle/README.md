# jws-oracle

`gen.mjs` generates the vectors in [`../../vectors/jws-oracle/`](../../vectors/jws-oracle/) with `node:crypto`, an OpenSSL-backed implementation independent of polyjose. ES256K (RFC 8812) and `Ed25519` (RFC 9864) have no RFC test vectors. panva/jose has no ES256K and JOSESwift has neither, so Node is the oracle (feature 0002 research.md §3, §4).

**It is a generator only.** CI never runs it. Its output is committed, and every platform's conformance runner reads the committed files like any other vector.

## Running it

```sh
node conformance/tools/jws-oracle/gen.mjs            # writes to conformance/vectors/jws-oracle/
node conformance/tools/jws-oracle/gen.mjs <dir>      # writes somewhere else, e.g. to diff against
```

It needs Node 24 or later and nothing else: no `package.json`, no npm dependencies. Run it from outside the output directory. Each vector's `source` records the Node and OpenSSL versions that produced it.

## What it generates

| File | Operation | Reproduced on re-run |
|---|---|---|
| `ed25519-compact-sign.json` | exact compact sign, `{"alg":"Ed25519"}`, RFC 8037 A.1 key and A.4 payload | yes, byte for byte |
| `ed25519-compact-verify.json` | verify of that JWS with the A.2 public key | yes, byte for byte |
| `es256k-compact-sign-roundtrip.json` | ES256K sign, checked by round trip (`verify_with`) | yes, byte for byte |
| `es256k-compact-verify-low-s.json` | verify of an oracle ES256K signature with S ≤ n/2 | no: ECDSA is randomized |
| `es256k-compact-verify-high-s.json` | verify of its high-S twin (S → n − S), expected valid (ADR 0026 §5) | no: derived from the one above |

On the same Node and OpenSSL versions, a re-run leaves the Ed25519 files and the ES256K round-trip file unchanged. The two ES256K token files get new, equally valid signatures each time, so only commit them when you mean to regenerate them, and always commit them together: the high-S file is the twin of the low-S one.

## How the entries are built

- **Ed25519.** Before signing anything, the script checks that `node:crypto` reproduces the RFC 8037 A.4 JWS exactly. It then signs the same payload with the same key under the header `{"alg":"Ed25519"}`.
- **ES256K key.** It is fixed so that re-runs keep the same key: `d` = SHA-256(`"polyjose jws-oracle ES256K key v1"`), and `x`, `y` are derived from it by `node:crypto`. The script checks that `d` lies in [1, n − 1] and that `node:crypto` derives the same public key from the private JWK. It is a test key, used nowhere else.
- **Low-S and high-S.** OpenSSL emits either S form, so the script signs until OpenSSL itself returns a signature with S ≤ n/2. The high-S twin keeps R and replaces S with n − S, where n is the secp256k1 group order (SEC 2 §2.4.1). That is BigInt subtraction to build a vector, not a cryptographic primitive. The script checks that `node:crypto` verifies both signatures before writing them.

Any failed check stops the script before it writes anything.
