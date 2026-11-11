# jws-oracle

`gen.mjs` generates the vectors in [`../../vectors/jws-oracle/`](../../vectors/jws-oracle/) with `node:crypto`, an OpenSSL-backed implementation independent of polyjose. ES256K (RFC 8812) and `Ed25519` (RFC 9864) have no RFC test vectors. panva/jose has no ES256K and JOSESwift has neither, so Node is the oracle (feature 0002 research.md §3, §4). RS384, RS512, PS512 and HS512 have no RFC-printed JWS either (RFC 7515 and RFC 7520 cover RS256, PS384 and HS256), so their vectors come from here too.

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
| `rs384-compact-sign.json`, `rs512-compact-sign.json` | exact compact sign with the RFC 7515 A.2 RSA private key | yes, byte for byte |
| `rs384-compact-verify.json`, `rs512-compact-verify.json` | verify of that JWS with the A.2 public key | yes, byte for byte |
| `rs{384,512}-compact-verify-tampered-signature.json` | one signature bit flipped: `InvalidSignature` | yes, byte for byte |
| `rs{384,512}-compact-verify-wrong-key.json` | verified with the RFC 7520 §3.4 RSA public key: `InvalidSignature` | yes, byte for byte |
| `rs{384,512}-compact-verify-alg-not-allowed.json` | the allow-list names only the other RS\* alg: `AlgorithmNotAllowed` | yes, byte for byte |
| `rs{384,512}-compact-verify-ec-key.json` | verified with the RFC 7515 A.3 P-256 public key: `KeyAlgorithmMismatch` | yes, byte for byte |
| `rs384-compact-verify-sha512-signature.json`, `rs512-compact-verify-sha384-signature.json` | the header names one RS\* alg, the signature uses the other's hash: `InvalidSignature` | yes, byte for byte |
| `ps512-compact-sign-roundtrip.json` | PS512 sign with the A.2 private key, checked by round trip (`verify_with`) | yes, byte for byte |
| `ps512-compact-verify.json` | verify of an oracle PS512 signature | no: RSASSA-PSS is salted |
| `ps512-compact-verify-tampered-signature.json` | that signature with one bit flipped: `InvalidSignature` | no: derived from the one above |
| `hs512-compact-sign.json`, `hs512-compact-verify.json` | exact compact sign and verify with a fixed 64-octet key | yes, byte for byte |
| `hs512-compact-verify-tampered-signature.json` | one MAC bit flipped: `InvalidSignature` | yes, byte for byte |

On the same Node and OpenSSL versions, a re-run leaves every file marked "yes" unchanged. The two ES256K token files and the two PS512 token files get new, equally valid signatures each time, so only commit them when you mean to regenerate them, and always commit each pair together: the second file is derived from the first. To add vectors without touching those, write to another directory and copy the new files.

## How the entries are built

- **Ed25519.** Before signing anything, the script checks that `node:crypto` reproduces the RFC 8037 A.4 JWS exactly. It then signs the same payload with the same key under the header `{"alg":"Ed25519"}`.
- **ES256K key.** It is fixed so that re-runs keep the same key: `d` = SHA-256(`"polyjose jws-oracle ES256K key v1"`), and `x`, `y` are derived from it by `node:crypto`. The script checks that `d` lies in [1, n − 1] and that `node:crypto` derives the same public key from the private JWK. It is a test key, used nowhere else.
- **Low-S and high-S.** OpenSSL emits either S form, so the script signs until OpenSSL itself returns a signature with S ≤ n/2. The high-S twin keeps R and replaces S with n − S, where n is the secp256k1 group order (SEC 2 §2.4.1). That is BigInt subtraction to build a vector, not a cryptographic primitive. The script checks that `node:crypto` verifies both signatures before writing them.

- **RSA keys.** None is generated. The script reads them from committed RFC vectors: the RFC 7515 A.2 key pair (`jws-rfc7515/a2-rs256-compact-sign.json`) signs and verifies, the RFC 7520 §3.4 public key is the wrong key, and the RFC 7515 A.3 P-256 public key is the key of another family. Before signing, it checks that `node:crypto` reproduces the RFC 7515 A.2 JWS exactly.
- **RS384 and RS512.** RSASSA-PKCS1-v1_5 is deterministic, so the sign vectors expect the exact JWS. The script checks with `node:crypto` that each signature verifies, that the tampered one and the wrong key do not, and that a signature made with the other hash verifies under its own hash and not under the one the header names.
- **PS512.** SHA-512, MGF1 with SHA-512 and a 64-octet salt (RFC 7518 §3.5). The script checks that `node:crypto` verifies the signature and refuses the tampered one.
- **HS512 key.** `k` = SHA-512(`"polyjose jws-oracle HS512 key v1"`), 64 octets. The script first checks that `node:crypto` reproduces the RFC 7515 A.1 JWS. It is a test key, used nowhere else.

Any failed check stops the script before it writes anything.
