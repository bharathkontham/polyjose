# interop

Interop tests against other JOSE libraries. Unlike the conformance vectors, which check polyjose against fixed expected outputs, these check that tokens cross between two live implementations.

- `node/`: two-way interop of `@polyjose/node` with [panva/jose](https://github.com/panva/jose) 6.x (pinned in `node/package-lock.json`). polyjose signs or encrypts and jose verifies or decrypts, and the reverse, always with explicit algorithm allow-lists; each case also flips one bit and expects the other side to reject the token.

Test with `interop/node/test.sh` (also `scripts/test-all.sh node`, step `interop-jose`). It builds `@polyjose/node` from this tree first. TypeScript only; Node runs `interop.test.ts` directly.
