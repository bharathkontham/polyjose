# ts-common

The TypeScript shared by `@polyjose/node` and `@polyjose/wasm` (layer 4, [ARCHITECTURE.md](../../ARCHITECTURE.md)). It is the private package `@polyjose/ts-common` and is never published on its own: each npm package compiles it in.

- `src/api.ts`: `createApi(backend)`, the public facade both packages export: argument checks, JSON to objects, Promises, `PolyjoseError`.
- `src/backend.ts`: the backend contract that the napi-rs addon and the wasm-bindgen glue implement. The rules are in [BACKEND.md](BACKEND.md).
- `src/types.ts`, `src/normalize.ts`; `src/error-codes.ts` is generated from the core's `Error::CODES` by `tools/gen-error-codes.ts`.
- `node/builtins.ts`: Node built-ins used by both packages.
- `conformance/`: the one JS conformance runner, used by `bindings/node` (runner `node`) and `bindings/wasm/test-pkg` (`wasm-pkg-*`).

TypeScript only; every `.js` and `.d.ts` is tsc output. Test with `./test.sh` (also `scripts/test-all.sh node`, step `ts-common`): it builds, checks that the files in `test/misuse/` fail to type-check, and runs the compiled tests.
