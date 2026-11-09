// The package-entry pattern (BACKEND.md) and the generated declarations (ADR 0047).
import { assert, fs, path, process, test } from "../node/builtins.js";
import * as entry from "./fake-entry.js";
import { ERROR_CODES, PolyjoseError } from "../src/api.js";
import { OPERATIONS } from "./fake-backend.js";

test("an entry that destructures createApi exports every operation, PolyjoseError and ERROR_CODES", async () => {
  assert.deepEqual(Object.keys(entry).sort(), [...OPERATIONS, "ERROR_CODES", "PolyjoseError"].sort());
  assert.equal(entry.PolyjoseError, PolyjoseError);
  assert.equal(entry.ERROR_CODES, ERROR_CODES);
  assert.equal(await entry.version(), "0.1.2");
  assert.equal(entry.jwsVerifyCompact.name, "jwsVerifyCompact");
});

const dist = (file: string): string => fs.readFileSync(path.resolve(process.cwd(), "dist/src", file), "utf8");

test("the declarations are tsc output with declaration maps", () => {
  const api = dist("api.d.ts");
  assert.match(api, /\/\/# sourceMappingURL=api\.d\.ts\.map/);
  assert.match(api, /export declare function createApi\(backend: Backend\): PolyjoseApi;/);
  assert.match(api, /export declare class PolyjoseError extends Error/);
  assert.match(dist("error-codes.d.ts"), /export type ErrorCode = \(typeof ERROR_CODES\)\[number\];/);
});

test("the declared records keep allowedAlgs and allowedEnc required, tunables optional", () => {
  const types = dist("types.d.ts");
  for (const record of ["JwsVerifyOptions", "JweDecryptOptions", "JwtVerifyOptions"]) {
    const body = new RegExp(`export interface ${record} \\{([\\s\\S]*?)\\n\\}`).exec(types)?.[1];
    assert.ok(body !== undefined, record);
    assert.match(body, /\n\s+allowedAlgs: readonly string\[\];/, `${record}.allowedAlgs is required`);
    assert.match(body, /\n\s+maxInputLen\?: number \| undefined;/, `${record}.maxInputLen is optional`);
  }
  assert.match(types, /\n\s+allowedEnc: readonly string\[\];/);
  assert.match(types, /export type Jwk = string \| JwkObject;/);
});
