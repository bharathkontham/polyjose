// Type-level usage of the facade (ADR 0047). Checked by `tsc` (`npx tsc --noEmit -p bindings/js`),
// never executed: `usage` is not called. Each `@ts-expect-error` line must fail to type-check,
// or tsc reports the directive as unused, so misuse is proven to be rejected.
import { createApi, PolyjoseError, ERROR_CODES } from "../src/api.js";
import type {
  Backend,
  ErrorCode,
  JweDecrypted,
  JwkObject,
  JwsVerified,
  JwsVerifyOptions,
  JwtNestedVerified,
  JwtVerified,
  JwtVerifyOptions,
  PolyjoseApi,
} from "../src/api.js";

declare const backend: Backend;
declare const bytes: Uint8Array;

export async function usage(): Promise<void> {
  const api: PolyjoseApi = createApi(backend);
  const jwk: JwkObject = await api.jwkParse({ kty: "oct", k: "AAAA" });
  await api.jwkParse('{"kty":"oct","k":"AAAA"}');
  const tp: string = await api.jwkThumbprint(jwk, "SHA-256");
  void tp;
  // The hash is optional (absent = the core default, SHA-256) and takes the nine names of
  // ADR 0054 §8.2.
  await api.jwkThumbprint(jwk);
  await api.jwkThumbprintUri(jwk, undefined);
  for (const hash of ["sha-256", "SHA-256", "sha256", "sha-384", "SHA-384", "sha384", "sha-512", "SHA-512", "sha512"] as const) {
    await api.jwkThumbprint(jwk, hash);
    await api.jwkThumbprintUri(jwk, hash);
  }
  const ambiguous: ErrorCode = "MultipleMatchingKeys";
  void ambiguous;

  const verified: JwsVerified = await api.jwsVerifyCompact("a.b.c", jwk, { allowedAlgs: ["ES256"] });
  const payload: Uint8Array = verified.payload;
  void payload;
  await api.jwsVerifyJson({ payload: "", signature: "" }, jwk, { allowedAlgs: ["ES256"], maxSignatures: 2 });
  // Optional fields accept an explicit undefined (exactOptionalPropertyTypes callers).
  const maybe: number | undefined = undefined;
  const opts: JwsVerifyOptions = { allowedAlgs: ["ES256"], maxInputLen: maybe };
  await api.jwsVerifyCompact("a.b.c", jwk, opts);

  // @ts-expect-error allowedAlgs is required (ADR 0007): a verify without it does not compile.
  await api.jwsVerifyCompact("a.b.c", jwk, {});
  // @ts-expect-error the options record itself is required.
  await api.jwsVerifyCompact("a.b.c", jwk);
  // @ts-expect-error allowedEnc is required too.
  await api.jweDecryptCompact("a.b.c.d.e", jwk, { allowedAlgs: ["dir"] });
  // @ts-expect-error a JWT verify needs allowedAlgs.
  await api.jwtVerify("a.b.c", jwk, { now: 0 });
  // @ts-expect-error the nested inner verify needs allowedAlgs.
  await api.jwtDecryptNested("t", jwk, { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] }, jwk, {});
  // @ts-expect-error SHA-1 thumbprints are not offered (ADR 0022).
  await api.jwkThumbprint(jwk, "SHA-1");
  // @ts-expect-error names are exact (ADR 0054 §8.2): no other case forms.
  await api.jwkThumbprintUri(jwk, "Sha-256");
  // @ts-expect-error not a polyjose error code.
  const notACode: ErrorCode = "MultipleKeys";
  void notACode;
  // @ts-expect-error allowedAlgs is a list, not a single name.
  await api.jwsVerifyCompact("a.b.c", jwk, { allowedAlgs: "ES256" });
  // @ts-expect-error a misspelled member is rejected (issuers, not issuer).
  await api.jwtVerify("a.b.c", jwk, { allowedAlgs: ["ES256"], issuer: "joe" });
  // The one profile is RFC 9068 §4's "access_token" (review N5): the name type-checks ...
  await api.jwtVerify("a.b.c", jwk, { allowedAlgs: ["ES256"], issuers: ["joe"], audiences: ["api"], profile: "access_token" });
  // @ts-expect-error ... and a typo of it does not compile.
  await api.jwtVerify("a.b.c", jwk, { allowedAlgs: ["ES256"], profile: "access-token" });
  // @ts-expect-error nor does another profile name (the core would answer UnsupportedAlgorithm).
  await api.jwtVerifyWithJwks("a.b.c", { keys: [] }, { allowedAlgs: ["ES256"], profile: "id_token" });
  // @ts-expect-error bytes are Uint8Array, not a string.
  await api.base64urlEncode("AQI");

  const decrypted: JweDecrypted = await api.jweDecryptJson("{}", jwk, { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] });
  void decrypted.plaintext;
  const v: JwtVerifyOptions = { allowedAlgs: ["ES256"], issuers: ["joe"], leeway: 30 };
  const jwt: JwtVerified = await api.jwtVerifyWithJwks("a.b.c", { keys: [] }, v);
  const index: number | undefined = jwt.keyIndex;
  void index;
  const nested: JwtNestedVerified = await api.jwtDecryptNestedWithJwks("t", jwk, { allowedAlgs: ["dir"], allowedEnc: ["A128GCM"] }, "{}", v);
  void nested.inner.claims;
  await api.jwtSign({ sub: "x" }, jwk, { alg: "ES256", typ: "at+jwt" });
  await api.jweEncryptJson(bytes, { enc: "A128GCM", recipients: [{ alg: "dir", key: jwk }] }, "general");

  try {
    await api.jwkParse("{}");
  } catch (e) {
    if (e instanceof PolyjoseError) {
      const code: ErrorCode = e.code;
      // @ts-expect-error a code outside Error::CODES is not an ErrorCode.
      const bogus: ErrorCode = "NotACode";
      void code;
      void bogus;
    }
  }
  const first: ErrorCode = ERROR_CODES[0];
  void first;
}
