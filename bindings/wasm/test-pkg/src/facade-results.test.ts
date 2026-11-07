/**
 * [WASM-pkg-node] The facade's results on the installed package after 0013 F09, which made the
 * facade read a backend result by its **own** members only (`bindings/js/BACKEND.md` "Results"):
 * a JWS verify and a JWE decrypt of the RFCs' own examples still return exactly the RFC's values,
 * with exactly the members present that the result has, and no absent optional member.
 *
 * - RFC 7515 Appendix A.1: the HS256 compact JWS, verified with the A.1 key (§A.1.2);
 * - RFC 7516 Appendix A.3: the A128KW + A128CBC-HS256 compact JWE (§A.3.7), decrypted with the
 *   A.3.3 key to "Live long and prosper." (§A.3).
 */
import * as api from "@polyjose/wasm";
import { assert, test } from "./node.js";

const JWS_A1 =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const KEY_A1 = {
  kty: "oct",
  k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
};
/** The A.1 JWS Payload, exactly as RFC 7515 §A.1.1 gives it (CRLF line breaks). */
const PAYLOAD_A1 = '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}';

const JWE_A3 =
  "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
  "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
  "AxY8DCtDaGlsbGljb3RoZQ." +
  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
  "U0m_YmjN04DJvceFICbCVQ";
const KEY_A3 = { kty: "oct", k: "GawgguFyGrWKav7AX4VKUg" };

/** A header's members as sorted `[name, value]` pairs: the core re-serializes headers, so their
 * member order is not the token's (a JSON object is unordered, RFC 8259 §4). */
function members(header: unknown): [string, unknown][] {
  assert.ok(header !== null && typeof header === "object", "a header is an object");
  return Object.entries(header as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

async function checkJws(): Promise<void> {
  const r = await api.jwsVerifyCompact(JWS_A1, KEY_A1, { allowedAlgs: ["HS256"] });
  assert.deepEqual(Object.keys(r).sort(), ["alg", "payload", "protectedHeader", "signatureIndex"]);
  assert.equal(r.alg, "HS256");
  assert.deepEqual(Array.from(r.payload), Array.from(new TextEncoder().encode(PAYLOAD_A1)));
  assert.deepEqual(members(r.protectedHeader), [["alg", "HS256"], ["typ", "JWT"]]);
  assert.equal(r.signatureIndex, 0);
  assert.ok(!Object.hasOwn(r, "unprotectedHeader"), "a compact JWS has no unprotected header (RFC 7515 §7.1)");
}

async function checkJwe(): Promise<void> {
  const r = await api.jweDecryptCompact(JWE_A3, KEY_A3, { allowedAlgs: ["A128KW"], allowedEnc: ["A128CBC-HS256"] });
  assert.deepEqual(Object.keys(r).sort(), ["header", "plaintext", "protectedHeader", "recipientIndex"]);
  assert.equal(new TextDecoder().decode(r.plaintext), "Live long and prosper.");
  assert.deepEqual(members(r.header), [["alg", "A128KW"], ["enc", "A128CBC-HS256"]]);
  assert.deepEqual(members(r.protectedHeader), [["alg", "A128KW"], ["enc", "A128CBC-HS256"]]);
  assert.equal(r.recipientIndex, 0);
  for (const name of ["sharedUnprotectedHeader", "recipientHeader", "aad"]) {
    assert.ok(!Object.hasOwn(r, name), `a compact JWE has no ${name} (RFC 7516 §7.1)`);
  }
}

await test("jwsVerifyCompact returns RFC 7515 A.1's values, with no absent member (0013 F09)", checkJws);
await test("jweDecryptCompact returns RFC 7516 A.3's values, with no absent member (0013 F09)", checkJwe);
