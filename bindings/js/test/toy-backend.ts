// A toy backend for the runner tests: a self-consistent fake "JOSE" in which every signature is
// the literal "sig" and ciphertexts are ids into a table. It knows exactly enough to give the
// fixture vectors under test/fixtures/vectors their expected outcomes, so the runner's mapping,
// round trips and comparisons are exercised end to end. Nothing here is cryptography.
import { b64uDecode, b64uEncode, coded, fakeBackend, type Fake, type Handler, type Operation } from "./fake-backend.js";

const ascii = (b: Uint8Array): string => String.fromCharCode(...b);
const bytesOf = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0));
const enc = (s: string): string => b64uEncode(bytesOf(s));
const dec = (s: string): string => ascii(b64uDecode(s));

type Obj = Record<string, unknown>;

function jwkImport(text: string): Obj {
  const jwk = JSON.parse(text) as Obj;
  if (typeof jwk["kty"] !== "string") throw coded("InvalidKey", "no kty");
  if (jwk["kty"] === "RSA" && "d" in jwk) throw coded("UnsupportedAlgorithm", "RSA private keys are not supported");
  return jwk;
}

function allowed(list: readonly string[], name: unknown): void {
  if (list.length === 0 || typeof name !== "string" || !list.includes(name)) throw coded("AlgorithmNotAllowed", "not allowed");
}

const OKP = '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}';

export function toyBackend(overrides: Partial<Record<Operation, Handler>> = {}): Fake {
  const ciphertexts = new Map<string, Uint8Array>([["ct-fixture", bytesOf("fixture")]]);
  const nested = new Map<string, string>([
    ["nested-fixture", `${enc('{"alg":"HS256","typ":"at+jwt"}')}.${enc('{"iss":"joe","exp":1300819380}')}.sig`],
  ]);
  let next = 0;

  const verifyJwt = (token: string, options: { allowedAlgs: string[]; now: number }) => {
    allowed(options.allowedAlgs, "HS256");
    const parts = token.split(".");
    if (parts.length !== 3) throw coded("InvalidFormat", "not three parts");
    const header = dec(parts[0] ?? "");
    const alg = (JSON.parse(header) as Obj)["alg"];
    allowed(options.allowedAlgs, alg);
    if (parts[2] !== "sig") throw coded("InvalidSignature", "bad signature");
    const claims = dec(parts[1] ?? "");
    const exp = (JSON.parse(claims) as Obj)["exp"];
    if (typeof exp === "number" && exp < options.now) throw coded("TokenExpired", "expired");
    return { claims, header, alg: alg as string };
  };

  const handlers: Partial<Record<Operation, Handler>> = {
    jwkParse: ((t: string) => JSON.stringify(jwkImport(t))) as Handler,
    jwkThumbprint: ((t: string, h: string) => {
      const kty = jwkImport(t)["kty"] as string;
      if (h !== "SHA-256") throw coded("UnsupportedAlgorithm", "hash");
      return `tp-${kty}`;
    }) as Handler,
    jwkThumbprintUri: ((t: string) => `urn:ietf:params:oauth:jwk-thumbprint:sha-256:tp-${jwkImport(t)["kty"] as string}`) as Handler,
    jwkFromPem: ((pem: string) => {
      if (!pem.includes("PUBLIC KEY")) throw coded("InvalidKey", "pem");
      return OKP;
    }) as Handler,
    jwkFromDer: ((_der: Uint8Array, format: string) => {
      if (format !== "spki") throw coded("InvalidKey", "der");
      return OKP;
    }) as Handler,
    jwkToDer: ((t: string, format: string) => {
      if (jwkImport(t)["kty"] === "oct" || format !== "spki") throw coded("UnsupportedAlgorithm", "format");
      return Uint8Array.from([0x30, 0x2a]);
    }) as Handler,
    jwkToPem: ((t: string) => {
      if (jwkImport(t)["kty"] === "oct") throw coded("UnsupportedAlgorithm", "oct has no PEM");
      return "-----BEGIN PUBLIC KEY-----\nMCo\n-----END PUBLIC KEY-----\n";
    }) as Handler,
    jwkToPublic: ((t: string) => {
      const jwk = jwkImport(t);
      delete jwk["d"];
      return JSON.stringify(jwk);
    }) as Handler,
    // Toy keys of the RFC shapes (RFC 7518 §6.2, §6.4.1; RFC 8037 §2), no alg; the core's oct bound is 16-512 octets.
    jwkGenerateOct: ((n: number) => {
      if (n < 16 || n > 512) throw coded("InvalidKey", "length");
      return JSON.stringify({ kty: "oct", k: enc("k".repeat(n)) });
    }) as Handler,
    jwkGenerateEc: ((crv: string) => JSON.stringify({ kty: "EC", crv, x: "eA", y: "eQ", d: "ZA" })) as Handler,
    jwkGenerateOkp: ((crv: string) => JSON.stringify({ kty: "OKP", crv, x: "eA", d: "ZA" })) as Handler,
    jwkGenerateForAlg: ((alg: string) => {
      if (alg === "A128KW") return JSON.stringify({ kty: "oct", k: enc("0123456789abcdef"), alg });
      if (alg.startsWith("ECDH-ES")) throw coded("InvalidKey", "needs a curve");
      throw coded("UnsupportedAlgorithm", "unknown");
    }) as Handler,

    jwsSignCompact: ((p: Uint8Array, key: string, o: { protectedHeader?: string; protectedB64u?: string; detached?: boolean }) => {
      jwkImport(key);
      const header = o.protectedB64u ?? (o.protectedHeader === undefined ? "" : enc(o.protectedHeader));
      return `${header}.${o.detached === true ? "" : b64uEncode(p)}.sig`;
    }) as Handler,
    jwsSignFlattened: ((p: Uint8Array, s: Obj, detached: boolean) => {
      jwkImport(s["key"] as string);
      const out: Obj = { signature: "sig" };
      if (s["protectedB64u"] !== undefined) out["protected"] = s["protectedB64u"];
      if (s["unprotectedHeader"] !== undefined) out["header"] = JSON.parse(s["unprotectedHeader"] as string);
      if (!detached) out["payload"] = b64uEncode(p);
      return JSON.stringify(out);
    }) as Handler,
    jwsSignGeneral: ((p: Uint8Array, signers: Obj[], detached: boolean) => {
      const signatures = signers.map((s) => {
        jwkImport(s["key"] as string);
        const one: Obj = {};
        if (s["protectedB64u"] !== undefined) one["protected"] = s["protectedB64u"];
        if (s["unprotectedHeader"] !== undefined) one["header"] = JSON.parse(s["unprotectedHeader"] as string);
        if (one["protected"] === undefined && one["header"] === undefined) throw coded("InvalidHeader", "no alg");
        one["signature"] = "sig";
        return one;
      });
      return JSON.stringify(detached ? { signatures } : { payload: b64uEncode(p), signatures });
    }) as Handler,
    jwsVerifyCompact: ((token: string, key: string, o: { allowedAlgs: string[]; detachedPayload?: Uint8Array }) => {
      jwkImport(key);
      allowed(o.allowedAlgs, o.allowedAlgs[0]);
      const [h = "", p = "", s] = token.split(".");
      const header = dec(h);
      const alg = (JSON.parse(header) as Obj)["alg"];
      allowed(o.allowedAlgs, alg);
      if (s !== "sig") throw coded("InvalidSignature", "bad signature");
      return { alg, payload: o.detachedPayload ?? b64uDecode(p), protectedHeader: header, signatureIndex: 0 };
    }) as Handler,
    jwsVerifyJson: ((text: string, key: string, o: { allowedAlgs: string[]; detachedPayload?: Uint8Array }) => {
      jwkImport(key);
      const jws = JSON.parse(text) as Obj;
      const sigs = (jws["signatures"] as Obj[] | undefined) ?? [jws];
      for (let i = 0; i < sigs.length; i++) {
        const s = sigs[i] ?? {};
        const header = typeof s["protected"] === "string" ? (JSON.parse(dec(s["protected"])) as Obj) : ((s["header"] as Obj | undefined) ?? {});
        if (s["signature"] === "sig" && o.allowedAlgs.includes(header["alg"] as string)) {
          const payload = o.detachedPayload ?? b64uDecode((jws["payload"] as string | undefined) ?? "");
          return { alg: header["alg"], payload, signatureIndex: i };
        }
      }
      throw coded("InvalidSignature", "no signature verifies");
    }) as Handler,

    jweEncryptCompact: ((p: Uint8Array, o: { recipients: Obj[] }) => {
      if (o.recipients.length !== 1) throw coded("InvalidFormat", "one recipient");
      jwkImport(o.recipients[0]?.["key"] as string);
      const id = `ct${next++}`;
      ciphertexts.set(id, p);
      return `h.k.iv.${id}.tag`;
    }) as Handler,
    jweEncryptJson: ((p: Uint8Array, o: { recipients: Obj[] }, form: string) => {
      for (const r of o.recipients) jwkImport(r["key"] as string);
      const id = `ct${next++}`;
      ciphertexts.set(id, p);
      return JSON.stringify(form === "general" ? { recipients: o.recipients.map(() => ({ encrypted_key: "k" })), ciphertext: id } : { encrypted_key: "k", ciphertext: id });
    }) as Handler,
    jweDecryptCompact: ((token: string, key: string, o: { allowedAlgs: string[]; allowedEnc: string[] }) => {
      jwkImport(key);
      allowed(o.allowedAlgs, o.allowedAlgs[0]);
      allowed(o.allowedEnc, o.allowedEnc[0]);
      const plaintext = ciphertexts.get(token.split(".")[3] ?? "");
      if (plaintext === undefined) throw coded("DecryptionFailed", "decryption failed");
      return { plaintext, header: '{"alg":"A128KW","enc":"A128GCM"}', protectedHeader: '{"alg":"A128KW","enc":"A128GCM"}', recipientIndex: 0 };
    }) as Handler,
    jweDecryptJson: ((text: string, key: string, o: { allowedAlgs: string[]; allowedEnc: string[] }) => {
      jwkImport(key);
      allowed(o.allowedAlgs, o.allowedAlgs[0]);
      allowed(o.allowedEnc, o.allowedEnc[0]);
      const plaintext = ciphertexts.get((JSON.parse(text) as Obj)["ciphertext"] as string);
      if (plaintext === undefined) throw coded("DecryptionFailed", "decryption failed");
      return { plaintext, header: '{"alg":"A128KW","enc":"A128GCM"}', recipientIndex: 0 };
    }) as Handler,

    jwtSign: ((claims: string, key: string, o: { alg: string; typ?: string; omitTyp?: boolean }) => {
      jwkImport(key);
      if (o.alg === "none") throw coded("AlgorithmNotAllowed", "none");
      const header = o.omitTyp === true ? { alg: o.alg } : { alg: o.alg, typ: o.typ ?? "JWT" };
      return `${enc(JSON.stringify(header))}.${enc(claims)}.sig`;
    }) as Handler,
    jwtVerify: ((token: string, key: string, o: { allowedAlgs: string[]; now: number }) => {
      jwkImport(key);
      return verifyJwt(token, o);
    }) as Handler,
    jwtVerifyWithJwks: ((token: string, jwks: string, o: { allowedAlgs: string[]; now: number }) => {
      const keys = (JSON.parse(jwks) as Obj)["keys"];
      if (!Array.isArray(keys)) throw coded("InvalidKey", "no keys");
      const verified = verifyJwt(token, o);
      const kid = (JSON.parse(verified.header) as Obj)["kid"];
      const keyIndex = keys.findIndex((k) => (k as Obj)["kid"] === kid);
      if (keyIndex < 0) throw coded("NoMatchingKey", "no key");
      return { ...verified, keyIndex, kid };
    }) as Handler,
    jwtEncryptNested: ((jwt: string, o: { recipients: Obj[] }) => {
      jwkImport(o.recipients[0]?.["key"] as string);
      const id = `nested${next++}`;
      nested.set(id, jwt);
      return `h.k.iv.${id}.tag`;
    }) as Handler,
    jwtDecryptNested: ((token: string, dk: string, d: { allowedAlgs: string[] }, key: string, v: { allowedAlgs: string[]; now: number }) => {
      jwkImport(dk);
      jwkImport(key);
      allowed(d.allowedAlgs, d.allowedAlgs[0]);
      const inner = nested.get(token.split(".")[3] ?? "");
      if (inner === undefined) throw coded("DecryptionFailed", "decryption failed");
      return { inner: verifyJwt(inner, v), outerHeader: '{"alg":"dir","enc":"A128GCM","cty":"JWT"}', recipientIndex: 0 };
    }) as Handler,
    ...overrides,
  };
  return fakeBackend({ handlers });
}
