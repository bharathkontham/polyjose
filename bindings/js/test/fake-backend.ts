// A scriptable fake of the backend contract (src/backend.ts, BACKEND.md). Every call is
// recorded; an operation without a scripted handler throws a plain Error (no `code`), which the
// facade turns into a TypeError, so a test can never pass through an unscripted path silently.
import type { Backend } from "../src/backend.js";
import { ERROR_CODES } from "../src/error-codes.js";

/** Every ADR 0030 §4 operation in camelCase, copied from the ADR (not from src/). */
export const OPERATIONS = [
  "version",
  "errorCodes",
  "base64urlEncode",
  "base64urlDecode",
  "jwkParse",
  "jwkToPublic",
  "jwkThumbprint",
  "jwkThumbprintUri",
  "jwksSelect",
  "jwkGenerateOct",
  "jwkGenerateEc",
  "jwkGenerateOkp",
  "jwkGenerateForAlg",
  "jwkFromPem",
  "jwkFromDer",
  "jwkToPem",
  "jwkToDer",
  "jwsSignCompact",
  "jwsSignFlattened",
  "jwsSignGeneral",
  "jwsVerifyCompact",
  "jwsVerifyJson",
  "jweEncryptCompact",
  "jweEncryptJson",
  "jweDecryptCompact",
  "jweDecryptJson",
  "jwtSign",
  "jwtVerify",
  "jwtVerifyWithJwks",
  "jwtEncryptNested",
  "jwtDecryptNested",
  "jwtDecryptNestedWithJwks",
] as const;

export type Operation = (typeof OPERATIONS)[number];

export interface Call {
  readonly op: string;
  readonly args: readonly unknown[];
}

export type Handler = (...args: never[]) => unknown;

export interface FakeOptions {
  handlers?: Partial<Record<Operation, Handler>>;
  ready?: () => Promise<void>;
  errorCodes?: readonly string[];
}

export interface Fake {
  readonly backend: Backend;
  readonly calls: Call[];
  /** The calls of one operation. */
  of(op: Operation): Call[];
}

/** An Error like napi's and wasm-bindgen's: `code` and `message` set. */
export function coded(code: string, message: string): Error {
  const e = new Error(message) as Error & { code: string };
  e.code = code;
  return e;
}

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** RFC 4648 §5 base64url without padding (test helper; the facade never encodes itself). */
export function b64uEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    const chars = Math.min(4, Math.ceil(((bytes.length - i) * 8) / 6));
    for (let j = 0; j < chars; j++) out += ALPHABET[(n >> (18 - 6 * j)) & 63];
  }
  return out;
}

/** Strict canonical base64url decoding; throws `InvalidBase64` like the core. */
export function b64uDecode(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) throw coded("InvalidBase64", "invalid base64url");
  const bytes: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const c of text) {
    acc = (acc << 6) | ALPHABET.indexOf(c);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((acc >> bits) & 255);
    }
  }
  if ((acc & ((1 << bits) - 1)) !== 0) throw coded("InvalidBase64", "non-canonical base64url");
  return Uint8Array.from(bytes);
}

export function fakeBackend(options: FakeOptions = {}): Fake {
  const calls: Call[] = [];
  const handlers = options.handlers ?? {};
  const defaults: Partial<Record<Operation, Handler>> = {
    version: () => "0.1.0",
    errorCodes: () => [...(options.errorCodes ?? ERROR_CODES)],
    base64urlEncode: ((bytes: Uint8Array) => b64uEncode(bytes)) as Handler,
    base64urlDecode: ((text: string) => b64uDecode(text)) as Handler,
  };
  const backend: Record<string, unknown> = {};
  for (const op of OPERATIONS) {
    backend[op] = (...args: unknown[]) => {
      calls.push({ op, args });
      const handler = handlers[op] ?? defaults[op];
      if (handler === undefined) throw new Error(`fake backend: ${op} is not scripted`);
      return (handler as (...a: unknown[]) => unknown)(...args);
    };
  }
  if (options.ready !== undefined) backend["ready"] = options.ready;
  return {
    backend: backend as unknown as Backend,
    calls,
    of: (op) => calls.filter((c) => c.op === op),
  };
}
