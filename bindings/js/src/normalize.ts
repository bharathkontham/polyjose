/**
 * Input and output normalisation of the facade: idiom only (ADR 0030 §1 host facade row, §2;
 * ADR 0031 §1). No policy, no defaults, no JOSE validation: the core decides all of that.
 *
 * Every failure here is a host `TypeError`, never a `PolyjoseError` (ADR 0030 E2: host type
 * errors stay outside the code contract). A message names the argument and the expected type,
 * never the value, which may be key material (ADR 0030 §5, "no input in errors").
 */

import type { JsonObject } from "./types.js";

/** `null` and `undefined` both mean "absent" (napi throws on `null`, research §3). */
export function isAbsent(v: unknown): v is null | undefined {
  return v === undefined || v === null;
}

function fail(at: string, expected: string): TypeError {
  return new TypeError(`polyjose: ${at} must be ${expected}`);
}

/**
 * `%TypedArray%.prototype[Symbol.toStringTag]` reads the internal [[TypedArrayName]] slot, so
 * it can't be spoofed by an object's own `Symbol.toStringTag`, and it works across realms.
 */
const typedArrayName = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype) as object, Symbol.toStringTag)?.get;

/** A `Uint8Array`, including a Node `Buffer` (a subclass). */
export function isUint8Array(v: unknown): v is Uint8Array {
  return ArrayBuffer.isView(v) && typedArrayName?.call(v) === "Uint8Array";
}

/** An object literal (or `Object.create(null)`), not an array or class instance. */
export function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

export function str(v: unknown, at: string): string {
  if (typeof v !== "string") throw fail(at, "a string");
  return v;
}

export function optStr(v: unknown, at: string): string | undefined {
  return isAbsent(v) ? undefined : str(v, at);
}

/**
 * A byte input, as a fresh copy (ADR 0030 §7; 0013 B06). The facade calls this synchronously,
 * when the operation is called and before it awaits the backend's lazy `ready()` (ADR 0031 §3),
 * so a caller that reuses its array after starting a call can't change what is signed or
 * encrypted. The copy is a plain `Uint8Array` holding exactly the view's bytes (a `Buffer` or a
 * subarray shares no memory with it) and is pushed onto `copies`, which the facade wipes once the
 * backend call settles; the caller's own array is never wiped. A view over a detached buffer
 * can't be copied and is a TypeError.
 */
export function bytes(v: unknown, at: string, copies: Uint8Array[]): Uint8Array {
  if (!isUint8Array(v)) throw fail(at, "a Uint8Array");
  let copy: Uint8Array;
  try {
    // The TypedArray constructor reads the internal slots, not `length` or an iterator.
    copy = new Uint8Array(v);
  } catch {
    throw fail(at, "a Uint8Array over an attached ArrayBuffer");
  }
  copies.push(copy);
  return copy;
}

export function optBytes(v: unknown, at: string, copies: Uint8Array[]): Uint8Array | undefined {
  return isAbsent(v) ? undefined : bytes(v, at, copies);
}

/**
 * Wipes the copies {@link bytes} made with `fill(0)` (ADR 0030 §7). JS gives no guarantee that
 * the engine kept no other copy (ADR 0030 §7 rule 4); this removes the facade's own.
 */
export function wipe(copies: readonly Uint8Array[]): void {
  for (const copy of copies) copy.fill(0);
}

export function bool(v: unknown, at: string): boolean {
  if (typeof v !== "boolean") throw fail(at, "a boolean");
  return v;
}

export function optBool(v: unknown, at: string): boolean | undefined {
  return isAbsent(v) ? undefined : bool(v, at);
}

/** The largest `u32`: sizes and counts are `u32` in the surface (ADR 0030 §2). */
const U32_MAX = 0xffff_ffff;

/**
 * A size or count: an integer in 0..=2^32−1. Checked here because wasm-bindgen would coerce
 * `-1` to `4294967295` (research §3).
 */
export function u32(v: unknown, at: string): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > U32_MAX) {
    throw fail(at, "an integer from 0 to 4294967295");
  }
  return v;
}

export function optU32(v: unknown, at: string): number | undefined {
  return isAbsent(v) ? undefined : u32(v, at);
}

/**
 * Whole seconds since the epoch (RFC 7519 §2), a safe integer: the NumericDate and clock range
 * ±(2^53 − 1) of ADR 0027 §2 and ADR 0028 §1, which a JS number holds exactly.
 */
export function optSeconds(v: unknown, at: string): number | undefined {
  if (isAbsent(v)) return undefined;
  if (typeof v !== "number" || !Number.isSafeInteger(v)) throw fail(at, "a safe integer (whole seconds)");
  return v;
}

/**
 * JSON text: a string is passed through unchanged (so member order and number spelling reach
 * the core's strict parser as written), a plain object is `JSON.stringify`'d (ADR 0030 §2).
 */
export function json(v: unknown, at: string): string {
  if (typeof v === "string") return v;
  if (!isPlainObject(v)) throw fail(at, "JSON text or a plain object");
  let text: string;
  try {
    text = JSON.stringify(v);
  } catch {
    // A cycle or a BigInt. The engine's message may quote the input, so it is not reused.
    throw fail(at, "a JSON-serializable plain object");
  }
  return text;
}

export function optJson(v: unknown, at: string): string | undefined {
  return isAbsent(v) ? undefined : json(v, at);
}

/**
 * A list, item by item, copied. Only the array's own elements below its `length` are read: a
 * hole is a TypeError naming its index, never read through `Array.prototype`, where a pollution
 * bug elsewhere in the host app could have put a value (0013 F04, security audit M1).
 */
export function list<T>(v: unknown, at: string, item: (x: unknown, at: string) => T): T[] {
  if (!Array.isArray(v)) throw fail(at, "an array");
  const n = v.length;
  const out: T[] = [];
  for (let i = 0; i < n; i++) {
    if (!Object.hasOwn(v, i)) throw fail(`${at}[${i}]`, "present: an array without holes");
    out.push(item(v[i], `${at}[${i}]`));
  }
  return out;
}

export function strList(v: unknown, at: string): string[] {
  return list(v, at, str);
}

export function optStrList(v: unknown, at: string): string[] | undefined {
  return isAbsent(v) ? undefined : strList(v, at);
}

/**
 * An allow-list (`allowedAlgs`, `allowedEnc`). Absent is passed as `[]`, which the core refuses
 * with `AlgorithmNotAllowed`, the code an empty or `none`-only list gets on every platform
 * (ADR 0030 §3). This is not a default list: it can never accept anything.
 */
export function allowList(v: unknown, at: string): string[] {
  return isAbsent(v) ? [] : strList(v, at);
}

/**
 * A record with no prototype, holding only `init`'s own members. Every record the facade hands
 * the backend is one, so a backend that reads a member by name or tests it with `in` sees only
 * what the facade put there, never an inherited member of a polluted `Object.prototype`
 * (0013 F04, security audit M1; ADR 0030 §3: an absent member is the core default).
 */
export function bare<T extends object>(init: T): T {
  return Object.assign(Object.create(null) as T, init);
}

/**
 * A record argument: a plain object whose own enumerable members are all among `members`.
 * Absent means no members. An unknown member is a TypeError, so a misspelling (`issuer` for
 * `issuers`) can never silently drop a check. The message lists the accepted members, not the
 * unknown one.
 *
 * Returns a {@link bare} copy of the caller's own enumerable members, each read exactly once, and
 * the facade reads options only from that copy (0013 F04, review S2, security audit M1). An
 * inherited member, such as `Object.prototype.ignoreAudience = true` set by a pollution bug
 * elsewhere in the host app, is never read, so it can't loosen policy, lift a limit, stand in
 * for a missing required member or inject a header: ADR 0030 §3 makes an absent option the core
 * default, and the host's global state must not write one either. A non-enumerable own member is
 * not read either, and reading once means a getter can't pass the type check with one value and
 * reach the backend with another.
 */
export function record(v: unknown, at: string, members: readonly string[]): Record<string, unknown> {
  const out = bare<Record<string, unknown>>({});
  if (isAbsent(v)) return out;
  if (!isPlainObject(v)) throw fail(at, "a plain object");
  for (const key of Object.keys(v)) {
    if (!members.includes(key)) throw fail(at, `an object with only the members ${members.join(", ")}`);
    out[key] = v[key];
  }
  return out;
}

/** Sets `out[key]` only when `value` is present, so absent optional fields are left out. */
export function put<T extends object, K extends keyof T>(out: T, key: K, value: T[K] | undefined): void {
  if (value !== undefined) out[key] = value;
}

// --- outputs (what the backend returned) -------------------------------------------------

function badResult(at: string, expected: string): TypeError {
  return new TypeError(`polyjose: the backend returned ${at} that is not ${expected}`);
}

export function outStr(v: unknown, at: string): string {
  if (typeof v !== "string") throw badResult(at, "a string");
  return v;
}

export function outBytes(v: unknown, at: string): Uint8Array {
  if (!isUint8Array(v)) throw badResult(at, "a Uint8Array");
  return v;
}

export function outIndex(v: unknown, at: string): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > U32_MAX) throw badResult(at, "an index");
  return v;
}

/** JSON text the core serialized, parsed to an object (ADR 0030 §2: JWKs, headers, claims). */
export function outObject(v: unknown, at: string): JsonObject {
  let parsed: unknown;
  try {
    parsed = JSON.parse(outStr(v, at));
  } catch (e) {
    if (e instanceof TypeError) throw e;
    throw badResult(at, "JSON text");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw badResult(at, "a JSON object");
  return parsed as JsonObject;
}

/** The backend's results are plain objects; this reads one member. */
export function member(v: unknown, name: string, at: string): unknown {
  if (typeof v !== "object" || v === null) throw badResult(at, "an object");
  return (v as Record<string, unknown>)[name];
}
