// Prototype traps for the write-side pollution tests (0013 F13, security audit M1 follow-up).
//
// A prototype-pollution bug elsewhere in the host app can put a member on `Object.prototype` (or
// `Array.prototype`). An ordinary assignment `out[key] = value` (ECMA-262 OrdinarySet) to an
// object that doesn't own `key` then consults that prototype member: an accessor's setter runs and
// receives the value (and the object gets no own member), and a non-writable data member makes the
// write fail (a TypeError in strict code). `Array.prototype.push` is such an assignment for the
// next index. The facade must create every member it hands out as an own data property instead.
//
// `plant` installs, for a list of members, either kind of trap:
// - "accessor": a getter returning `polluted(member)` and a setter that records the write and its
//   site, and stores nothing (so a value the facade wrote this way is lost, as in a real attack);
// - "readonly": a non-writable, non-enumerable data member holding `polluted(member)`.
// Every trap is configurable and removed by `remove()`, which the tests call in `finally`.
import { assert } from "../node/builtins.js";

export type TrapKind = "accessor" | "readonly";

export const TRAP_KINDS: readonly TrapKind[] = ["accessor", "readonly"];

/** One write a setter trap saw. */
export interface TrapWrite {
  readonly member: PropertyKey;
  readonly value: unknown;
  /** The file (URL) of the nearest JS frame that made the write, or "" if none is visible. */
  readonly site: string;
}

export interface Planted {
  /** Every write a setter trap saw, in order. */
  readonly writes: TrapWrite[];
  /** The writes made by the facade (`dist/src/`) or the conformance runner (`dist/conformance/`). */
  ours(): TrapWrite[];
  /** Removes every trap. */
  remove(): void;
}

/**
 * A property descriptor with no prototype: `Object.defineProperty` reads `get`, `set`, `value`,
 * ... through the descriptor's prototype chain (ECMA-262 ToPropertyDescriptor), and a trap planted
 * earlier may sit on `Object.prototype` under one of those names.
 */
function desc(d: PropertyDescriptor): PropertyDescriptor {
  return Object.assign(Object.create(null) as PropertyDescriptor, d);
}

/** This module's compiled file: its frames (this function, the setter) are skipped. */
const SELF = /\/dist\/test\/traps\.js$/;

/**
 * The file of the code that assigned: the first `file:` frame below this module's own frames.
 * Native frames (`Array.push (<anonymous>)`) have no file, so a `push` is attributed to its
 * caller. A write by other code (the test, a fake backend, a Node internal) has another site and
 * is not one of {@link Planted.ours}.
 */
function writeSite(): string {
  const stack = new Error().stack ?? "";
  for (const line of stack.split("\n").slice(1)) {
    const m = /(file:\/\/[^\s)]+?):\d+:\d+\)?\s*$/.exec(line);
    if (m === null) continue;
    const file = m[1] ?? "";
    if (!SELF.test(file)) return file;
  }
  return "";
}

function isOurs(site: string): boolean {
  return /\/dist\/(src|conformance)\//.test(site);
}

/** Plants a trap of `kind` on `target` for each member; none may already be an own member. */
export function plant(target: object, members: readonly PropertyKey[], kind: TrapKind, polluted: (member: PropertyKey) => unknown): Planted {
  const writes: TrapWrite[] = [];
  const planted: PropertyKey[] = [];
  const remove = (): void => {
    for (const m of planted) delete (target as Record<PropertyKey, unknown>)[m];
    planted.length = 0;
  };
  try {
    for (const member of new Set(members)) {
      assert.ok(!Object.hasOwn(target, member), `${String(member)} is not already on the prototype`);
      const value = polluted(member);
      const descriptor = desc(
        kind === "accessor"
          ? {
              get: () => value,
              set: (v: unknown) => {
                // Recorded with a fixed index, never push: this setter may be an `Array.prototype` index trap.
                Object.defineProperty(
                  writes,
                  writes.length,
                  desc({ value: { member, value: v, site: writeSite() }, enumerable: true, writable: true, configurable: true }),
                );
              },
              enumerable: false,
              configurable: true,
            }
          : { value, writable: false, enumerable: false, configurable: true },
      );
      Object.defineProperty(target, member, descriptor);
      Object.defineProperty(planted, planted.length, desc({ value: member, enumerable: true, writable: true, configurable: true }));
    }
  } catch (e) {
    remove();
    throw e;
  }
  return { writes, ours: () => writes.filter((w) => isOurs(w.site)), remove };
}

/** Runs `body` with the traps planted, and always removes them. */
export async function withTraps<T>(
  target: object,
  members: readonly PropertyKey[],
  kind: TrapKind,
  polluted: (member: PropertyKey) => unknown,
  body: () => Promise<T>,
): Promise<{ value: T; writes: TrapWrite[]; ours: TrapWrite[] }> {
  const traps = plant(target, members, kind, polluted);
  let value: T;
  try {
    value = await body();
  } finally {
    traps.remove();
  }
  return { value, writes: traps.writes, ours: traps.ours() };
}

/** `holder[member]` is an own, enumerable, writable, configurable data property; returns its value. */
export function ownData(holder: unknown, member: PropertyKey, label: string): unknown {
  assert.ok(typeof holder === "object" && holder !== null, `${label}: an object`);
  const d = Object.getOwnPropertyDescriptor(holder, member);
  assert.ok(d !== undefined, `${label}: has an own ${String(member)}`);
  assert.ok("value" in d && d.get === undefined && d.set === undefined, `${label}: ${String(member)} is a data property`);
  assert.equal(d.enumerable, true, `${label}: ${String(member)} is enumerable`);
  assert.equal(d.writable, true, `${label}: ${String(member)} is writable`);
  assert.equal(d.configurable, true, `${label}: ${String(member)} is configurable`);
  return d.value;
}
