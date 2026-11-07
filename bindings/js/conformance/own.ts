/**
 * Own-member construction for the conformance runner (0013 F13, security audit M1 follow-up).
 *
 * The runner is a caller of the facade, and it can run in a browser page or a workerd script it
 * doesn't control, so it follows the facade's rule: no member it hands the library or records as
 * an output is created by an ordinary assignment (ECMA-262 OrdinarySet), which consults the
 * object's prototype. There, a setter a pollution bug put on `Object.prototype.aad` (or on
 * `Array.prototype[0]`, which `push` assigns) would receive the value and the object would be
 * left without it, and a non-writable inherited member would make the write a TypeError.
 *
 * Kept apart from the facade's own helpers (`src/normalize.ts`), so the runner, which checks the
 * facade, shares no code with it. No Node-only imports.
 */

/**
 * A prototype-less copy of `init`'s own members. Members assigned to it later are created as own
 * data properties: with no prototype, there is no inherited setter or read-only member to
 * consult. The facade accepts such records (a plain object, ADR 0030 §2).
 */
export function rec<T extends object>(init: T): T {
  return Object.assign(Object.create(null) as T, init);
}

/**
 * Adds `value` at the end of `list` as an own data element, never with `push`. The descriptor
 * is prototype-less too: `Object.defineProperty` reads its members through the descriptor's
 * prototype chain (ToPropertyDescriptor).
 */
export function add<T>(list: T[], value: T): void {
  Object.defineProperty(list, list.length, rec<PropertyDescriptor>({ value, enumerable: true, writable: true, configurable: true }));
}
