/**
 * Checks a parsed vector against `conformance/schema.json` (JSON Schema draft 2020-12), as every
 * runner must (conformance/README.md "Rules for every runner": a file that is not schema-valid
 * fails, including a misspelled member anywhere).
 *
 * The bindings have no runtime dependencies (ADR 0016, ADR 0031), so this is a small checker of
 * exactly the keywords schema.json uses: `$ref` (local `#/$defs/...`), `type`, `enum`, `const`,
 * `properties`, `required`, `additionalProperties` (boolean or schema), `items`, `minItems`,
 * `maxItems`, `uniqueItems`, `minimum`, `maximum`, `minLength`, `pattern`, `allOf`, `oneOf`,
 * `if`/`then`/`else`, and the annotations `$schema`, `title`, `description`. Any other keyword
 * throws, so a schema change can't be silently ignored by this runner.
 *
 * JavaScript reads `1300819439.0` as the integer 1300819439, so `"type": "integer"` can't tell
 * them apart here; the Rust runner's `jwt_vectors_are_binding_ready` keeps such spellings out of
 * the vector files (conformance/README.md "Binding readiness"; 0004 T10-r1 ambiguity 5).
 * No Node-only imports.
 */

const ANNOTATIONS = new Set(["$schema", "title", "description"]);
const KEYWORDS = new Set([
  "$ref",
  "$defs",
  "type",
  "enum",
  "const",
  "properties",
  "required",
  "additionalProperties",
  "items",
  "minItems",
  "maxItems",
  "uniqueItems",
  "minimum",
  "maximum",
  "minLength",
  "pattern",
  "allOf",
  "oneOf",
  "if",
  "then",
  "else",
]);

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Equality of JSON values (RFC 8259): member order ignored, numbers as doubles. */
export function jsonEqual(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => jsonEqual(x, b[i]));
  }
  if (isObject(a) && isObject(b)) {
    const ka = Object.keys(a);
    return ka.length === Object.keys(b).length && ka.every((k) => Object.hasOwn(b, k) && jsonEqual(a[k], b[k]));
  }
  return a === b;
}

function hasType(value: unknown, type: unknown): boolean {
  switch (type) {
    case "object":
      return isObject(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    case "number":
      return typeof value === "number";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    default:
      throw new Error(`schema: unknown type ${JSON.stringify(type)}`);
  }
}

const regexCache = new Map<string, RegExp>();
function regex(pattern: string): RegExp {
  let re = regexCache.get(pattern);
  if (re === undefined) {
    re = new RegExp(pattern, "u");
    regexCache.set(pattern, re);
  }
  return re;
}

/**
 * The first violation of `schema` by `value`, as `<JSON pointer>: <problem>`, or undefined when
 * it is valid. Throws on a schema construct this checker does not implement.
 */
export function schemaViolation(root: unknown, value: unknown): string | undefined {
  if (!isObject(root) && typeof root !== "boolean") throw new Error("schema: the root is not a schema");
  const defs = isObject(root) && isObject(root["$defs"]) ? root["$defs"] : {};

  const check = (schema: unknown, v: unknown, ptr: string): string | undefined => {
    const at = ptr === "" ? "(root)" : ptr;
    if (schema === true) return undefined;
    if (schema === false) return `${at}: not allowed`;
    if (!isObject(schema)) throw new Error(`schema: not a schema at ${at}`);
    for (const k of Object.keys(schema)) {
      if (!KEYWORDS.has(k) && !ANNOTATIONS.has(k)) throw new Error(`schema: unsupported keyword ${k}`);
    }
    const s = schema as Record<string, unknown>;

    if (s["$ref"] !== undefined) {
      const ref = s["$ref"];
      const m = typeof ref === "string" ? /^#\/\$defs\/([^/]+)$/.exec(ref) : null;
      const target = m?.[1] === undefined ? undefined : defs[m[1]];
      if (target === undefined) throw new Error(`schema: unresolvable $ref ${String(ref)} (missing)`);
      const bad = check(target, v, ptr);
      if (bad !== undefined) return bad;
    }
    if (s["type"] !== undefined) {
      const types = Array.isArray(s["type"]) ? s["type"] : [s["type"]];
      if (!types.some((t) => hasType(v, t))) return `${at}: must be of type ${types.join(" or ")}`;
    }
    if (s["enum"] !== undefined) {
      const options = s["enum"];
      if (!Array.isArray(options)) throw new Error("schema: enum is not an array");
      if (!options.some((o) => jsonEqual(o, v))) return `${at}: must be one of ${JSON.stringify(options)}`;
    }
    if (Object.hasOwn(s, "const") && !jsonEqual(s["const"], v)) return `${at}: must be ${JSON.stringify(s["const"])}`;

    if (isObject(v)) {
      const props = isObject(s["properties"]) ? s["properties"] : {};
      if (s["required"] !== undefined) {
        for (const name of s["required"] as string[]) {
          if (!Object.hasOwn(v, name)) return `${ptr}/${name}: required member is missing`;
        }
      }
      for (const [name, sub] of Object.entries(props)) {
        if (Object.hasOwn(v, name)) {
          const bad = check(sub, v[name], `${ptr}/${name}`);
          if (bad !== undefined) return bad;
        }
      }
      if (s["additionalProperties"] !== undefined) {
        for (const name of Object.keys(v)) {
          if (Object.hasOwn(props, name)) continue;
          if (s["additionalProperties"] === false) return `${ptr}/${name}: unknown member (additionalProperties is false)`;
          const bad = check(s["additionalProperties"], v[name], `${ptr}/${name}`);
          if (bad !== undefined) return bad;
        }
      }
    }
    if (Array.isArray(v)) {
      if (typeof s["minItems"] === "number" && v.length < s["minItems"]) return `${at}: at least ${s["minItems"]} item(s)`;
      if (typeof s["maxItems"] === "number" && v.length > s["maxItems"]) return `${at}: at most ${s["maxItems"]} item(s)`;
      if (s["uniqueItems"] === true && v.some((x, i) => v.findIndex((y) => jsonEqual(x, y)) !== i)) return `${at}: items must be unique`;
      if (s["items"] !== undefined) {
        for (let i = 0; i < v.length; i++) {
          const bad = check(s["items"], v[i], `${ptr}/${i}`);
          if (bad !== undefined) return bad;
        }
      }
    }
    if (typeof v === "number") {
      if (typeof s["minimum"] === "number" && v < s["minimum"]) return `${at}: at least ${s["minimum"]}`;
      if (typeof s["maximum"] === "number" && v > s["maximum"]) return `${at}: at most ${s["maximum"]}`;
    }
    if (typeof v === "string") {
      // JSON Schema counts characters as code points.
      if (typeof s["minLength"] === "number" && [...v].length < s["minLength"]) return `${at}: at least ${s["minLength"]} character(s)`;
      if (typeof s["pattern"] === "string" && !regex(s["pattern"]).test(v)) return `${at}: must match ${s["pattern"]}`;
    }

    if (s["allOf"] !== undefined) {
      for (const sub of s["allOf"] as unknown[]) {
        const bad = check(sub, v, ptr);
        if (bad !== undefined) return bad;
      }
    }
    if (s["oneOf"] !== undefined) {
      const results = (s["oneOf"] as unknown[]).map((sub) => check(sub, v, ptr));
      const passing = results.filter((r) => r === undefined).length;
      if (passing !== 1) {
        return passing === 0 ? `${at}: matches none of oneOf (${results.join("; ")})` : `${at}: matches more than one of oneOf`;
      }
    }
    if (s["if"] !== undefined) {
      const branch = check(s["if"], v, ptr) === undefined ? s["then"] : s["else"];
      if (branch !== undefined) {
        const bad = check(branch, v, ptr);
        if (bad !== undefined) return bad;
      }
    }
    return undefined;
  };

  return check(root, value, "");
}
