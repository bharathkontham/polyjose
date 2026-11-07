/**
 * A strict JSON text scanner for vector files (conformance/README.md "Rules for every runner").
 *
 * `JSON.parse` alone is not enough for a conformance runner:
 * - it silently keeps the last of duplicate members, while vector files must be I-JSON
 *   (RFC 7493 §2.3; the Rust runner parses them with polyjose's strict parser and fails them);
 * - a JS object reorders integer-like member names, so `JSON.stringify(JSON.parse(text))`
 *   changes the order of `jwt.issue` claims, which an exact token depends on (ADR 0027 §1;
 *   0004 T10-r1 ambiguity 4).
 *
 * So the runner scans the text once (RFC 8259 grammar), refusing duplicates, and keeps the span
 * of every value; {@link textAt} then hands the library a value's own text, in file order.
 * No Node-only imports: the runner also runs in browsers and workerd.
 */

export type JsonNode =
  | { readonly kind: "object"; readonly start: number; readonly end: number; readonly members: ReadonlyMap<string, JsonNode> }
  | { readonly kind: "array"; readonly start: number; readonly end: number; readonly items: readonly JsonNode[] }
  | { readonly kind: "scalar"; readonly start: number; readonly end: number };

const WS = /[ \t\n\r]*/y;
// RFC 8259 §7: unescaped characters are U+0020..U+10FFFF except '"' and '\'.
const STRING = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
// RFC 8259 §6.
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const LITERAL = /true|false|null/y;

/** Scans `text` as one JSON value; throws a SyntaxError naming the offset or duplicate member. */
export function scanJson(text: string): JsonNode {
  let pos = 0;

  const fail = (what: string): never => {
    throw new SyntaxError(`invalid JSON at offset ${pos}: ${what}`);
  };
  const ws = (): void => {
    WS.lastIndex = pos;
    WS.exec(text);
    pos = WS.lastIndex;
  };
  const token = (re: RegExp): string | undefined => {
    re.lastIndex = pos;
    const m = re.exec(text);
    if (m === null) return undefined;
    pos = re.lastIndex;
    return m[0];
  };

  const value = (): JsonNode => {
    ws();
    const start = pos;
    const c = text[pos];
    if (c === "{") {
      pos++;
      const members = new Map<string, JsonNode>();
      ws();
      if (text[pos] === "}") {
        pos++;
        return { kind: "object", start, end: pos, members };
      }
      for (;;) {
        ws();
        const raw = token(STRING) ?? fail("expected a member name");
        const name = JSON.parse(raw) as string;
        if (members.has(name)) fail(`duplicate member ${JSON.stringify(name)} (RFC 7493 §2.3)`);
        ws();
        if (text[pos] !== ":") fail("expected ':'");
        pos++;
        members.set(name, value());
        ws();
        if (text[pos] === ",") {
          pos++;
          continue;
        }
        if (text[pos] === "}") {
          pos++;
          return { kind: "object", start, end: pos, members };
        }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      pos++;
      const items: JsonNode[] = [];
      ws();
      if (text[pos] === "]") {
        pos++;
        return { kind: "array", start, end: pos, items };
      }
      for (;;) {
        items.push(value());
        ws();
        if (text[pos] === ",") {
          pos++;
          continue;
        }
        if (text[pos] === "]") {
          pos++;
          return { kind: "array", start, end: pos, items };
        }
        fail("expected ',' or ']'");
      }
    }
    if (token(STRING) !== undefined || token(NUMBER) !== undefined || token(LITERAL) !== undefined) {
      return { kind: "scalar", start, end: pos };
    }
    return fail("expected a value");
  };

  const root = value();
  ws();
  if (pos !== text.length) fail("trailing characters");
  return root;
}

/** `text` without insignificant whitespace (outside strings); order and spelling unchanged. */
export function compactText(text: string): string {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] ?? "";
    if (inString) {
      out += c;
      if (c === "\\") out += text[++i] ?? "";
      else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
      out += c;
    } else if (c !== " " && c !== "\t" && c !== "\n" && c !== "\r") {
      out += c;
    }
  }
  return out;
}

/** The node at `path` (member names and array indices), if any. */
export function nodeAt(root: JsonNode, path: readonly (string | number)[]): JsonNode | undefined {
  let node: JsonNode | undefined = root;
  for (const step of path) {
    if (node === undefined) return undefined;
    if (typeof step === "number") node = node.kind === "array" ? node.items[step] : undefined;
    else node = node.kind === "object" ? node.members.get(step) : undefined;
  }
  return node;
}

/** The compact text of the value at `path`, in file order, or undefined when absent. */
export function textAt(text: string, root: JsonNode, path: readonly (string | number)[]): string | undefined {
  const node = nodeAt(root, path);
  return node === undefined ? undefined : compactText(text.slice(node.start, node.end));
}
