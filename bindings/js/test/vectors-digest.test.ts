// The vector-set digest of ADR 0060 §2-§3, computed by the shared runner from the files a driver
// read, with the SHA-256 the driver injects: node:crypto (node-main) or SubtleCrypto (browser and
// worker drivers), never polyjose.
import { assert, crypto, test } from "../node/builtins.js";
import { subtleSha256, vectorsDigest, type DigestInput, type Sha256 } from "../conformance/runner.js";

const nodeSha256: Sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest();

const bytes = (...octets: number[]): Uint8Array => Uint8Array.from(octets);

/** ADR 0060 §4: `README.md` (not a vector) is never handed in, so only the three `*.json` files. */
const WORKED_EXAMPLE: readonly DigestInput[] = [
  { id: "a.json#0", bytes: bytes(0x7b, 0x7d) },
  { id: "jws/b.json#0", bytes: bytes(0x7b, 0x7d, 0x0a) },
  { id: "jws-x/c.json#0", bytes: bytes(0xef, 0xbb, 0xbf, 0x7b, 0x7d) },
];
const WORKED_DIGEST = "9a06f1efdd269176088cb0e6bfc6a7e4d4f74aa3d1b1b8fc6c879fdbb82ac7d1";

test("the ADR 0060 §4 worked example, with node:crypto and with SubtleCrypto", async () => {
  assert.equal(await vectorsDigest(WORKED_EXAMPLE, nodeSha256), WORKED_DIGEST);
  assert.equal(await vectorsDigest(WORKED_EXAMPLE, subtleSha256), WORKED_DIGEST);
  // Lines are sorted before hashing, so the read order doesn't matter.
  assert.equal(await vectorsDigest([...WORKED_EXAMPLE].reverse(), nodeSha256), WORKED_DIGEST);
});

test("lines sort by UTF-8 bytes, not by JS (UTF-16) string order", async () => {
  // U+FF61 is EF BD A1 in UTF-8 and U+1F600 is F0 9F 98 80, so U+FF61 sorts first by bytes;
  // in UTF-16, U+1F600 (D83D DE00) sorts before U+FF61.
  const halfwidth = "\u{ff61}.json#0";
  const emoji = "\u{1f600}.json#0";
  assert.ok(emoji < halfwidth, "the UTF-16 order is the other one");
  const files: DigestInput[] = [
    { id: emoji, bytes: bytes(0x31) },
    { id: halfwidth, bytes: bytes(0x32) },
  ];
  const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const line = (id: string, content: Uint8Array): string => `${id}\t${hex(nodeSha256(content) as Uint8Array)}\n`;
  // The expected digest over [halfwidth line, emoji line], each encoded as UTF-8 by node:crypto.
  const expected = crypto.createHash("sha256");
  for (const [id, content] of [[halfwidth, bytes(0x32)], [emoji, bytes(0x31)]] as const) {
    expected.update(utf8(line(id, content)));
  }
  assert.equal(await vectorsDigest(files, nodeSha256), hex(expected.digest()));
});

test("an empty corpus has no digest: vectorsDigest refuses it (ADR 0060 §3)", async () => {
  await assert.rejects(vectorsDigest([], nodeSha256), /no vector file/);
});

test("a SHA-256 that doesn't return 32 bytes is refused, not hex-encoded", async () => {
  await assert.rejects(vectorsDigest(WORKED_EXAMPLE, () => bytes(1, 2, 3)), /32 bytes/);
});

/** UTF-8 of `s`, through the platform's TextEncoder (present in Node, browsers and workerd). */
function utf8(s: string): Uint8Array {
  const encoder = new (globalThis as unknown as { TextEncoder: new () => { encode(text: string): Uint8Array } }).TextEncoder();
  return encoder.encode(s);
}
