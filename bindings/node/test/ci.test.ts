// The CI build of @polyjose/node (feature 0007 T05; ADR 0031 §2, ADR 0034 §2, ADR 0037 §1), checked
// as text on every run of test.sh:
//   - scripts/ci-build.sh knows exactly the eight napi targets of package.json, each with its
//     npm/<platform> package;
//   - scripts/ci-build.sh and scripts/pack-platform.sh never publish (Gate 3, ADR 0011).
import { assert, fs, path, test } from "../../js/dist/node/builtins.js";

interface NodeUrl {
  fileURLToPath(url: string): string;
}
const host = (globalThis as unknown as { process: { getBuiltinModule(id: "node:url"): NodeUrl } }).process;
const thisFile = host.getBuiltinModule("node:url").fileURLToPath((import.meta as unknown as { url: string }).url);
/** bindings/node: this file is bindings/node/dist/ci.test.js. */
const pkgDir = path.resolve(path.dirname(thisFile), "..");
const ciBuildFile = path.join(pkgDir, "scripts", "ci-build.sh");
const packPlatformFile = path.join(pkgDir, "scripts", "pack-platform.sh");

const read = (file: string): string => fs.readFileSync(file, "utf8");
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;

/** package.json `napi.targets`: the eight Rust targets of ADR 0031 §2. */
function napiTargets(): string[] {
  const pkg: unknown = JSON.parse(read(path.join(pkgDir, "package.json")));
  assert.ok(isRecord(pkg) && isRecord(pkg["napi"]), "package.json has a napi section");
  const targets = pkg["napi"]["targets"];
  assert.ok(Array.isArray(targets) && targets.every((t) => typeof t === "string"), "napi.targets is a string array");
  return [...(targets as string[])].sort();
}

// --- The scripts ------------------------------------------------------------------------------------

/** The lines of a shell script that are not comments. */
function codeLines(file: string): string[] {
  return read(file)
    .split(/\r?\n/)
    .filter((line) => !line.trim().startsWith("#"));
}

/** ci-build.sh's `<triple>) platform=<npm dir> ;;` table. */
function ciBuildTable(): Map<string, string> {
  const table = new Map<string, string>();
  for (const line of codeLines(ciBuildFile)) {
    const m = /^\s*([a-z0-9_]+(?:-[a-z0-9_]+)+)\)\s*platform=([a-z0-9-]+)\s*;;/.exec(line);
    if (m !== null) table.set(m[1] ?? "", m[2] ?? "");
  }
  return table;
}

test("ci-build.sh maps each napi target to its npm/<platform> package", () => {
  const table = ciBuildTable();
  assert.deepEqual([...table.keys()].sort(), napiTargets(), "ci-build.sh knows exactly the napi targets");
  const dirs = fs
    .readdirSync(path.join(pkgDir, "npm"), { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
  assert.deepEqual([...table.values()].sort(), dirs, "one npm/<platform> directory per target");
  for (const [triple, platform] of table) {
    const pkg: unknown = JSON.parse(read(path.join(pkgDir, "npm", platform, "package.json")));
    assert.ok(isRecord(pkg), `npm/${platform}/package.json is an object`);
    assert.equal(pkg["name"], `@polyjose/node-${platform}`, `${triple}: package name`);
    assert.equal(pkg["main"], `polyjose.${platform}.node`, `${triple}: the addon napi build --platform writes`);
  }
});

test("ci-build.sh and pack-platform.sh never publish (npm publish and napi pre-publish are Gate 3)", () => {
  for (const file of [ciBuildFile, packPlatformFile]) {
    const name = path.relative(pkgDir, file);
    const code = codeLines(file).join("\n");
    assert.doesNotMatch(code, /publish/i, `${name}: no publish command`);
    assert.doesNotMatch(code, /token/i, `${name}: no registry token`);
    for (const m of code.matchAll(/\bnpm[ \t]+([a-z-]+)/g)) {
      assert.ok(["pack", "ci"].includes(m[1] ?? ""), `${name}: npm ${m[1]} is pack or ci`);
    }
    for (const m of code.matchAll(/\bnapi\b"?[ \t]+([a-z-]+)/g)) {
      assert.equal(m[1], "build", `${name}: napi ${m[1]} is build`);
    }
  }
});
