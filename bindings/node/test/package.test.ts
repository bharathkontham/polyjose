// The packed @polyjose/node tarball (feature 0007 T04, feature 0017; ADR 0031 §4, ADR 0020 §4,
// ADR 0011), run with `node --test` by scripts/pack.sh right after it writes it to dist/npm/.
// test.sh does not run this file: packing builds the darwin-x64 addon too, which the host suite
// does not need.
//
// It checks what would be published, read back from the tarball itself (`tar`):
//   - pack.sh, pack-main.sh and build.sh never publish: no `npm publish`, `napi pre-publish`;
//   - the tarball holds exactly package.json plus the `files` of package.json that the Mac build
//     has (the two darwin addons of the eight), compiled output only, with the sourceMappingURL
//     comments removed (the maps are not shipped);
//   - each addon is a Mach-O for its CPU, byte-equal to the build's;
//   - THIRD-PARTY-NOTICES.txt is the one scripts/third-party-notices.sh generates for the two
//     darwin targets together, and names napi and the crypto crates, not wasm-bindgen;
//   - every package.json version equals the workspace version;
//   - addon-sha256.json pins exactly the two addons in the tarball, by their SHA-256 (F07);
//   - installing the tarball alone into a temporary directory, offline, gives a package that
//     `import`s by name and round-trips jwsSignCompact and jwsVerifyCompact. The darwin-x64 addon
//     cannot run on an Apple-silicon Mac without Rosetta, so it is checked by contents only.
import { assert, fs, os, path, test } from "../../js/dist/node/builtins.js";
import type * as Api from "@polyjose/node";

interface ExecOptions {
  cwd?: string;
  env?: Record<string, string>;
  encoding?: "utf8";
  stdio?: readonly ("ignore" | "pipe" | "inherit")[];
}
interface NodeChildProcess {
  execFileSync(file: string, args: readonly string[], options: ExecOptions & { encoding: "utf8" }): string;
  execFileSync(file: string, args: readonly string[], options?: ExecOptions): Uint8Array;
}
interface NodeFsBytes {
  readFileSync(path: string): Uint8Array;
  realpathSync(path: string): string;
}
interface NodeCrypto {
  createHash(algorithm: "sha256"): { update(data: Uint8Array): { digest(encoding: "hex"): string } };
}
interface NodeModule {
  createRequire(from: string): { resolve(id: string): string; readonly cache: Record<string, unknown> };
}
interface NodeUrl {
  fileURLToPath(url: string): string;
  pathToFileURL(path: string): { readonly href: string };
}
interface Host {
  readonly platform: string;
  readonly arch: string;
  readonly env: Record<string, string | undefined>;
  getBuiltinModule(id: "node:child_process"): NodeChildProcess;
  getBuiltinModule(id: "node:crypto"): NodeCrypto;
  getBuiltinModule(id: "node:fs"): NodeFsBytes;
  getBuiltinModule(id: "node:module"): NodeModule;
  getBuiltinModule(id: "node:url"): NodeUrl;
}
const host = (globalThis as unknown as { process: Host }).process;
const cp = host.getBuiltinModule("node:child_process");
const fsb = host.getBuiltinModule("node:fs");
const url = host.getBuiltinModule("node:url");

const thisFile = url.fileURLToPath((import.meta as unknown as { url: string }).url);
/** bindings/node: this file is bindings/node/dist/package.test.js. */
const pkgDir = path.resolve(path.dirname(thisFile), "..");
const repo = path.resolve(pkgDir, "..", "..");
const outDir = path.join(pkgDir, "dist", "npm");

/** The darwin addons pack.sh builds on this Mac, with their Rust target and Mach-O CPU. */
const PLATFORMS = [
  { name: "darwin-arm64", triple: "aarch64-apple-darwin", arch: "arm64", cputype: 0x0100000c },
  { name: "darwin-x64", triple: "x86_64-apple-darwin", arch: "x64", cputype: 0x01000007 },
] as const;

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;
function readJson(file: string): Record<string, unknown> {
  const v: unknown = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.ok(isRecord(v), `${file} is a JSON object`);
  return v;
}
function strings(v: unknown, what: string): string[] {
  assert.ok(Array.isArray(v) && v.every((x) => typeof x === "string"), `${what} is a string array`);
  return v as string[];
}
const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
/** Whether a file is byte-equal to the repository's MIT LICENSE (ADR 0015). */
const sameLicense = (file: string): boolean =>
  bytesEqual(fsb.readFileSync(file), fsb.readFileSync(path.join(repo, "LICENSE")));

/** `version` of `[workspace.package]` in the root Cargo.toml (every crate inherits it). */
function workspaceVersion(): string {
  const toml = fs.readFileSync(path.join(repo, "Cargo.toml"), "utf8");
  const section = toml.split(/^\[workspace\.package\]$/m)[1]?.split(/^\[/m)[0] ?? "";
  const m = /^version = "([^"]+)"$/m.exec(section);
  assert.ok(m?.[1] !== undefined, "[workspace.package] version in Cargo.toml");
  return m[1];
}

const pkg = readJson(path.join(pkgDir, "package.json"));
const version = workspaceVersion();
/** npm pack's file name for a scoped package: `@polyjose/node-x` 0.1.0 -> polyjose-node-x-0.1.0.tgz. */
const tarballName = (name: string): string => `${name.replace(/^@/, "").replace("/", "-")}-${version}.tgz`;
const mainTgz = path.join(outDir, tarballName("@polyjose/node"));

/** The entries of a tarball, without npm's `package/` prefix, sorted. */
function tarList(tgz: string): string[] {
  const out = cp.execFileSync("tar", ["-tzf", tgz], { encoding: "utf8" });
  return out
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => {
      assert.ok(line.startsWith("package/"), `${tgz}: ${line} is under package/`);
      return line.slice("package/".length);
    })
    .sort();
}

/** Extracts a tarball into a fresh temporary directory and returns its package/ directory. */
function extract(tgz: string, scratch: string[]): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "polyjose-node-pack-"));
  scratch.push(dir);
  cp.execFileSync("tar", ["-xzf", tgz, "-C", dir]);
  return path.join(dir, "package");
}
function withScratch(fn: (scratch: string[]) => void | Promise<void>): () => Promise<void> {
  return async () => {
    const scratch: string[] = [];
    try {
      await fn(scratch);
    } finally {
      for (const dir of scratch) fs.rmSync(dir, { recursive: true, force: true });
    }
  };
}

/**
 * The files of package.json `files`, expanded against the built package: a literal name stays
 * as it is (LICENSE, README.md and THIRD-PARTY-NOTICES.txt are added at pack time), except the
 * addons, of which a Mac packs the two darwin ones only; `dir/*.ext` names every file of dir/
 * ending in .ext. npm always adds package.json.
 */
function expectedMainFiles(): string[] {
  const out = ["package.json"];
  for (const pattern of strings(pkg["files"], "package.json files")) {
    const star = pattern.indexOf("*");
    if (star === -1) {
      const addon = /^polyjose\.([a-z0-9-]+)\.node$/.exec(pattern)?.[1];
      if (addon === undefined || PLATFORMS.some((p) => p.name === addon)) out.push(pattern);
      continue;
    }
    const m = /^([a-z]+)\/\*(\.[a-z.]+)$/.exec(pattern);
    assert.ok(m?.[1] !== undefined && m[2] !== undefined, `files pattern ${pattern} has the form dir/*.ext`);
    const [dir, ext] = [m[1], m[2]];
    const names = fs
      .readdirSync(path.join(pkgDir, dir), { withFileTypes: true })
      .filter((d) => d.isFile() && d.name.endsWith(ext) && (ext !== ".js" || !d.name.endsWith(".d.js")))
      .map((d) => `${dir}/${d.name}`);
    assert.ok(names.length > 0, `${pattern} matches built files`);
    out.push(...names);
  }
  return [...new Set(out)].sort();
}

/** Crates the notices must name: the napi runtime and the ADR 0002 primitives. */
const NAMED_CRATES = [
  "napi",
  "napi-sys",
  "p256",
  "p384",
  "p521",
  "rsa",
  "ed25519-dalek",
  "x25519-dalek",
  "aes-gcm",
  "aes-kw",
  "sha2",
  "hmac",
  "pbkdf2",
  "zeroize",
  "subtle",
  "getrandom",
];

/** A trailing `//# sourceMappingURL=<file>.map` line, as tsc writes it. */
const SOURCE_MAP_LINE = /\n\/\/# sourceMappingURL=[^\s]+\.map\n?$/;

/** Lines of a shell script that are not comments. */
function codeLines(file: string): string[] {
  return fs
    .readFileSync(file, "utf8")
    .split("\n")
    .filter((line) => !line.trim().startsWith("#"));
}

test("pack.sh, pack-main.sh and build.sh never publish (npm publish and napi pre-publish are Gate 3)", () => {
  for (const script of ["pack.sh", "pack-main.sh", "build.sh"]) {
    const file = path.join(pkgDir, "scripts", script);
    const code = codeLines(file).join("\n");
    assert.doesNotMatch(code, /publish/i, `${script}: no publish command`);
    for (const m of code.matchAll(/\bnpm\s+([a-z-]+)/g)) {
      assert.ok(["pack", "ci"].includes(m[1] ?? ""), `${script}: npm ${m[1]} is pack or ci`);
    }
    for (const m of code.matchAll(/\$napi"?\s+([a-z-]+)/g)) {
      assert.equal(m[1], "build", `${script}: napi ${m[1]} is build`);
    }
  }
});

test("dist/npm holds exactly the one @polyjose/node tarball", () => {
  const found = fs
    .readdirSync(outDir, { withFileTypes: true })
    .map((d) => d.name)
    .sort();
  assert.deepEqual(found, [path.relative(outDir, mainTgz)]);
});

test("the tarball holds exactly package.json and the files list: compiled output, the addons, no maps", () => {
  const list = tarList(mainTgz);
  assert.deepEqual(list, expectedMainFiles());
  for (const f of list) {
    assert.ok(!f.endsWith(".map"), `${f}: no source maps`);
    assert.ok(!f.endsWith(".cjs"), `${f}: no napi-rs loader (feature 0017)`);
    assert.ok(!f.endsWith(".ts") || f.endsWith(".d.ts"), `${f}: no TypeScript sources (ADR 0047)`);
  }
  assert.deepEqual(
    list.filter((f) => f.endsWith(".node")),
    PLATFORMS.map((p) => `polyjose.${p.name}.node`).sort(),
    "the two darwin addons",
  );
});

test(
  "the main tarball's files equal the build, the LICENSE and README, minus the sourceMappingURL lines",
  withScratch((scratch) => {
    const dir = extract(mainTgz, scratch);
    assert.deepEqual(readJson(path.join(dir, "package.json")), pkg, "package.json as committed");
    assert.ok(sameLicense(path.join(dir, "LICENSE")), "LICENSE is the repository's");
    const readme = fs.readFileSync(path.join(dir, "README.md"), "utf8");
    assert.equal(readme, fs.readFileSync(path.join(pkgDir, "README.md"), "utf8"), "README.md as committed");
    for (const f of tarList(mainTgz)) {
      if (!/\.(js|cjs|d\.ts)$/.test(f)) continue;
      const shipped = fs.readFileSync(path.join(dir, f), "utf8");
      const built = fs.readFileSync(path.join(pkgDir, f), "utf8");
      assert.doesNotMatch(shipped, /sourceMappingURL/, `${f}: no reference to an unshipped map`);
      assert.equal(shipped, built.replace(SOURCE_MAP_LINE, "\n"), `${f}: the build, minus that one line`);
    }
  }),
);

test(
  "each addon in the tarball is a Mach-O dylib for its CPU, byte-equal to the build's",
  withScratch((scratch) => {
    const dir = extract(mainTgz, scratch);
    for (const p of PLATFORMS) {
      const addon = `polyjose.${p.name}.node`;
      const bin = fsb.readFileSync(path.join(dir, addon));
      const view = new DataView(bin.buffer, bin.byteOffset, bin.byteLength);
      assert.equal(view.getUint32(0, true), 0xfeedfacf, `${addon}: MH_MAGIC_64`);
      assert.equal(view.getUint32(4, true), p.cputype, `${addon}: CPU type for ${p.arch}`);
      assert.equal(view.getUint32(12, true), 6, `${addon}: MH_DYLIB`);
      assert.ok(bytesEqual(bin, fsb.readFileSync(path.join(pkgDir, addon))), `${addon}: the built addon`);
    }
  }),
);

test(
  "the notices are generated for the addons' targets: napi and the crypto crates, no wasm-bindgen",
  withScratch((scratch) => {
    const notices = fs.readFileSync(path.join(extract(mainTgz, scratch), "THIRD-PARTY-NOTICES.txt"), "utf8");
    const regen = fs.mkdtempSync(path.join(os.tmpdir(), "polyjose-node-notices-"));
    scratch.push(regen);
    const fresh = path.join(regen, "notices.txt");
    cp.execFileSync(
      path.join(repo, "scripts", "third-party-notices.sh"),
      ["-p", "polyjose-node", ...PLATFORMS.flatMap((p) => ["--target", p.triple]), "-o", fresh],
      { stdio: ["ignore", "ignore", "inherit"] },
    );
    assert.equal(notices, fs.readFileSync(fresh, "utf8"), "generated, not edited");
    assert.ok(notices.startsWith("THIRD-PARTY NOTICES\n\nArtifact: polyjose-node "), "header");
    const triples = PLATFORMS.map((p) => p.triple).sort();
    assert.ok(notices.includes(`\nTargets: ${triples.join(", ")}\n`), "both darwin targets");
    // The crate list: "<name> <version>  <license>" lines between the "Third-party crates" rules.
    const crates = notices
      .split("\n")
      .map((line) => /^([a-z0-9_-]+) \d+\.\d+\.\d+\S*  \S/.exec(line)?.[1])
      .filter((name): name is string => name !== undefined);
    for (const name of NAMED_CRATES) assert.ok(crates.includes(name), `names ${name}`);
    assert.ok(!notices.includes("wasm-bindgen"), "no wasm-bindgen (that is @polyjose/wasm)");
    assert.ok(notices.includes(fs.readFileSync(path.join(repo, "LICENSE"), "utf8").trimEnd()), "polyjose's LICENSE text");
  }),
);

test(
  "the tarball's addon-sha256.json pins exactly the two darwin addons it holds (F07)",
  withScratch((scratch) => {
    const dir = extract(mainTgz, scratch);
    const pins = readJson(path.join(dir, "addon-sha256.json"));
    const want: Record<string, string> = {};
    for (const p of PLATFORMS) {
      const addon = fsb.readFileSync(path.join(dir, `polyjose.${p.name}.node`));
      want[p.name] = host.getBuiltinModule("node:crypto").createHash("sha256").update(addon).digest("hex");
    }
    assert.deepEqual(pins, want);
  }),
);

test(
  "every package.json version, committed and packed, equals the workspace version",
  withScratch((scratch) => {
    assert.equal(pkg["version"], version, "bindings/node/package.json");
    const packed = readJson(path.join(extract(mainTgz, scratch), "package.json"));
    assert.equal(packed["version"], version, path.relative(outDir, mainTgz));
  }),
);

test("the README states the module format, the Node floor and the docs links", () => {
  const readme = fs.readFileSync(path.join(pkgDir, "README.md"), "utf8");
  assert.ok(readme.startsWith("# @polyjose/node\n"), "title");
  const needles = ["ESM", "require(esm)", "22.12", "https://polyjose.dev/start/node/", "https://polyjose.dev/reference/node/"];
  for (const needle of [...needles, "LICENSE", "THIRD-PARTY-NOTICES.txt"]) {
    assert.ok(readme.includes(needle), `README mentions ${needle}`);
  }
});

test(
  "installed offline from the tarball alone, the package imports by name and round-trips a compact JWS",
  withScratch(async (scratch) => {
    const platform = PLATFORMS.find((p) => host.platform === "darwin" && host.arch === p.arch);
    const hostName = `${host.platform}-${host.arch}`;
    assert.ok(platform !== undefined, `the host (${hostName}) is one of the darwin targets pack.sh builds`);
    const dir = fsb.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "polyjose-node-install-")));
    scratch.push(dir);
    const manifest = { name: "polyjose-node-smoke", version: "0.0.0", private: true, type: "module" };
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(manifest));
    // npm refuses to load one file as both the user and the global config.
    fs.writeFileSync(path.join(dir, "user.npmrc"), "");
    fs.writeFileSync(path.join(dir, "global.npmrc"), "");
    // Hermetic npm: a temporary cache and empty user and global configs, offline, no scripts.
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(host.env)) {
      if (v !== undefined && !/^npm_/i.test(k) && k !== "NAPI_RS_NATIVE_LIBRARY_PATH") env[k] = v;
    }
    Object.assign(env, {
      npm_config_cache: path.join(dir, "cache"),
      npm_config_userconfig: path.join(dir, "user.npmrc"),
      npm_config_globalconfig: path.join(dir, "global.npmrc"),
      npm_config_offline: "true",
      npm_config_audit: "false",
      npm_config_fund: "false",
      npm_config_update_notifier: "false",
      npm_config_ignore_scripts: "true",
      npm_config_package_lock: "false",
    });
    cp.execFileSync("npm", ["install", "--offline", "--no-audit", "--no-fund", mainTgz], {
      cwd: dir,
      env,
      stdio: ["ignore", "ignore", "inherit"],
    });

    // Resolve "@polyjose/node" by name from the install directory, through its exports map.
    const require = host.getBuiltinModule("node:module").createRequire(path.join(dir, "smoke.js"));
    const entry = require.resolve("@polyjose/node");
    assert.equal(entry, path.join(dir, "node_modules", "@polyjose", "node", "index.js"));
    delete host.env["NAPI_RS_NATIVE_LIBRARY_PATH"];
    const api = (await import(url.pathToFileURL(entry).href)) as typeof Api;

    const key = await api.jwkGenerateEc("P-256");
    const payload = Uint8Array.from("polyjose packed", (c) => c.charCodeAt(0));
    const token = await api.jwsSignCompact(payload, key, { protectedHeader: { alg: "ES256" } });
    const verified = await api.jwsVerifyCompact(token, await api.jwkToPublic(key), { allowedAlgs: ["ES256"] });
    assert.equal(verified.alg, "ES256");
    assert.ok(bytesEqual(verified.payload, payload), "the payload round-trips");

    // The addon is a private, hash-checked copy (F07; test/loader.test.ts checks where): the only
    // one loaded, outside the install and the build. Its source is the installed package's own
    // polyjose.<host>.node (feature 0017): the install holds no other package.
    assert.deepEqual(fs.readdirSync(path.join(dir, "node_modules", "@polyjose"), { withFileTypes: true }).map((d) => d.name), ["node"], "only @polyjose/node is installed");
    const addons = Object.keys(require.cache).filter((k) => k.endsWith(".node"));
    assert.equal(addons.length, 1, `one addon loaded (${addons.join(", ")})`);
    const copy = addons[0] ?? "";
    assert.ok(!copy.startsWith(dir + path.sep) && !copy.startsWith(pkgDir + path.sep), `${copy}: a private copy`);
    assert.match(copy, /[\\/]polyjose-addon-[^\\/]+[\\/]polyjose-[0-9a-f]{32}\.node$/, "the private copy's name");
  }),
);
