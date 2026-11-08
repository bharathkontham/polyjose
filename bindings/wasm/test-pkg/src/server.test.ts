/**
 * The Chrome run's static server (`server.ts`) serves only what it is told to: the fixed routes,
 * and known file types under the allowed prefixes, read-only, never outside its root.
 */
import { fs, path, assert, test, stageRoot } from "./node.js";
import { startServer } from "./server.js";

await test("the static server serves allowed files and refuses everything else", async () => {
  const root = fs.mkdtempSync(path.join(stageRoot(import.meta), "server-test-"));
  try {
    fs.mkdirSync(path.join(root, "pub"), { recursive: true });
    fs.writeFileSync(path.join(root, "pub", "a.js"), "export {};\n");
    fs.writeFileSync(path.join(root, "pub", "b.wasm"), "\0asm");
    fs.writeFileSync(path.join(root, "pub", "notes.txt"), "text");
    fs.writeFileSync(path.join(root, "secret.json"), "{}");
    const server = await startServer(root, ["/pub/"], { "/": { type: "text/html; charset=utf-8", body: "<p>page</p>" } });
    try {
      const get = (p: string, init?: RequestInit) => fetch(`${server.origin}${p}`, init);

      const page = await get("/");
      assert.equal(page.status, 200);
      assert.equal(await page.text(), "<p>page</p>");
      const js = await get("/pub/a.js");
      assert.equal(js.status, 200);
      assert.equal(js.headers.get("content-type"), "text/javascript; charset=utf-8");
      const wasm = await get("/pub/b.wasm");
      assert.equal(wasm.headers.get("content-type"), "application/wasm");

      for (const p of ["/secret.json", "/pub/notes.txt", "/pub/missing.js", "/pub/../secret.json", "/pub/%2e%2e/secret.json", "/pub/%2E%2E%2Fsecret.json"]) {
        const res = await get(p);
        assert.equal(res.status, 404, `${p} must be 404`);
        await res.arrayBuffer();
      }
      const post = await get("/pub/a.js", { method: "POST", body: "x" });
      assert.equal(post.status, 405);
      await post.arrayBuffer();
    } finally {
      await server.close();
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
