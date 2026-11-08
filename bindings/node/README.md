# @polyjose/node

polyjose for Node.js: JOSE (JWS, JWE, JWK and JWT; RFC 7515 to 7519) implemented in pure Rust and
loaded as a Node-API addon. All cryptography comes from the RustCrypto and dalek crates, with no
OpenSSL. Verify and decrypt always take an explicit algorithm allow-list, and `none` is never
accepted (RFC 8725).

## Install

```sh
npm install @polyjose/node
```

npm also installs the matching prebuilt addon, `@polyjose/node-<platform>`, for macOS (x64,
arm64), Linux glibc and musl (x64, arm64) and Windows (x64, arm64). Each is an optional
dependency at exactly this package's version, and npm installs only the one for your platform.
If you install with `--omit=optional`, no addon is installed and the import throws.

### Linux glibc floor

The Linux glibc addons (`linux-x64-gnu`, `linux-arm64-gnu`) need **glibc 2.28 or later**. That is
also the floor of the official Node.js 22 and later Linux builds, so any glibc system that runs
official Node 22 can load the addon. They are built in the `manylinux_2_28` images (glibc 2.28),
and the build fails if an addon needs a newer glibc symbol version.

| Distribution | glibc |
|---|---|
| RHEL, AlmaLinux, Rocky Linux 8 | 2.28 |
| Debian 11 | 2.31 |
| Ubuntu 20.04 | 2.31 |
| RHEL, AlmaLinux, Rocky Linux 9 | 2.34 |
| Amazon Linux 2023, AWS Lambda `nodejs22.x` and `nodejs24.x` | 2.34 |
| Ubuntu 22.04 | 2.35 |
| Debian 12 | 2.36 |
| Ubuntu 24.04 | 2.39 |

Any later release of these works too. Amazon Linux 2 (glibc 2.26) is not supported: it reached its
end of life on 2026-06-30, and official Node 22 doesn't run on it either. Alpine and other musl
systems use the `linux-x64-musl` and `linux-arm64-musl` addons instead.

## Module format

- The package is **ESM only** and needs **Node.js 22.12 or later**.
- CommonJS code can still load it with `require("@polyjose/node")`, through Node's `require(esm)`
  (unflagged since 22.12).
- Every operation returns a Promise. The work runs on the libuv thread pool, so it doesn't block
  the event loop.
- The API and its TypeScript types are the same as `@polyjose/wasm`, so you can switch between
  the two packages by changing the import.

## Documentation

Guides and the API reference are at <https://polyjose.dev>. The Node.js guide is at
<https://polyjose.dev/start/node/>.

## Loading the addon

The package loads **only the polyjose addon whose SHA-256 it was built with**. Otherwise the
import throws an `Error` with `code` `ERR_POLYJOSE_ADDON_REFUSED`, and nothing it refused has run.

- **The hash pin.** The package ships `addon-sha256.json`: the SHA-256 of each platform's addon,
  generated when the package is built. Before anything loads, the package picks the one addon file
  for your platform, the same one the generated napi-rs loader (`binding.cjs`) would pick:
  1. the file named by `NAPI_RS_NATIVE_LIBRARY_PATH`, if set (see below);
  2. else a local `polyjose.<platform>.node` next to the loader;
  3. else the platform package `@polyjose/node-<platform>`, found through Node's normal module
     resolution: this package's `node_modules`, then every ancestor `node_modules`, then
     `NODE_PATH`.

  It hashes that file and refuses it unless the hash is the pinned one. The refusal names the
  platform, both hashes and where the file came from. There is no fallback to another file. So a
  substitute is refused wherever it was planted, a native addon as much as a JavaScript file,
  including when the genuine platform package is missing: after `npm install --omit=optional`, or
  on a platform polyjose doesn't publish. A package without the map, or without an entry for your
  platform, loads nothing.
- **No swap after the check.** The package writes the bytes it checked to a new private directory
  in `os.tmpdir()` (mode `0700`; on Windows, your own `%TEMP%`), checks the copy again, and has
  the loader load exactly that copy. Then it deletes the copy; the loaded addon stays in memory.
  Windows can't delete a loaded DLL, so there each copy (the size of the addon) stays in the
  temporary directory. The temporary directory must allow loading native code: if yours is
  mounted `noexec`, point `TMPDIR` (`TEMP` on Windows) at one that does.
- **Every candidate is native.** Before that, everything the loader could pick must be a native
  `.node` file. If any candidate resolves to something else, such as a JavaScript
  `@polyjose/node-<platform>` in a parent folder or on `NODE_PATH`, the import throws before that
  file runs.
- **After loading,** the result must be exactly the checked copy, not wrapped by any JavaScript,
  and its own `version()` must be this package's version. An addon from another polyjose release
  is refused, whatever `NAPI_RS_ENFORCE_VERSION_CHECK` says.
- polyjose **never publishes a `wasm32-wasi` package**. The napi-rs loader still has a WASI
  fallback, tried when the native load fails: `./polyjose.wasi.cjs`, then
  `@polyjose/node-wasm32-wasi`. The package never reaches it. If either WASI file or package can be
  found from the loader's directory, the import throws before anything is loaded. If loading the
  checked copy fails, the import throws "Cannot find native binding". For WebAssembly, use
  `@polyjose/wasm`.

These checks keep the package from *choosing* a substitute. They can't protect against code that
already runs in your process, which can change anything.

### Environment variables

| Variable | Effect |
|---|---|
| `NAPI_RS_NATIVE_LIBRARY_PATH` | Loads the addon from this path instead of the installed one, **only if its SHA-256 is the pinned one** for your platform (see below). |
| `NAPI_RS_FORCE_WASI` | **Refused.** If it is set, whatever the value (even `false` or empty), the import throws. |
| `NAPI_RS_WASI_FLAVOR` | **Refused**, like `NAPI_RS_FORCE_WASI`. |
| `NAPI_RS_ENFORCE_VERSION_CHECK` | Read by the generated loader only. The package checks the hash and the version anyway (see above). |

**`NAPI_RS_NATIVE_LIBRARY_PATH` is held to the same pin.** It names the file the package checks, so
it can only relocate polyjose's own addon, for example out of an archive or a bundle. A JavaScript
file there is refused before it runs; any other native library is refused by its hash. The package
sets the variable to its private copy while the loader runs and restores your value right after.

### A panic in the addon aborts the process

If the Rust code ever panics, Node.js **aborts the whole process** (SIGABRT). The Promise isn't
rejected, and no `catch` or `process.on("uncaughtException")` handler runs. This fails closed:
no partial result is returned, and no memory is corrupted. Today we know of no input that causes a
panic; the core forbids `panic!`, `unwrap` and `expect`. A server that must survive a panic should
run polyjose in a worker process it can restart. Turning panics into rejected Promises is planned.

### Side effects of loading

- **Linux:** to tell musl from glibc, the package reads `/usr/bin/ldd`, as the generated loader
  would. If that fails, it calls `process.report.getReport()`, and before that it sets
  `process.report.excludeNetwork = true` for the whole process. If there is no report either, the
  import throws. (The loader's last resort, `ldd --version` in a child process, is never run.)
- **Windows x64:** an embedder that runs Node as a shared library (`node_target_type` is
  `shared_library`), or a Node whose `shlib_suffix` is `dll.a`, maps to the `win32-x64-gnu`
  platform, as in the loader. polyjose doesn't publish that addon, so those hosts can't load the
  package.
- **Temporary directory:** each import that loads the addon creates one directory in
  `os.tmpdir()` (see "No swap after the check").
- **`__napiBindingTarget`:** the loaded addon has an extra property, `__napiBindingTarget`
  (`"native"`), set by the loader. The package's own API doesn't export it.

## Secrets in results

Results are plain objects, and their byte fields are plain `Uint8Array`s. So **printing a result
prints its secret bytes**: `console.log`, `util.inspect`, `JSON.stringify` and error reporters
show every byte. (The Kotlin and Swift bindings redact these fields when printed; JavaScript keeps
plain data instead, ADR 0065.)

- Never log a `JwsVerified` or `JweDecrypted` result.
- Never log the options and records that carry a secret: `JwsVerifyOptions` (`detachedPayload`),
  `JweEncryptOptions` (`aad`), `JwsSigner` and `JweRecipient` (`key`). Never log a private JWK.
- The seven secret fields are `JwsSigner.key`, `JweRecipient.key`, `JwsVerified.payload`,
  `JweDecrypted.plaintext`, `JweDecrypted.aad`, `JweEncryptOptions.aad` and
  `JwsVerifyOptions.detachedPayload`.
- When you are done with a returned `Uint8Array`, wipe it with `fill(0)`. JavaScript strings, such
  as a JWK's text, can't be wiped.

## License

MIT; see `LICENSE`. `THIRD-PARTY-NOTICES.txt` lists the third-party code this package contains.
Each platform package carries its own `THIRD-PARTY-NOTICES.txt` for the Rust crates compiled into
its addon.
