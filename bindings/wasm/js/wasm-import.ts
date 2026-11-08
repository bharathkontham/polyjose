// The type of the static `.wasm` import that workerd.mts makes (ADR 0031 §3): Cloudflare
// Workers and wrangler turn `import m from "./x.wasm"` into a compiled `WebAssembly.Module`
// (0006 research §5), because Workers forbid compiling wasm from bytes at run time.
//
// Written in TypeScript, not as a hand-written .d.ts (ADR 0047): this file has no import or
// export, so build-package.sh compiles it as a script (`moduleDetection: "legacy"`) and the
// ambient module below is global for the build. The pattern names the one module it types.
// Its compiled output is not shipped: the published declarations never mention the import.
declare module "*/polyjose_wasm_bg.wasm" {
  const module: WebAssembly.Module;
  export default module;
}
