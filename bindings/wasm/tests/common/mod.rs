//! Shared by the wasm-bindgen-test binaries (`tests/conformance.rs`, `tests/engine.rs`): which
//! engine a run is in (0006 T02).
//!
//! Without `wasm_bindgen_test_configure!(run_in_browser)` a `wasm-pack test --headless --chrome`
//! run skips every test and exits 0, and with it a `--node` run does (0006 research §7). So the
//! `browser` feature sets the configuration, the Chrome run passes `--features browser`, and every
//! binary checks here that it runs in the engine its build was configured for. A run in the wrong
//! engine then fails; a run that skips everything prints no results line, which
//! `bindings/wasm/test.sh` fails on.

use js_sys::Reflect;
use wasm_bindgen::JsValue;

/// The ADR 0034 §2 runner name of this build: `wasm-chrome` with the `browser` feature, else
/// `wasm-node`.
pub(crate) const RUNNER: &str = if cfg!(feature = "browser") {
    "wasm-chrome"
} else {
    "wasm-node"
};

/// `globalThis[a][b]...` as a string, if every step exists and the last is a string.
fn global_string(path: &[&str]) -> Option<String> {
    let mut value: JsValue = js_sys::global().into();
    for key in path {
        if !value.is_object() {
            return None;
        }
        value = Reflect::get(&value, &JsValue::from_str(key)).ok()?;
    }
    value.as_string()
}

/// `Ok(user agent)` when the run is in the engine of [`RUNNER`]: headless Chrome (a
/// `navigator.userAgent` naming `Chrome/`, and no Node `process`) for `wasm-chrome`, Node (a
/// `process.versions.node` and a `navigator.userAgent` of `Node.js/…`, Node 21 and later) for
/// `wasm-node`. Otherwise `Err` with what was found.
pub(crate) fn check_engine() -> Result<String, String> {
    let agent = global_string(&["navigator", "userAgent"]).unwrap_or_default();
    let node = global_string(&["process", "versions", "node"]);
    let ok = if cfg!(feature = "browser") {
        agent.contains("Chrome/") && node.is_none()
    } else {
        node.is_some() && agent.starts_with("Node.js/")
    };
    if ok {
        Ok(agent)
    } else {
        Err(format!(
            "{RUNNER} runs in the wrong engine: navigator.userAgent {agent:?}, \
             process.versions.node {node:?}"
        ))
    }
}
