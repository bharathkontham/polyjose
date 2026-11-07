//! Sets up the Node-API link arguments napi-rs needs for a loadable `.node` module (ADR 0031 §2).

fn main() {
    napi_build::setup();
}
