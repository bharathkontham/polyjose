//! The UniFFI bindgen CLI for polyjose (ADR 0032 §2, ADR 0033): generates the Kotlin and Swift
//! sources from the compiled `polyjose-ffi` library in UniFFI's library mode. Build tooling only;
//! nothing of it ships.

fn main() {
    uniffi::uniffi_bindgen_main()
}
