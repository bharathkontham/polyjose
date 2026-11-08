//! Host-side source rules of the adapter (feature 0006 T01), checked by reading `src/*.rs` as
//! text, because the exports themselves only run inside a JS runtime (feature 0006 T02).
//!
//! - **Secrets in** (ADR 0030 §7.1, ADR 0031 §3, 0006 research §3): every `String`/`Vec<u8>`
//!   parameter of an export is moved into `Zeroizing` before anything else runs, and a borrowed
//!   `&str` is used only for a registered identifier (`alg`, `crv`, `format`, `form`, `hash`),
//!   never for a key, a payload, a token or any other JOSE data.
//! - **Secrets out** (ADR 0030 §7.2): no export returns bytes as `Vec<u8>`, and only the listed
//!   public results return an owned `String`; everything else is built from a borrowed slice. No
//!   source copies a secret out of its owner (`as_str().to_…`, `as_bytes().to_…`).
//! - **Optional `hash`, no default** (ADR 0054 §9, ADR 0030 §1, §3): `jwkThumbprint` and
//!   `jwkThumbprintUri` take `hash: Option<String>` and hand it to the surface as `as_deref()`;
//!   the adapter names no hash, so an absent one is the core's default (SHA-256).
//! - **Own data out** (BACKEND.md "Results", 0006 review S1): no source builds a JS object that
//!   inherits from `Object.prototype` (`Object::new()`) or assigns through the prototype chain
//!   (`set_name`), and no `Reflect` result is dropped (`let _ =`, `.map(drop)`), so a planted
//!   setter or read-only member can neither see a value nor silently remove a member.
//! - **No clock** (ADR 0028, ADR 0030 §4): the facade passes JWT `now`; nothing here reads time.
//! - **No `unsafe`, no logging** (workspace rules, ADR 0030 §7.5).
//! - **Coverage** (ADR 0030 §4, BACKEND.md): one export per `op` of `bindings/api-inventory.txt`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Parameter names that may be borrowed (`&str`): registered identifiers, public by definition
/// (RFC 7518 §3.1, §4.1, §5.1 names; RFC 7638 hash names; key format and JSON form names).
const IDENTIFIER_PARAMS: [&str; 5] = ["alg", "crv", "form", "format", "hash"];

/// Identifier parameters that are optional, as `Option<String>` (wasm-bindgen maps JS
/// `undefined` and `null` to `None`): only the thumbprint `hash` (ADR 0054 §9, BACKEND.md).
const OPTIONAL_IDENTIFIER_PARAMS: [&str; 1] = ["hash"];

/// Exports allowed to return an owned `String`: results that carry no secret (ADR 0030 §7.2):
/// the version, a public JWK, thumbprints (RFC 7638 §7) and JWE ciphertext (RFC 7516).
const PUBLIC_STRING_RESULTS: [&str; 7] = [
    "version",
    "jwkToPublic",
    "jwkThumbprint",
    "jwkThumbprintUri",
    "jweEncryptCompact",
    "jweEncryptJson",
    "jwtEncryptNested",
];

/// One `#[wasm_bindgen(js_name = …)] pub fn` of the adapter.
struct Export {
    file: String,
    js_name: String,
    params: Vec<(String, String)>,
    returns: String,
    body: String,
}

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Drops `//` comments (doc comments included), so the rules see code only. The adapter has no
/// string literal containing `//`.
fn code_only(text: &str) -> String {
    text.lines()
        .map(|line| line.find("//").map_or(line, |at| &line[..at]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every `src/*.rs` file except this one, as `(file name, code without comments)`.
fn sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(src_dir()).unwrap_or_else(|e| unreachable!("read src: {e}")) {
        let path = entry.unwrap_or_else(|e| unreachable!("{e}")).path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.extension().is_some_and(|x| x == "rs") && name != "rules.rs" {
            let text = fs::read_to_string(&path).unwrap_or_else(|e| unreachable!("{name}: {e}"));
            out.push((name, code_only(&text)));
        }
    }
    out.sort();
    out
}

/// The text between the bracket at `open` and its match, exclusive.
fn balanced(text: &str, open: usize, (l, r): (char, char)) -> (&str, usize) {
    let mut depth = 0usize;
    for (i, c) in text[open..].char_indices() {
        if c == l {
            depth += 1;
        } else if c == r {
            depth -= 1;
            if depth == 0 {
                return (&text[open + 1..open + i], open + i);
            }
        }
    }
    unreachable!("unbalanced {l}{r}")
}

/// Splits on commas outside `<>`, `()` and `[]`.
fn split_top(list: &str) -> Vec<String> {
    let (mut parts, mut cur, mut depth) = (Vec::new(), String::new(), 0i32);
    for c in list.chars() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    parts.push(cur);
    parts
        .into_iter()
        .map(|p| p.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|p| !p.is_empty())
        .collect()
}

fn exports() -> Vec<Export> {
    let mut out = Vec::new();
    for (file, text) in sources() {
        let mut from = 0;
        while let Some(at) = text[from..].find("#[wasm_bindgen(js_name = ") {
            let attr = from + at;
            let name_start = attr + "#[wasm_bindgen(js_name = ".len();
            let name_end = name_start + text[name_start..].find(')').unwrap_or(0);
            let js_name = text[name_start..name_end].to_owned();
            let fn_at = name_end
                + text[name_end..]
                    .find("pub fn ")
                    .unwrap_or_else(|| unreachable!("{file}: {js_name}: no pub fn"));
            let paren = fn_at + text[fn_at..].find('(').unwrap_or(0);
            let (params, close) = balanced(&text, paren, ('(', ')'));
            let brace = close + text[close..].find('{').unwrap_or(0);
            let returns = text[close + 1..brace]
                .trim()
                .trim_start_matches("->")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let (body, end) = balanced(&text, brace, ('{', '}'));
            let params = split_top(params)
                .into_iter()
                .map(|p| {
                    let (n, t) = p
                        .split_once(':')
                        .unwrap_or_else(|| unreachable!("{file}: {js_name}: param {p}"));
                    (n.trim().to_owned(), t.trim().to_owned())
                })
                .collect();
            out.push(Export {
                file: file.clone(),
                js_name,
                params,
                returns,
                body: body.to_owned(),
            });
            from = end;
        }
    }
    out
}

#[test]
fn owned_inputs_are_zeroizing_from_the_first_statement() {
    let exports = exports();
    assert!(!exports.is_empty(), "no export found");
    for e in &exports {
        let owned: Vec<&str> = e
            .params
            .iter()
            .filter(|(_, t)| t == "String" || t == "Vec<u8>")
            .map(|(n, _)| n.as_str())
            .collect();
        let leading: Vec<String> = e
            .body
            .split(';')
            .take(owned.len())
            .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        for name in &owned {
            let wrap = format!("let {name} = Zeroizing::new({name})");
            assert!(
                leading.contains(&wrap),
                "{}: {}: `{name}` must be wrapped by the leading `{wrap};` statements",
                e.file,
                e.js_name
            );
        }
    }
}

#[test]
fn borrowed_and_other_parameters_are_public_only() {
    for e in exports() {
        for (name, ty) in &e.params {
            let ok = match ty.as_str() {
                "String" | "Vec<u8>" | "u32" | "bool" | "&JsValue" => true,
                "&str" => IDENTIFIER_PARAMS.contains(&name.as_str()),
                "Option<String>" => OPTIONAL_IDENTIFIER_PARAMS.contains(&name.as_str()),
                _ => false,
            };
            assert!(
                ok,
                "{}: {}: parameter `{name}: {ty}`: JOSE data is taken by value (String, Vec<u8>) \
                 and records as &JsValue; &str only for {IDENTIFIER_PARAMS:?}, Option<String> \
                 only for {OPTIONAL_IDENTIFIER_PARAMS:?}",
                e.file, e.js_name
            );
        }
    }
}

#[test]
fn owned_results_are_public_only() {
    for e in exports() {
        let r = e.returns.as_str();
        assert!(
            !r.contains("Vec<u8>"),
            "{}: {}: bytes go out as Uint8Array built from a slice",
            e.file,
            e.js_name
        );
        let owned_string = r == "String" || r.starts_with("Result<String,");
        assert!(
            !owned_string || PUBLIC_STRING_RESULTS.contains(&e.js_name.as_str()),
            "{}: {}: returns an owned String; only {PUBLIC_STRING_RESULTS:?} may",
            e.file,
            e.js_name
        );
    }
}

#[test]
fn no_secret_is_copied_out_of_its_owner() {
    for (file, text) in sources() {
        for pattern in ["as_str().to_", "as_bytes().to_", ".as_str().into()"] {
            assert!(
                !text.contains(pattern),
                "{file}: `{pattern}` copies a secret"
            );
        }
    }
}

#[test]
fn objects_are_prototype_less_and_no_reflect_result_is_dropped() {
    // Built from pieces so this file does not match itself.
    let banned = [["Object::", "new()"].concat(), [".set_", "name("].concat()];
    for (file, text) in sources() {
        for b in &banned {
            assert!(
                !text.contains(b.as_str()),
                "{file}: `{b}` goes through Object.prototype; use a prototype-less object and \
                 define or set own members (write.rs, error.rs)"
            );
        }
        for statement in text.split(';').filter(|s| s.contains("Reflect::")) {
            let statement = statement.split_whitespace().collect::<Vec<_>>().join(" ");
            for dropped in ["let _ =", ".map(drop)", ".ok()"] {
                assert!(
                    !statement.contains(dropped),
                    "{file}: a Reflect result is dropped (`{dropped}`): {statement}"
                );
            }
        }
    }
}

#[test]
fn the_adapter_reads_no_clock() {
    // Built from pieces so this file does not match itself.
    let banned = [
        ["Date", "::now"].concat(),
        ["Date", "::new"].concat(),
        ["System", "Time"].concat(),
        ["Inst", "ant"].concat(),
        ["perfor", "mance"].concat(),
        ["Date", ".now"].concat(),
    ];
    for (file, text) in sources() {
        for b in &banned {
            assert!(!text.contains(b.as_str()), "{file}: reads a clock ({b})");
        }
    }
}

#[test]
fn no_unsafe_and_no_logging() {
    let banned = [
        ["unsafe", " {"].concat(),
        ["unsafe", " fn"].concat(),
        ["unsafe", " impl"].concat(),
        ["unsafe", " extern"].concat(),
        ["print", "ln!"].concat(),
        ["eprint", "ln!"].concat(),
        ["dbg", "!("].concat(),
        ["cons", "ole"].concat(),
        ["{:", "?}"].concat(),
    ];
    for (file, text) in sources() {
        for b in &banned {
            assert!(!text.contains(b.as_str()), "{file}: contains `{b}`");
        }
    }
    let lib = fs::read_to_string(src_dir().join("lib.rs")).unwrap_or_default();
    assert!(lib.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn every_inventory_operation_is_exported_once() {
    let inventory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../api-inventory.txt");
    let inventory = fs::read_to_string(inventory).unwrap_or_else(|e| unreachable!("{e}"));
    let ops: BTreeSet<String> = inventory
        .lines()
        .filter_map(|l| l.trim().strip_prefix("op "))
        .map(|op| op.trim().to_owned())
        .collect();
    let mut exported = BTreeSet::new();
    for e in exports() {
        assert!(
            exported.insert(e.js_name.clone()),
            "{} exported twice",
            e.js_name
        );
    }
    assert_eq!(
        exported, ops,
        "exports differ from bindings/api-inventory.txt"
    );
}

#[test]
fn the_thumbprint_hash_is_optional_and_passed_through_without_a_default() {
    let thumbprints: Vec<Export> = exports()
        .into_iter()
        .filter(|e| e.js_name == "jwkThumbprint" || e.js_name == "jwkThumbprintUri")
        .collect();
    assert_eq!(thumbprints.len(), 2, "jwkThumbprint and jwkThumbprintUri");
    for e in &thumbprints {
        assert!(
            e.params
                .iter()
                .any(|(n, t)| n == "hash" && t == "Option<String>"),
            "{}: {}: `hash` must be `Option<String>` (ADR 0054 §9)",
            e.file,
            e.js_name
        );
        let body: String = e.body.split_whitespace().collect();
        assert!(
            body.contains("hash.as_deref()"),
            "{}: {}: `hash` goes to the surface as `hash.as_deref()`",
            e.file,
            e.js_name
        );
        for default in ["unwrap_or", "map_or", "SHA-", "sha-", "sha2", "\"sha"] {
            assert!(
                !body.contains(default),
                "{}: {}: the adapter writes no hash default ({default}); the core has it \
                 (ADR 0030 §3)",
                e.file,
                e.js_name
            );
        }
    }
}
