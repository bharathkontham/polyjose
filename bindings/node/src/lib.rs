//! polyjose-node: the napi-rs adapter of `@polyjose/node` (ADR 0030 §1, ADR 0031 §2).
//!
//! A mechanical adapter over `polyjose-surface`: every export is a type conversion and one
//! surface call, with no JSON parsing, policy, defaults or crypto of its own (ADR 0030 §1, "the
//! adapter test"). The exported names, argument order and record fields are the backend contract
//! of the shared JS facade (`bindings/js/BACKEND.md`, `bindings/js/src/backend.ts`); napi-rs
//! turns the `snake_case` Rust names into those `camelCase` names.
//!
//! - [`util`]: `version` and `errorCodes` (synchronous), `base64urlEncode`, `base64urlDecode`;
//! - [`jwk`], [`keys`], [`jws`], [`jwe`], [`jwt`]: the operations, each returning a Promise from
//!   an `AsyncTask` that runs on the libuv pool (ADR 0031 §2, 0007 research §3);
//! - [`records`]: the `#[napi(object)]` mirrors of the surface records, converted with `From`;
//! - [`error`]: [`error::Code`], the stable code on every rejected Promise (ADR 0030 §5).
//!
//! A core failure rejects the Promise with an `Error` whose `code` is the core code and whose
//! `message` is the core text. napi's own argument-conversion failures (a number for a string, a
//! `null` field, a missing required field) are thrown synchronously with napi's codes
//! (`StringExpected`, `InvalidArg`), before a Promise exists; the facade type-checks first and
//! maps those to `TypeError` (ADR 0031 §1, research §2, §3).
//!
//! # Secrets (ADR 0030 §7, ADR 0031 §2)
//!
//! - **Inputs** are copied on the JS thread into `Zeroizing` task fields (or surface records
//!   whose secret fields are `SecretString`/`SecretBytes`), which wipe when the task drops after
//!   `resolve`. `compute` never reads borrowed JS memory. A JS string arrives as one Rust-owned
//!   `String` (napi copies it once), which is moved, not copied, into its zeroizing owner.
//! - **Outputs** that are secret are created by copying from a borrow of the surface's zeroizing
//!   buffer (`env.create_string`, `Uint8ArraySlice::copy_from`), never by handing an owned
//!   `String`/`Vec<u8>` to napi, so no un-wiped Rust copy remains. JS strings are immutable and
//!   cannot be wiped (ADR 0030 §7.4).
//! - **Residual, on the misuse path only:** napi converts the arguments, and the fields of a
//!   record, one after another before the function body runs. When a later one fails to convert
//!   (a host type error), the secret `String`s already converted (a `key` argument, or the keys
//!   of earlier `JwsSigner`/`JweRecipient` entries) are dropped by napi's generated code without
//!   being wiped. The facade's type checks run first, so a call through `@polyjose/node` does not
//!   reach this path. Closing it needs a hand-written `unsafe` `FromNapiValue`, which this crate
//!   does not have. To keep the window small, the secrets are converted last: `key` is declared
//!   last in `JwsSigner` and `JweRecipient`, and `recipients` last in `JweEncryptOptions`, so no
//!   other field of the options (`aad`, `compress`, …) can fail after a recipient key has been
//!   converted (review-code.md N1). A failure inside the recipients array, or in a later
//!   argument, still drops the keys converted before it.
//! - Nothing is logged, and no hand-written `unsafe` exists; the only `unsafe` is what
//!   napi-derive generates.

pub mod error;
pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod keys;
pub mod records;
mod task;
pub mod util;

#[cfg(test)]
pub(crate) mod tests {
    use zeroize::ZeroizeOnDrop;

    /// RFC 7517 Appendix A.2: a P-256 private key (with `use` and `kid`).
    pub(crate) const RFC7517_A2_P256_PRIVATE: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}"#;

    /// Compiles only if `value`'s type wipes itself on drop (ADR 0030 §7.7: the secret-input
    /// path compiles to a zeroizing owner).
    pub(crate) fn wipes_on_drop<T: ZeroizeOnDrop>(_value: &T) {}

    /// Every source file of the crate, for the source checks below.
    const SOURCES: [(&str, &str); 11] = [
        ("lib.rs", include_str!("lib.rs")),
        ("error.rs", include_str!("error.rs")),
        ("task.rs", include_str!("task.rs")),
        ("records.rs", include_str!("records.rs")),
        ("util.rs", include_str!("util.rs")),
        ("jwk.rs", include_str!("jwk.rs")),
        ("keys.rs", include_str!("keys.rs")),
        ("jws.rs", include_str!("jws.rs")),
        ("jwe.rs", include_str!("jwe.rs")),
        ("jwt.rs", include_str!("jwt.rs")),
        ("../build.rs", include_str!("../build.rs")),
    ];

    /// Tasks whose result the API does not classify as secret, so they may resolve through
    /// `String` or the JWT records: tokens, JSON serializations, thumbprints, a public JWK
    /// (ADR 0030 §4, §7), and the JWT claims and headers, plain for 0.1.0 (ADR 0058, owner
    /// decision 2). Every other task must resolve through `SecretString`, `SecretBytes` or a
    /// record that copies its secret fields.
    ///
    /// This list is the classification, not the wiping: since review-code.md SF-6 these results
    /// are wiped too. `ToJs for String` and the JWT records move every string into a `Zeroizing`
    /// owner and copy it into V8 from the borrow, so no task hands napi an owned `String`
    /// (`no_task_resolves_with_an_owned_string`).
    const NON_SECRET_TASKS: [&str; 14] = [
        "JwkToPublicTask",
        "JwkThumbprintTask",
        "JwkThumbprintUriTask",
        "JwsSignCompactTask",
        "JwsSignFlattenedTask",
        "JwsSignGeneralTask",
        "JweEncryptCompactTask",
        "JweEncryptJsonTask",
        "JwtSignTask",
        "JwtEncryptNestedTask",
        // The JWT results: records of strings the API leaves plain (claims and headers,
        // ADR 0030 §4, ADR 0058 owner decision 2), wiped by the adapter all the same.
        "JwtVerifyTask",
        "JwtVerifyWithJwksTask",
        "JwtDecryptNestedTask",
        "JwtDecryptNestedWithJwksTask",
    ];

    /// The result types a secret-output task may resolve through: each builds its JS value by
    /// copying from a borrow (`env.create_string`, `Uint8ArraySlice::copy_from`).
    const SECRET_OUTPUTS: [&str; 4] = [
        "SecretString",
        "SecretBytes",
        "surface::JwsVerified",
        "surface::JweDecrypted",
    ];

    /// `(task name, result type)` of every `surface_task!` in the crate.
    fn declared_tasks() -> Vec<(String, String)> {
        let mut tasks = Vec::new();
        for (file, text) in SOURCES {
            for (start, _) in text.match_indices(concat!("surface_task!", " {\n")) {
                let body = &text[start..];
                let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
                let name = body
                    .lines()
                    .skip(1)
                    .map(str::trim)
                    .find(|line| !line.starts_with("///") && !line.starts_with("#["))
                    .and_then(|line| line.split([' ', '{']).next())
                    .unwrap_or_else(|| panic!("{file}: a surface_task! without a name"));
                let out = body
                    .split_once("} -> ")
                    .map(|(_, rest)| rest.lines().next().unwrap_or("").trim())
                    .unwrap_or_else(|| panic!("{file}: {name} has no result type"));
                tasks.push((name.to_owned(), out.to_owned()));
            }
        }
        tasks
    }

    /// The field names of `pub struct <name>` in `text`, in declaration order.
    fn struct_fields(text: &str, name: &str) -> Vec<String> {
        let header = format!("pub struct {name}");
        let start = text
            .match_indices(&header)
            .map(|(i, _)| i)
            .find(|&i| text[i + header.len()..].starts_with([' ', '<']))
            .unwrap_or_else(|| panic!("no `{header}`"));
        let body = &text[start..];
        let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
        body.lines()
            .skip(1)
            .map(str::trim)
            .filter_map(|line| line.strip_prefix("pub "))
            .filter_map(|line| line.split_once(':').map(|(field, _)| field.to_owned()))
            .collect()
    }

    #[test]
    fn secret_inputs_are_declared_last() {
        // napi-derive converts the fields of a `#[napi(object)]` input in declaration order, and a
        // failing conversion drops the fields already converted unwiped (the module docs'
        // misuse-path residual). The secret key `String`s, and the recipients that hold them,
        // come last, so every other field is converted first (review-code.md N1).
        let records = include_str!("records.rs");
        for (record, last) in [
            ("JwsSigner", "key"),
            ("JweRecipient", "key"),
            ("JweEncryptOptions", "recipients"),
        ] {
            let fields = struct_fields(records, record);
            assert!(fields.len() > 1, "{record}: {fields:?}");
            assert_eq!(
                fields.last().map(String::as_str),
                Some(last),
                "{record} declares `{last}` last: {fields:?}"
            );
        }
    }

    #[test]
    fn no_hand_written_unsafe() {
        // The needles are split with concat! so this test does not match itself.
        let needles = [
            concat!("unsafe", " {"),
            concat!("unsafe", " fn"),
            concat!("unsafe", " impl"),
            concat!("allow(", "unsafe"),
            concat!("expect(", "unsafe"),
        ];
        for (file, text) in SOURCES {
            for needle in needles {
                assert!(!text.contains(needle), "{file} contains `{needle}`");
            }
        }
    }

    #[test]
    fn no_owned_buffer_is_handed_to_napi() {
        // ADR 0030 §7.2: these give napi a Rust allocation that is then never wiped (0007
        // research §4). Secret and non-secret outputs alike are built by copying from a borrow.
        let needles = [
            concat!("Buffer", "::from("),
            concat!("Buffer", "::new("),
            concat!("Uint8Array", "::new("),
            concat!("Uint8Array", "::from("),
            concat!("ArrayBuffer", "::from_data("),
            concat!("BufferSlice", "::from_data("),
            concat!("Uint8ArraySlice", "::from_data("),
            concat!("create_string", "_from_std("),
            concat!("create_buffer", "_with_data("),
            concat!("create_arraybuffer", "_with_data("),
        ];
        for (file, text) in SOURCES {
            for needle in needles {
                assert!(!text.contains(needle), "{file} contains `{needle}`");
            }
        }
    }

    #[test]
    fn secret_outputs_never_resolve_as_a_plain_string() {
        let tasks = declared_tasks();
        // 31 operations plus the test task of task.rs; version and errorCodes are synchronous.
        assert_eq!(tasks.len(), 32, "{tasks:?}");
        for (name, out) in &tasks {
            if NON_SECRET_TASKS.contains(&name.as_str()) {
                continue;
            }
            assert!(
                SECRET_OUTPUTS.contains(&out.as_str()),
                "{name} resolves through `{out}`: a task not listed as non-secret must resolve \
                 through one of {SECRET_OUTPUTS:?}"
            );
        }
        for name in NON_SECRET_TASKS {
            assert!(
                tasks.iter().any(|(task, _)| task == name),
                "{name} is listed as non-secret but not declared"
            );
        }
    }

    /// The text of the block that starts at `header` in `text`, up to its closing `}` at column 0.
    fn block<'t>(text: &'t str, header: &str) -> &'t str {
        let start = text.find(header).unwrap_or_else(|| panic!("no `{header}`"));
        let body = &text[start..];
        &body[..body.find("\n}\n").unwrap_or(body.len())]
    }

    /// `(name, [(field, type)])` of every output record of records.rs (`object_from_js = false`).
    fn output_records(records: &str) -> Vec<(String, Vec<(String, String)>)> {
        let marker = concat!("#[napi(object, ", "object_from_js = false)]\npub struct ");
        records
            .match_indices(marker)
            .map(|(i, _)| {
                let rest = &records[i + marker.len()..];
                let name = rest.split(['<', ' ']).next().unwrap_or_default().to_owned();
                let fields = block(rest, &name)
                    .lines()
                    .skip(1)
                    .map(str::trim)
                    .filter_map(|line| line.strip_prefix("pub "))
                    .filter_map(|line| line.split_once(": "))
                    .map(|(field, ty)| (field.to_owned(), ty.trim_end_matches(',').to_owned()))
                    .collect();
                (name, fields)
            })
            .collect()
    }

    #[test]
    fn no_task_resolves_with_an_owned_string() {
        // review-code.md SF-6: napi copies an owned `String` into V8 and then frees it unwiped, and
        // a token embeds base64url(payload), which ADR 0049 §4 treats as secret. So every string
        // result, whatever its classification (ADR 0058 owner decision 2 leaves JWT claims plain
        // in the API), is moved into a `Zeroizing` owner and copied into V8 from a borrow; the JS
        // type stays `string`.
        let task = include_str!("task.rs");
        let string = block(task, concat!("impl<'env> ToJs<'env> for ", "String {"));
        for line in [
            "type Js = JsString<'env>;",
            "let value = Zeroizing::new(self);",
            "env.create_string(value.as_str())",
        ] {
            assert!(
                string.contains(line),
                "ToJs for String lacks `{line}`:\n{string}"
            );
        }
        for (file, text) in SOURCES {
            for needle in [
                concat!("type Js = ", "String;"),
                concat!("_env: &'env ", "Env"),
            ] {
                assert!(!text.contains(needle), "{file} contains `{needle}`");
            }
        }

        let records = include_str!("records.rs");
        let outputs = output_records(records);
        let names: Vec<&str> = outputs.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "JwsVerified",
                "JweDecrypted",
                "JwtVerified",
                "JwtNestedVerified"
            ]
        );
        for (name, fields) in &outputs {
            let to_js = block(
                records,
                &format!("impl<'env> ToJs<'env> for surface::{name} {{"),
            );
            assert!(
                to_js.contains(&format!("type Js = {name}<'env>;")),
                "{name}: its ToJs builds the JS record with the env"
            );
            for (field, ty) in fields {
                assert!(
                    !ty.replace("JsString", "").contains("String"),
                    "{name}.{field}: `{ty}` hands an owned String to napi"
                );
                if !ty.contains("JsString") {
                    continue;
                }
                let moved = [
                    format!("Zeroizing::new(self.{field})"),
                    format!("self.{field}.map(Zeroizing::new)"),
                ];
                assert!(
                    moved.iter().any(|m| to_js.contains(m.as_str())),
                    "{name}.{field}: the surface string is not moved into a Zeroizing owner"
                );
            }
        }
    }

    #[test]
    fn secret_record_fields_are_copied_slices() {
        let records = include_str!("records.rs");
        for field in [
            "pub payload: Uint8ArraySlice<'env>,",
            "pub plaintext: Uint8ArraySlice<'env>,",
            "pub aad: Option<Uint8ArraySlice<'env>>,",
            "payload: Uint8ArraySlice::copy_from(env, self.payload.as_bytes())?,",
            "plaintext: Uint8ArraySlice::copy_from(env, self.plaintext.as_bytes())?,",
            ".map(|aad| Uint8ArraySlice::copy_from(env, aad.as_bytes()))",
        ] {
            assert!(records.contains(field), "records.rs lacks `{field}`");
        }
        let task = include_str!("task.rs");
        for conversion in [
            "env.create_string(self.as_str())",
            "env.create_string(value.as_str())",
            "Uint8ArraySlice::copy_from(env, self.as_bytes())",
        ] {
            assert!(task.contains(conversion), "task.rs lacks `{conversion}`");
        }
    }
}
