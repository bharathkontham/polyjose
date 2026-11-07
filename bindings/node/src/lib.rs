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
//! # The facade is the safety boundary
//!
//! `@polyjose/node`'s public API is the shared facade (`index.js`, ADR 0031 §1). This backend,
//! `binding.cjs`, ships in the package because the facade loads it, but it is **not a supported
//! API**: it checks only what napi's conversions check, and trusts the facade for the rest
//! (`bindings/js/BACKEND.md`). Called directly, it:
//! - **wraps integers** (review-code.md N8): napi converts every `u32` and `i64` field with
//!   Node-API's own coercion, so `-1` becomes `4294967295`, `2**32` becomes `0` and `1.5` is
//!   truncated. The facade checks every size, count and `now` first;
//! - **does not check shape or attachment** (review-security.md I3): a detached `Uint8Array` is
//!   read as empty input, and a primitive where a record belongs reads as an empty record. The
//!   facade refuses both with a `TypeError`;
//! - **assumes plain data** (review-security.md L1): a record with getters or a `Proxy` runs JS
//!   while napi converts the arguments. The adapter makes that safe for the bytes it reads: each
//!   byte argument is copied before any record is read, and each byte field as napi hands it
//!   over ([`records`]), so a getter that detaches and frees a byte argument cannot make it read
//!   freed memory. It does not make such objects supported. The facade snapshots every byte input
//!   and builds fresh plain records before the backend is reached (0013 B06).
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
//! - **Residual, on the misuse path only:** napi converts the positional arguments one after
//!   another before the function body runs. When a later one fails to convert (a host type
//!   error), the secret `String`s already converted (a `token` or `key` argument) are dropped by
//!   napi's generated code without being wiped. The facade's type checks run first, so a call
//!   through `@polyjose/node` does not reach this path. Closing it needs a hand-written `unsafe`
//!   `FromNapiValue`, which this crate does not have. The records read by hand
//!   ([`records`]: `JwsSigner`, `JweRecipient`, `JweEncryptOptions`, …) do not add to it: their
//!   functions take them as an `Object`, whose conversion cannot fail, move every string
//!   argument into its zeroizing owner before reading them, and move each record key into a
//!   `SecretString` as it is read, last in its record (review-code.md N1,
//!   review-security.md L1). So a failing field drops nothing secret unwiped.
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
        // The secret key `String`s, and the recipients that hold them, are declared last, so
        // `binding.d.ts` lists them last and the readers below read them last
        // (review-code.md N1; `records_that_meet_bytes_are_read_by_hand`).
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

    /// The JS names of the fields of `pub struct <name>` (napi's camelCase, or its `js_name`),
    /// each with whether its type holds bytes.
    fn struct_js_fields(text: &str, name: &str) -> Vec<(String, bool)> {
        let header = format!("pub struct {name}");
        let start = text
            .match_indices(&header)
            .map(|(i, _)| i)
            .find(|&i| text[i + header.len()..].starts_with([' ', '<']))
            .unwrap_or_else(|| panic!("no `{header}`"));
        let mut js_name = None;
        let mut fields = Vec::new();
        for line in block(&text[start..], &header)
            .lines()
            .skip(1)
            .map(str::trim)
        {
            if let Some(rest) = line.strip_prefix(concat!("#[napi(js_name = ", "\"")) {
                js_name = rest.split('"').next().map(str::to_owned);
            } else if let Some((field, ty)) =
                line.strip_prefix("pub ").and_then(|l| l.split_once(": "))
            {
                let camel = field
                    .split('_')
                    .enumerate()
                    .map(|(i, part)| {
                        let mut chars = part.chars();
                        match (i, chars.next()) {
                            (0, _) | (_, None) => part.to_owned(),
                            (_, Some(c)) => c.to_ascii_uppercase().to_string() + chars.as_str(),
                        }
                    })
                    .collect::<String>();
                fields.push((
                    js_name.take().unwrap_or(camel),
                    ty.contains("Uint8ArraySlice"),
                ));
            }
        }
        fields
    }

    #[test]
    fn records_that_meet_bytes_are_read_by_hand() {
        // review-security.md L1: every property read can run a JS getter, which can detach and
        // free a byte argument napi has already captured as a view. So these records are not
        // converted by napi-derive at all (`object_from_js = false` makes that a compile error);
        // their functions take a plain `Object` and read them with the `read` functions.
        let records = include_str!("records.rs");
        for record in [
            "JwsSignOptions",
            "JwsSigner",
            "JwsVerifyOptions",
            "JweRecipient",
            "JweEncryptOptions",
        ] {
            let declaration = concat!(
                "#[napi(object, object_to_js = false, ",
                "object_from_js = false)]\npub struct "
            );
            assert!(
                records.contains(&format!("{declaration}{record} "))
                    || records.contains(&format!("{declaration}{record}<")),
                "{record} is declared for its type only"
            );
            // Each reader reads exactly the declared JS fields, the byte fields first (each copied
            // by `copied_bytes` as it is read) and a secret key or the recipients last.
            let reader = block(records, &format!("impl {record}"));
            let reader = &reader[..reader
                .find("pub(crate) fn read_all")
                .unwrap_or(reader.len())];
            let read: Vec<&str> = reader.split('"').skip(1).step_by(2).collect();
            let fields = struct_js_fields(records, record);
            let mut declared: Vec<&str> = fields.iter().map(|(f, _)| f.as_str()).collect();
            let mut sorted = read.clone();
            declared.sort_unstable();
            sorted.sort_unstable();
            assert_eq!(
                sorted, declared,
                "{record}: the reader reads every declared field once"
            );
            let bytes = fields.iter().filter(|(_, b)| *b).count();
            for (i, name) in read.iter().enumerate() {
                let is_bytes = fields.iter().any(|(f, b)| f == name && *b);
                assert_eq!(
                    is_bytes,
                    i < bytes,
                    "{record}: `{name}` is read in the wrong place: {read:?}"
                );
                if is_bytes {
                    assert!(
                        reader.contains(&format!("copied_bytes(obj, \"{name}\")")),
                        "{record}.{name}"
                    );
                }
            }
            if let Some(last) = ["key", "recipients"].into_iter().find(|s| read.contains(s)) {
                assert_eq!(
                    read.last(),
                    Some(&last),
                    "{record}: `{last}` is read last: {read:?}"
                );
            }
        }
        assert_eq!(
            records
                .matches(r#"key: SecretString::from(required::<String>(obj, "key")?),"#)
                .count(),
            2,
            "each record key moves straight into its zeroizing owner"
        );

        // Every function that reads such a record copies its byte argument, and moves every
        // string argument into its owner, before the first property read.
        let mut functions = 0;
        for (file, text) in SOURCES {
            for (start, _) in text.match_indices("#[napi]\npub fn ") {
                let function = block(&text[start..], "#[napi]");
                let (signature, body) = function.split_once(") -> ").unwrap_or((function, ""));
                if !signature.contains("Object<'_>") && !signature.contains("Array<'_>") {
                    continue;
                }
                functions += 1;
                let name = signature.split(['(', '\n']).nth(1).unwrap_or(signature);
                assert!(
                    !signature.contains("&[u8]"),
                    "{file} {name}: bytes as a Uint8ArraySlice"
                );
                let first_read = body
                    .find("::read")
                    .unwrap_or_else(|| panic!("{file} {name}: no record read"));
                let owners = body[..first_read].matches("Zeroizing::new(").count();
                // The arguments before the record: the payload or plaintext, and the token and
                // key strings (a later `form` or `detached` is not secret).
                let before = &signature[..signature
                    .find("#[napi(ts_arg_type")
                    .unwrap_or(signature.len())];
                let arguments = before.matches(": String").count()
                    + before.matches(": Uint8ArraySlice").count();
                assert_eq!(
                    owners, arguments,
                    "{file} {name}: every byte and string argument before the record is owned \
                     before the record is read"
                );
                assert!(
                    !body[first_read..].contains("Zeroizing::new("),
                    "{file} {name}"
                );
            }
        }
        assert_eq!(
            functions, 8,
            "the sign, verify and encrypt functions that take a record"
        );
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
