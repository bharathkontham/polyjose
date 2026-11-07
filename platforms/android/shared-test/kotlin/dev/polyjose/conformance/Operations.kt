package dev.polyjose.conformance

import dev.polyjose.JweDecryptOptions
import dev.polyjose.JweEncryptOptions
import dev.polyjose.JweRecipient
import dev.polyjose.JwkSelector
import dev.polyjose.JwsSignOptions
import dev.polyjose.JwsSigner
import dev.polyjose.JwsVerifyOptions
import dev.polyjose.JwtSignOptions
import dev.polyjose.JwtVerified
import dev.polyjose.JwtVerifyOptions
import dev.polyjose.PolyjoseException
import dev.polyjose.base64urlDecode
import dev.polyjose.base64urlEncode
import dev.polyjose.jweDecryptCompact
import dev.polyjose.jweDecryptJson
import dev.polyjose.jweEncryptCompact
import dev.polyjose.jweEncryptJson
import dev.polyjose.jwkFromDer
import dev.polyjose.jwkFromPem
import dev.polyjose.jwkGenerateEc
import dev.polyjose.jwkGenerateForAlg
import dev.polyjose.jwkGenerateOct
import dev.polyjose.jwkGenerateOkp
import dev.polyjose.jwkParse
import dev.polyjose.jwkThumbprint
import dev.polyjose.jwkThumbprintUri
import dev.polyjose.jwkToDer
import dev.polyjose.jwkToPem
import dev.polyjose.jwkToPublic
import dev.polyjose.jwksSelect
import dev.polyjose.jwsSignCompact
import dev.polyjose.jwsSignFlattened
import dev.polyjose.jwsSignGeneral
import dev.polyjose.jwsVerifyCompact
import dev.polyjose.jwsVerifyJson
import dev.polyjose.jwtDecryptNested
import dev.polyjose.jwtDecryptNestedWithJwks
import dev.polyjose.jwtEncryptNested
import dev.polyjose.jwtSign
import dev.polyjose.jwtVerify
import dev.polyjose.jwtVerifyWithJwks

private typealias Obj = Map<String, Any?>
private typealias Out = MutableMap<String, Any?>
private typealias Handler = (input: Obj, expect: Obj, text: JsonText, out: Out) -> Unit

/**
 * The vector operations mapped to the generated Kotlin API, one handler per schema operation, each
 * mirroring the JS runner's handler and the Rust runner's function of the same name. The calls are
 * exactly those of conformance/README.md "Operation mapping", in its order, with no call of the
 * runner's own before them. JSON-valued inputs go to the library as their own text
 * ([JsonText.at]); record fields a vector doesn't set stay unset, so the core default applies
 * (ADR 0030 §3). An operation not in [HANDLERS] fails, never skips (ADR 0034 §3).
 */
internal object Operations {
    /** The payload or plaintext of every `use_with` round trip: the ASCII octets of `polyjose` (ADR 0034 §6). */
    private val USE_WITH_PAYLOAD = "polyjose".toByteArray(Charsets.US_ASCII)

    /** The members a generated private key has (RFC 7518 §6.2.1-§6.2.2, RFC 8037 §2, RFC 7518 §6.4.1), plus `alg`. */
    private val GENERATED_MEMBERS = mapOf(
        "EC" to listOf("alg", "crv", "d", "kty", "x", "y"),
        "OKP" to listOf("alg", "crv", "d", "kty", "x"),
        "oct" to listOf("alg", "k", "kty"),
    )

    /** [GENERATED_MEMBERS] of a key bound to no algorithm (`jwkGenerateOct`, `Ec`, `Okp`): no `alg`. */
    private val UNBOUND_MEMBERS = GENERATED_MEMBERS.mapValues { (_, names) -> names - "alg" }

    /** Runs the vector's operation: a `PolyjoseException` is the outcome; anything else propagates (a fail). */
    fun execute(vector: Obj, text: JsonText): Outcome {
        val operation = vector["operation"] as String
        val handler = HANDLERS[operation]
            ?: throw HarnessError("operation `$operation` is not implemented by the Kotlin runner; a vector is never skipped")
        val out = LinkedHashMap<String, Any?>()
        return try {
            handler(obj(vector["input"]), obj(vector["expect"]), text, out)
            Outcome.Ok(out)
        } catch (e: LibraryError) {
            Outcome.Err(e.code)
        }
    }

    /** Compares an outcome with the expectation: exactly the expected outputs, as JSON values (Rust `compare`). */
    fun compare(expect: Map<*, *>, outcome: Outcome): String? {
        if (expect["ok"] == true) {
            if (outcome is Outcome.Err) return "expected success, got error ${outcome.code}"
            val out = (outcome as Outcome.Ok).out
            for ((name, want) in expect) {
                if (name == "ok") continue
                if (!out.containsKey(name)) return "`$name`: expected ${toJson(want)}, got nothing"
                if (!jsonEqual(want, out[name])) return "`$name`: expected ${toJson(want)}, got ${toJson(out[name])}"
            }
            for (name in out.keys) {
                if (!expect.containsKey(name)) return "`$name`: expected nothing, got ${toJson(out[name])}"
            }
            return null
        }
        return when (outcome) {
            is Outcome.Ok -> "expected error ${expect["error"]}, but the operation succeeded with ${toJson(outcome.out)}"
            is Outcome.Err -> if (outcome.code == expect["error"]) null else "expected error ${expect["error"]}, got error ${outcome.code}"
        }
    }

    /**
     * The rules tying members together that the schema can't state, as the Rust runner's
     * `check_jwe_encrypt_features` and `check_jwt_issue` and the JS runner's `crossMemberRules`
     * check them (conformance/README.md; ADR 0056 §3-§4).
     */
    fun crossMemberRules(vector: Obj) {
        val input = obj(vector["input"])
        val expect = obj(vector["expect"])
        val features = strs(vector["features"] ?: emptyList<String>())
        val absent = strs(vector["features_absent"] ?: emptyList<String>())
        absent.firstOrNull { it in features }?.let { throw HarnessError("/features_absent: \"$it\" is listed in `features` too") }
        if (vector["operation"] == "jwe.encrypt") {
            for (member in listOf("rng_b64u", "protected_b64u")) {
                if (input.containsKey(member) && "fixed-rng" !in features) {
                    throw HarnessError("/features: `input/$member` needs \"fixed-rng\" listed in `features`")
                }
            }
            if (input.containsKey("compress") && "deflate" !in features && "deflate" !in absent) {
                throw HarnessError("/features: `input/compress` needs \"deflate\" listed in `features` or `features_absent`")
            }
        }
        if (vector["operation"] == "jwt.issue") {
            val encrypt = input.containsKey("encrypt")
            val validate = input.containsKey("validate")
            if (expect["ok"] == true && expect.containsKey("token") && encrypt) {
                throw HarnessError("/expect/token: an encrypted token is randomized (RFC 7516 §5.1); expect {\"ok\": true} and give `validate`")
            }
            if (expect["ok"] == true && !expect.containsKey("token") && !validate && !encrypt) {
                throw HarnessError("/input/validate: required when the expectation has no `token`")
            }
            if (expect["ok"] == false && validate) {
                throw HarnessError("/input/validate: used only when the issue succeeds, so a failure vector has none")
            }
        }
    }

    private val HANDLERS: Map<String, Handler> = mapOf(
        // b64url.encode → base64urlEncode(hex-decoded bytes_hex); RFC 4648 §5.
        "b64url.encode" to { input, _, _, out ->
            out["b64u"] = lib { base64urlEncode(hexDecode(str(input["bytes_hex"]))) }
        },
        // b64url.decode → base64urlDecode(b64u), as lowercase hex; RFC 4648 §5.
        "b64url.decode" to { input, _, _, out ->
            out["bytes_hex"] = hexEncode(lib { base64urlDecode(str(input["b64u"])) })
        },
        // jwk.thumbprint → jwkThumbprint + jwkThumbprintUri (RFC 7638 §3, RFC 9278 §3). `hash` is
        // passed exactly as given, an absent one as absent (the core default SHA-256; ADR 0054 §8.2, §9).
        "jwk.thumbprint" to { input, _, text, out ->
            val hash = if (input.containsKey("hash")) str(input["hash"]) else null
            val jwk = text.at("input", "jwk")
            out["thumbprint"] = lib { jwkThumbprint(jwk, hash) }
            out["thumbprint_uri"] = lib { jwkThumbprintUri(jwk, hash) }
        },
        // jwks.select → jwksSelect(jwks, JwkSelector { kid, alg, keyUse }) (RFC 7517 §5; ADR 0054 §1-§4,
        // §9): the set as its own text, each selector member only when present, as given.
        "jwks.select" to { input, _, text, out ->
            val criteria = obj(input["selector"])
            val selector = JwkSelector(
                kid = criteria["kid"]?.let(::str),
                alg = criteria["alg"]?.let(::str),
                keyUse = criteria["key_use"]?.let(::str),
            )
            val jwks = text.at("input", "jwks")
            out["jwk"] = parseOutput(lib { jwksSelect(jwks, selector) }, "the selected JWK")
        },

        // jws.sign → jwsSignCompact / jwsSignFlattened / jwsSignGeneral (RFC 7515 §5.1, §7).
        "jws.sign" to { input, expect, text, out -> jwsSign(input, expect, text, out) },
        // jws.verify → jwsVerifyCompact (string) / jwsVerifyJson (object, as its text); RFC 7515 §5.2.
        "jws.verify" to { input, _, text, out ->
            val key = text.at("input", "key")
            val options = JwsVerifyOptions(allowedAlgs = strs(input["allowed_algs"]))
            if (input.containsKey("detached_payload_b64u")) {
                options.detachedPayload = decode(input["detached_payload_b64u"], "detached_payload_b64u")
            }
            input["max_input_len"]?.let { options.maxInputLen = count(it, "max_input_len") }
            input["max_signatures"]?.let { options.maxSignatures = count(it, "max_signatures") }
            val jws = input["jws"]
            val verified = lib {
                if (jws is String) jwsVerifyCompact(jws, key, options) else jwsVerifyJson(text.at("input", "jws"), key, options)
            }
            out["payload_b64u"] = base64urlEncode(verified.payload)
            out["alg"] = verified.alg
            out["signature_index"] = verified.signatureIndex.toLong()
        },

        // keys.import_pem → jwkFromPem (ADR 0018 §3).
        "keys.import_pem" to { input, _, _, out ->
            out["jwk"] = imported(lib { jwkFromPem(str(input["pem"])) })
        },
        // keys.import_der → jwkFromDer(decoded der_b64u, format) (ADR 0018 §3).
        "keys.import_der" to { input, _, _, out ->
            val der = decode(input["der_b64u"], "der_b64u")
            out["jwk"] = imported(lib { jwkFromDer(der, str(input["format"])) })
        },
        // keys.export_pem → jwkToPem(jwk, format); the JWK import inside is the first step.
        "keys.export_pem" to { input, _, text, out ->
            out["pem"] = lib { jwkToPem(text.at("input", "jwk"), str(input["format"])) }
        },
        // keys.export_der → jwkToDer(jwk, format), as base64url.
        "keys.export_der" to { input, _, text, out ->
            out["der_b64u"] = base64urlEncode(lib { jwkToDer(text.at("input", "jwk"), str(input["format"])) })
        },
        // keys.generate_for → jwkGenerateForAlg(alg) (ADR 0018 §5), then `use_with` when present (ADR 0034 §6).
        "keys.generate_for" to { input, expect, _, out ->
            val jwk = lib { jwkGenerateForAlg(str(input["alg"])) }
            out["shape"] = generatedShape(jwk, GENERATED_MEMBERS)
            echoUseWith(jwk, expect, out)
        },
        // keys.generate_oct → jwkGenerateOct(len_bytes) (RFC 7518 §6.4.1; ADR 0030 §4).
        "keys.generate_oct" to { input, expect, _, out ->
            val jwk = lib { jwkGenerateOct(count(input["len_bytes"], "len_bytes")) }
            out["shape"] = generatedShape(jwk, UNBOUND_MEMBERS)
            echoUseWith(jwk, expect, out)
        },
        // keys.generate_ec → jwkGenerateEc(crv) (RFC 7518 §6.2, RFC 8812 §3.1; ADR 0030 §4).
        "keys.generate_ec" to { input, expect, _, out ->
            val jwk = lib { jwkGenerateEc(str(input["crv"])) }
            out["shape"] = generatedShape(jwk, UNBOUND_MEMBERS)
            echoUseWith(jwk, expect, out)
        },
        // keys.generate_okp → jwkGenerateOkp(crv) (RFC 8037 §2; ADR 0030 §4).
        "keys.generate_okp" to { input, expect, _, out ->
            val jwk = lib { jwkGenerateOkp(str(input["crv"])) }
            out["shape"] = generatedShape(jwk, UNBOUND_MEMBERS)
            echoUseWith(jwk, expect, out)
        },

        // jwe.encrypt → jweEncryptCompact / jweEncryptJson(form) (RFC 7516 §5.1, §7).
        "jwe.encrypt" to { input, expect, text, out -> jweEncrypt(input, expect, text, out) },
        // jwe.decrypt → jweDecryptCompact (string) / jweDecryptJson (object, as its text); RFC 7516 §5.2.
        "jwe.decrypt" to { input, _, text, out ->
            val key = text.at("input", "key")
            val options = jweDecryptOptions(input)
            val jwe = input["jwe"]
            val decrypted = lib {
                if (jwe is String) jweDecryptCompact(jwe, key, options) else jweDecryptJson(text.at("input", "jwe"), key, options)
            }
            out["plaintext_b64u"] = base64urlEncode(decrypted.plaintext)
            out["recipient"] = decrypted.recipientIndex.toLong()
        },

        // jwt.validate → jwtVerify / jwtVerifyWithJwks, or jwtDecryptNested(WithJwks) with `decrypt` (RFC 7519 §7.2).
        "jwt.validate" to { input, _, text, out ->
            val verified = jwtValidate(input, listOf("input"), str(input["token"]), text)
            out["claims"] = parseOutput(verified.claims, "the validated claims")
            out["alg"] = verified.alg
            // ADR 0029 §4: present exactly when a key set verified; 0 is an index, not "absent" (note 2).
            verified.keyIndex?.let { out["key_index"] = it.toLong() }
        },
        // jwt.issue → jwtSign, then jwtEncryptNested with `encrypt` (RFC 7519 §7.1; ADR 0027 §7-§8).
        "jwt.issue" to { input, expect, text, out -> jwtIssue(input, expect, text, out) },
    )

    private fun jwsSign(input: Obj, expect: Obj, text: JsonText, out: Out) {
        val serialization = str(input["serialization"])
        val payload = decode(input["payload_b64u"], "payload_b64u")
        val detached = input["detached"] == true
        val signers = list(input["signers"]).mapIndexed { i, s ->
            val signer = obj(s)
            JwsSigner(
                key = text.at("input", "signers", i, "key"),
                protectedB64u = signer["protected_b64u"] as? String,
                // RFC 7515 §7.2.1; a signer may have only an unprotected header (ADR 0045 §1, note 11).
                unprotectedHeader = text.opt("input", "signers", i, "header"),
            )
        }
        val first = signers.firstOrNull() ?: throw HarnessError("jws.sign: no signers")
        val signed = lib {
            when (serialization) {
                // The header always goes as protectedB64u, never as protectedHeader.
                "compact" -> jwsSignCompact(payload, first.key, JwsSignOptions(protectedB64u = first.protectedB64u, detached = detached))
                "flattened" -> jwsSignFlattened(payload, first, detached)
                else -> jwsSignGeneral(payload, signers, detached)
            }
        }
        val jws: Any? = if (serialization == "compact") signed else parseOutput(signed, "the signed JSON JWS")
        val verifyWith = expect["verify_with"] as? Map<*, *>
        if (verifyWith == null) {
            out["jws"] = jws
            return
        }
        // Round trip (Rust `check_round_trip`): shape, verify with verify_with, same payload.
        val shapeOk = when (serialization) {
            "compact" -> signed.split('.').size == 3
            "flattened" -> jws is Map<*, *> && jws.containsKey("signature") && !jws.containsKey("signatures")
            else -> jws is Map<*, *> && (jws["signatures"] as? List<*>)?.size == signers.size
        }
        if (!shapeOk) throw HarnessError("round trip: the output is not a $serialization JWS with ${signers.size} signature(s)")
        val key = text.at("expect", "verify_with", "key")
        val options = JwsVerifyOptions(allowedAlgs = strs(verifyWith["allowed_algs"]))
        if (detached) options.detachedPayload = payload
        val verified = check("round trip: the signed JWS does not verify with verify_with") {
            if (serialization == "compact") jwsVerifyCompact(signed, key, options) else jwsVerifyJson(signed, key, options)
        }
        if (!verified.payload.contentEquals(payload)) throw HarnessError("round trip: the verified payload is not the signed one")
        out["verify_with"] = verifyWith
    }

    private fun jweEncrypt(input: Obj, expect: Obj, text: JsonText, out: Out) {
        if (input.containsKey("rng_b64u") || input.containsKey("protected_b64u")) {
            throw HarnessError("a reproducible encryption (rng_b64u, protected_b64u) is not in the binding API (ADR 0005)")
        }
        val serialization = str(input["serialization"])
        val plaintext = decode(input["plaintext_b64u"], "plaintext_b64u")
        val recipients = list(input["recipients"]).mapIndexed { i, r ->
            val recipient = obj(r)
            JweRecipient(alg = str(recipient["alg"]), key = text.at("input", "recipients", i, "key")).apply {
                header = text.opt("input", "recipients", i, "header")
                if (recipient.containsKey("apu_b64u")) apu = decode(recipient["apu_b64u"], "apu_b64u")
                if (recipient.containsKey("apv_b64u")) apv = decode(recipient["apv_b64u"], "apv_b64u")
                recipient["p2c"]?.let { p2c = count(it, "p2c") }
                recipient["p2s_len"]?.let { p2sLen = count(it, "p2s_len") }
            }
        }
        val options = JweEncryptOptions(enc = str(input["enc"]), recipients = recipients).apply {
            protectedHeader = text.opt("input", "protected")
            sharedUnprotectedHeader = text.opt("input", "unprotected")
            if (input.containsKey("aad_b64u")) aad = decode(input["aad_b64u"], "aad_b64u")
            if (input["compress"] == true) compress = true
        }
        val encrypted = lib {
            if (serialization == "compact") jweEncryptCompact(plaintext, options) else jweEncryptJson(plaintext, options, serialization)
        }
        val jwe: Any? = if (serialization == "compact") encrypted else parseOutput(encrypted, "the encrypted JSON JWE")
        val decryptWith = expect["decrypt_with"] as? Map<*, *>
        if (decryptWith == null) {
            out["jwe"] = jwe
            return
        }
        // Round trip (Rust `check_jwe_round_trip`): shape, decrypt with decrypt_with, same plaintext.
        val shapeOk = when (serialization) {
            "compact" -> encrypted.split('.').size == 5
            "flattened" -> jwe is Map<*, *> && jwe.containsKey("ciphertext") && !jwe.containsKey("recipients")
            else -> jwe is Map<*, *> && (jwe["recipients"] as? List<*>)?.size == recipients.size
        }
        if (!shapeOk) throw HarnessError("round trip: the output is not a $serialization JWE with ${recipients.size} recipient(s)")
        val key = text.at("expect", "decrypt_with", "key")
        val policy = JweDecryptOptions(allowedAlgs = strs(decryptWith["allowed_algs"]), allowedEnc = strs(decryptWith["allowed_enc"]))
        val decrypted = check("round trip: the encrypted JWE does not decrypt with decrypt_with") {
            if (serialization == "compact") jweDecryptCompact(encrypted, key, policy) else jweDecryptJson(encrypted, key, policy)
        }
        if (!decrypted.plaintext.contentEquals(plaintext)) throw HarnessError("round trip: the decrypted plaintext is not the encrypted one")
        out["decrypt_with"] = decryptWith
    }

    private fun jwtIssue(input: Obj, expect: Obj, text: JsonText, out: Out) {
        // Exactly the calls of the mapping table, in order, none of the runner's own (no jwkParse
        // pre-check): jwtSign (which imports `key`, then parses `claims`), then jwtEncryptNested.
        val key = text.at("input", "key")
        val claims = text.at("input", "claims") // ordered JSON text (ADR 0027 §1, implementer note 4)
        val encrypt = input["encrypt"] as? Map<*, *>
        val encryptKey = if (encrypt == null) null else text.at("input", "encrypt", "key")
        val alg = str(input["alg"])
        val options = JwtSignOptions(alg = alg)
        // `typ`: absent → the core default JWT; null → omitted (RFC 7519 §5.1, note 3); a string → set.
        if (input.containsKey("typ")) {
            val typ = input["typ"]
            if (typ == null) options.omitTyp = true else options.typ = str(typ)
        }
        var token = lib { jwtSign(claims, key, options) }
        var parts = 3
        if (encrypt != null && encryptKey != null) {
            val signed = token
            val recipient = JweRecipient(alg = str(encrypt["alg"]), key = encryptKey)
            token = lib { jwtEncryptNested(signed, JweEncryptOptions(enc = str(encrypt["enc"]), recipients = listOf(recipient))) }
            parts = 5
        }
        if (token.split('.').size != parts) throw HarnessError("the issued token is not $parts compact parts")
        val validate = input["validate"]
        if (validate is Map<*, *>) {
            // Round trip (Rust `check_jwt_issue_round_trip`): validates, with the issued alg and claims (note 10).
            val verified = try {
                jwtValidate(obj(validate), listOf("input", "validate"), token, text)
            } catch (e: LibraryError) {
                throw HarnessError("round trip: the issued token does not validate with `validate` (${e.code})")
            }
            if (verified.alg != alg) throw HarnessError("round trip: validated with alg ${verified.alg}, issued with $alg")
            if (!jsonEqual(parseOutput(verified.claims, "the validated claims"), input["claims"])) {
                throw HarnessError("round trip: validated claims ${verified.claims} are not the issued $claims")
            }
        }
        if (expect["ok"] == true && expect.containsKey("token")) out["token"] = token
    }

    /**
     * Validates [token] with a `jwt.validate` input or a `jwt.issue` `validate` object at [base]
     * (Rust `jwt_validation` + `jwt_verify`): the four forms are chosen by `decrypt` and by `key`
     * vs `jwks` (ADR 0030 §4). A nested JWT's result is its inner JWT.
     */
    private fun jwtValidate(source: Obj, base: List<Any>, token: String, text: JsonText): JwtVerified {
        val options = jwtVerifyOptions(source)
        val decrypt = source["decrypt"] as? Map<*, *>
        val jwks = text.opt(*(base + "jwks").toTypedArray())
        val keys = jwks ?: text.at(*(base + "key").toTypedArray())
        if (decrypt != null) {
            val decryptKey = text.at(*(base + listOf("decrypt", "key")).toTypedArray())
            val decryptOptions = jweDecryptOptions(obj(decrypt))
            return lib {
                if (jwks == null) {
                    jwtDecryptNested(token, decryptKey, decryptOptions, keys, options)
                } else {
                    jwtDecryptNestedWithJwks(token, decryptKey, decryptOptions, keys, options)
                }
            }.inner
        }
        return lib { if (jwks == null) jwtVerify(token, keys, options) else jwtVerifyWithJwks(token, keys, options) }
    }

    /** The decrypt options of `jwe.decrypt` and of a nested JWT's `decrypt` (Rust `jwe_policy`). */
    private fun jweDecryptOptions(source: Obj): JweDecryptOptions =
        JweDecryptOptions(allowedAlgs = strs(source["allowed_algs"]), allowedEnc = strs(source["allowed_enc"])).apply {
            if (source.containsKey("understood_crit")) understoodCrit = strs(source["understood_crit"])
            source["max_input_len"]?.let { maxInputLen = count(it, "max_input_len") }
            source["max_recipients"]?.let { maxRecipients = count(it, "max_recipients") }
            source["max_pbes2_count"]?.let { maxPbes2Count = count(it, "max_pbes2_count") }
            source["max_decompressed_len"]?.let { maxDecompressedLen = count(it, "max_decompressed_len") }
        }

    /**
     * The JWT verify options from `allowed_algs`, `now` and `policy` (Rust `jwt_policy`), member by
     * member (conformance/README.md "policy → JwtVerifyOptions"). `now` is always set: the runner
     * never reads a clock (ADR 0028 §4). An absent member, or a boolean `false`, sets nothing, so
     * the library default stays (implementer note 6).
     */
    private fun jwtVerifyOptions(source: Obj): JwtVerifyOptions {
        val policy = (source["policy"] as? Map<*, *>) ?: emptyMap<String, Any?>()
        val typPolicy = policy["typ"] as? Map<*, *>
        if (policy.containsKey("profile") && typPolicy?.get("mode") == "default") {
            throw HarnessError("`policy/typ/mode` \"default\" contradicts `policy/profile` \"access_token\", which requires typ at+jwt (RFC 9068 §4)")
        }
        return JwtVerifyOptions(allowedAlgs = strs(source["allowed_algs"]), now = seconds(source["now"])).apply {
            policy["issuer"]?.let { issuers = if (it is String) listOf(it) else strs(it) }
            policy["audience"]?.let { audiences = strs(it) }
            policy["subject"]?.let { subject = str(it) }
            policy["leeway"]?.let { leeway = count(it, "policy/leeway") }
            policy["max_age"]?.let { maxAge = count(it, "policy/max_age") }
            policy["require"]?.let { requiredClaims = strs(it) }
            if (policy["allow_missing_exp"] == true) allowMissingExp = true
            if (policy["ignore_audience"] == true) ignoreAudience = true
            if (typPolicy?.get("mode") == "exact") typ = str(typPolicy["value"])
            if (typPolicy?.get("mode") == "any") anyTyp = true
            policy["profile"]?.let { profile = str(it) }
            policy["max_key_candidates"]?.let { maxKeyCandidates = count(it, "policy/max_key_candidates") }
        }
    }

    /** A PEM/DER import result; an `oct` key fails the vector whatever it expects (RFC 8725 §2.1). */
    private fun imported(jwk: String): Any? {
        val value = parseOutput(jwk, "the imported JWK")
        if ((value as? Map<*, *>)?.get("kty") == "oct") throw HarnessError("a PEM or DER import returned an oct key (RFC 8725 §2.1)")
        return value
    }

    /** Rust `generated_shape`: private, exactly the RFC members of [members], imports back unchanged; then the shape. */
    private fun generatedShape(jwkText: String, members: Map<String, List<String>>): Obj {
        val jwk = obj(parseOutput(jwkText, "the generated JWK"))
        val kty = jwk["kty"] as? String ?: ""
        if (!(kty == "oct" || jwk.containsKey("d"))) throw HarnessError("the generator returned a public key")
        val names = jwk.keys.sorted()
        if (members[kty] != names) throw HarnessError("the generator returned a JWK with members ${toJson(names)}")
        val again = check("the generated JWK does not import") { jwkParse(jwkText) }
        if (!jsonEqual(parseOutput(again, "the re-imported JWK"), jwk)) throw HarnessError("the generated JWK imports as a different key")
        val shape = LinkedHashMap<String, Any?>()
        for (name in listOf("kty", "crv", "alg")) if (jwk.containsKey(name)) shape[name] = jwk[name]
        (jwk["k"] as? String)?.let { shape["k_octets"] = decode(it, "the generated k").size.toLong() }
        return shape
    }

    /** Runs the expectation's `use_with` round trip on [jwk], if it has one, and echoes it back as an output. */
    private fun echoUseWith(jwk: String, expect: Obj, out: Out) {
        val useWith = expect["use_with"] as? Map<*, *> ?: return
        checkUseWith(jwk, useWith)
        out["use_with"] = useWith
    }

    /**
     * Rust `check_use_with` (ADR 0034 §6; conformance/README.md `use_with`, note 14): every call is
     * a check, so any failure fails the vector. The other side is the key's public form, or the key
     * itself for `oct` (RFC 7518 §6.4).
     * - Without `enc`: a compact JWS (RFC 7515 §7.1) of `polyjose` under `{"alg": alg}`, verified
     *   with allow-list `[alg]` (RFC 7515 §5.1-§5.2).
     * - With `enc`: a compact JWE (RFC 7516 §7.1) of it to one recipient with `alg`, decrypted with
     *   the key and allow-lists `[alg]` and `[enc]` (RFC 7516 §5.1-§5.2).
     */
    private fun checkUseWith(key: String, useWith: Map<*, *>) {
        val alg = str(useWith["alg"])
        val kty = (parseOutput(key, "the generated JWK") as? Map<*, *>)?.get("kty")
        val other = if (kty == "oct") key else check("use_with: the key has no public form") { jwkToPublic(key) }
        val enc = useWith["enc"]
        if (enc !is String) {
            val token = check("use_with: the key does not sign") {
                jwsSignCompact(USE_WITH_PAYLOAD, key, JwsSignOptions(protectedHeader = "{\"alg\":${quote(alg)}}"))
            }
            val verified = check("use_with: the signature does not verify") {
                jwsVerifyCompact(token, other, JwsVerifyOptions(allowedAlgs = listOf(alg)))
            }
            if (!verified.payload.contentEquals(USE_WITH_PAYLOAD)) throw HarnessError("use_with: the verified payload is not the signed one")
        } else {
            val token = check("use_with: encryption to the key fails") {
                jweEncryptCompact(USE_WITH_PAYLOAD, JweEncryptOptions(enc = enc, recipients = listOf(JweRecipient(alg = alg, key = other))))
            }
            val decrypted = check("use_with: the key does not decrypt") {
                jweDecryptCompact(token, key, JweDecryptOptions(allowedAlgs = listOf(alg), allowedEnc = listOf(enc)))
            }
            if (!decrypted.plaintext.contentEquals(USE_WITH_PAYLOAD)) {
                throw HarnessError("use_with: the decrypted plaintext is not the encrypted one")
            }
        }
    }

    // --- Calls and conversions ---------------------------------------------------------------------

    /** Calls the library: a `PolyjoseException` becomes the outcome, by its `code()` (ADR 0030 §5). */
    private inline fun <T> lib(call: () -> T): T = try {
        call()
    } catch (e: PolyjoseException) {
        throw LibraryError(e.code())
    }

    /** A library call inside a runner check (round trip, decoding): any failure fails the vector. */
    private inline fun <T> check(what: String, call: () -> T): T = try {
        lib(call)
    } catch (e: LibraryError) {
        throw HarnessError("$what (${e.code})")
    }

    /** A `*_b64u` input's octets. A non-canonical value is a broken vector, never an outcome. */
    private fun decode(value: Any?, name: String): ByteArray =
        check("`$name` is not canonical base64url; the runner must decode it") { base64urlDecode(str(value)) }

    private fun parseOutput(text: String, what: String): Any? = try {
        Json.parseValue(text)
    } catch (e: Exception) {
        throw HarnessError("$what does not parse as JSON (${e.javaClass.simpleName})")
    }

    /** A vector count (a `u32` in ADR 0030): a plain JSON integer in range, else a broken vector (note 5). */
    private fun count(v: Any?, name: String): UInt {
        val n = (v as? Int)?.toLong() ?: (v as? Long) ?: throw HarnessError("`$name` is not a plain integer: ${toJson(v)}")
        if (n < 0 || n > UInt.MAX_VALUE.toLong()) throw HarnessError("`$name` is outside 0..2^32-1: $n")
        return n.toUInt()
    }

    /** `now`: whole seconds, a plain JSON integer within ±(2^53 - 1) (ADR 0027 §2; note 5). */
    private fun seconds(v: Any?): Long {
        val n = (v as? Int)?.toLong() ?: (v as? Long) ?: throw HarnessError("`now` is not a plain integer: ${toJson(v)}")
        if (n > MAX_SAFE || n < -MAX_SAFE) throw HarnessError("`now` is outside ±(2^53 - 1): $n")
        return n
    }

    private const val MAX_SAFE = 9_007_199_254_740_991L

    private fun str(v: Any?): String = v as? String ?: throw HarnessError("expected a string, got ${toJson(v)}")

    private fun strs(v: Any?): List<String> = list(v).map(::str)

    private fun list(v: Any?): List<Any?> = v as? List<*> ?: throw HarnessError("expected an array, got ${toJson(v)}")

    @Suppress("UNCHECKED_CAST")
    private fun obj(v: Any?): Obj = v as? Map<String, Any?> ?: throw HarnessError("expected an object, got ${toJson(v)}")

    /** The runner's own hex code (codec vectors are hex so the codec is never checked against itself). */
    private fun hexDecode(hex: String): ByteArray {
        if (hex.length % 2 != 0) throw HarnessError("`bytes_hex` has an odd length")
        return ByteArray(hex.length / 2) { i ->
            val hi = Character.digit(hex[2 * i], 16)
            val lo = Character.digit(hex[2 * i + 1], 16)
            if (hi < 0 || lo < 0) throw HarnessError("`bytes_hex` is not hex")
            ((hi shl 4) or lo).toByte()
        }
    }

    private fun hexEncode(bytes: ByteArray): String {
        val digits = "0123456789abcdef"
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            out.append(digits[v ushr 4]).append(digits[v and 0x0f])
        }
        return out.toString()
    }
}
