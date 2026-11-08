package dev.polyjose

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * ADR 0065 (decision 1, 2, 4; supersedes ADR 0030 §7's printing residual; feature 0008 F05, audit
 * L1): the records' `toString()`, which the build patches (UniffiKotlinPatch), prints each secret
 * field as `<redacted, N bytes>` and every other field as the generated `data class` would.
 *
 * - A marker in every listed field is absent from the printed record, as text and as the decimal
 *   list a `ByteArray` prints as, and `N` is the field's length (UTF-8 bytes for a JWK string,
 *   the bytes Rust receives, ADR 0030 §2).
 * - The non-secret fields print unchanged, and JWT claims are not redacted (ADR 0058 decision 2,
 *   ADR 0065 decision 3).
 * - The fields covered here are exactly ADR 0065's list (PatchTest checks the patch's own list
 *   and the records it overrides against the same set).
 */
class RedactionTest {
    @Test
    fun everyListedFieldIsRedactedWithItsLength() {
        val cases: Map<String, Pair<Any, Int>> = mapOf(
            "JwsSigner.key" to (JwsSigner(key = MARKED_KEY) to KEY_BYTES),
            "JweRecipient.key" to (JweRecipient(alg = "A256KW", key = MARKED_KEY) to KEY_BYTES),
            "JwsVerified.payload" to (JwsVerified(alg = "HS256", payload = MARKED_BYTES, signatureIndex = 0u) to MARKED_BYTES.size),
            "JweDecrypted.plaintext" to (JweDecrypted(plaintext = MARKED_BYTES, header = "{}", recipientIndex = 0u) to MARKED_BYTES.size),
            "JweDecrypted.aad" to (JweDecrypted(plaintext = byteArrayOf(), header = "{}", aad = MARKED_BYTES, recipientIndex = 0u) to MARKED_BYTES.size),
            "JweEncryptOptions.aad" to (JweEncryptOptions(enc = "A256GCM", recipients = emptyList(), aad = MARKED_BYTES) to MARKED_BYTES.size),
            "JwsVerifyOptions.detachedPayload" to (JwsVerifyOptions(allowedAlgs = listOf("HS256"), detachedPayload = MARKED_BYTES) to MARKED_BYTES.size),
        )
        assertEquals(ADR_0065_FIELDS, cases.keys, "the fields this test covers are not ADR 0065's list")
        for ((field, case) in cases) {
            val (record, length) = case
            val printed = record.toString()
            assertNoMarker(field, printed)
            val name = field.substringAfter('.')
            assertTrue(printed.contains("$name=<redacted, $length bytes>"), "$field: not `<redacted, $length bytes>`: $printed")
            assertEquals(printed, "$record", "$field: a string template prints differently")
        }
    }

    /** The exact printed forms: the non-secret fields as the data class prints them. */
    @Test
    fun theOtherFieldsPrintAsBefore() {
        assertEquals(
            "JwsSigner(key=<redacted, $KEY_BYTES bytes>, protectedHeader={\"alg\":\"HS256\"}, protectedB64u=null, unprotectedHeader={\"kid\":\"k1\"})",
            JwsSigner(key = MARKED_KEY, protectedHeader = """{"alg":"HS256"}""", unprotectedHeader = """{"kid":"k1"}""").toString(),
        )
        val recipient = JweRecipient(alg = "ECDH-ES+A128KW", key = MARKED_KEY, header = """{"kid":"r"}""", apu = byteArrayOf(1, 2), apv = null, p2c = 1000u, p2sLen = 16u)
        val recipientText = "JweRecipient(alg=ECDH-ES+A128KW, key=<redacted, $KEY_BYTES bytes>, header={\"kid\":\"r\"}, apu=[1, 2], apv=null, p2c=1000, p2sLen=16)"
        assertEquals(recipientText, recipient.toString())
        assertEquals(
            "JweEncryptOptions(enc=A256GCM, recipients=[$recipientText], protectedHeader=null, sharedUnprotectedHeader={\"x\":1}, aad=<redacted, 3 bytes>, compress=true)",
            JweEncryptOptions(enc = "A256GCM", recipients = listOf(recipient), sharedUnprotectedHeader = """{"x":1}""", aad = byteArrayOf(7, 8, 9), compress = true).toString(),
        )
        assertEquals(
            "JwsVerified(alg=ES256, payload=<redacted, 4 bytes>, protectedHeader={\"alg\":\"ES256\"}, unprotectedHeader=null, signatureIndex=2)",
            JwsVerified(alg = "ES256", payload = byteArrayOf(1, 2, 3, 4), protectedHeader = """{"alg":"ES256"}""", signatureIndex = 2u).toString(),
        )
        assertEquals(
            "JweDecrypted(plaintext=<redacted, 0 bytes>, header={\"enc\":\"A256GCM\"}, protectedHeader=p, sharedUnprotectedHeader=null, recipientHeader=r, aad=null, recipientIndex=1)",
            JweDecrypted(plaintext = byteArrayOf(), header = """{"enc":"A256GCM"}""", protectedHeader = "p", recipientHeader = "r", recipientIndex = 1u).toString(),
        )
        assertEquals(
            "JwsVerifyOptions(allowedAlgs=[HS256, ES256], detachedPayload=null, maxInputLen=4096, maxSignatures=null)",
            JwsVerifyOptions(allowedAlgs = listOf("HS256", "ES256"), maxInputLen = 4096u).toString(),
        )
    }

    /** `N` counts UTF-8 bytes, also for non-ASCII text and surrogate pairs. */
    @Test
    fun theLengthOfAStringSecretIsItsUtf8Length() {
        for (key in listOf("", "a", "é", "€", "😀", """{"kty":"oct","k":"é€😀"}""")) {
            assertEquals(
                "JwsSigner(key=<redacted, ${key.toByteArray(Charsets.UTF_8).size} bytes>, protectedHeader=null, protectedB64u=null, unprotectedHeader=null)",
                JwsSigner(key = key).toString(),
                "key ${key.length} chars",
            )
        }
    }

    /** Real results of verify and decrypt (RFC 7515 §5.2, RFC 7516 §5.2) print no secret. */
    @Test
    fun realResultsPrintNoSecret() {
        val token = jwsSignCompact(MARKED_BYTES, OCT, JwsSignOptions(protectedHeader = """{"alg":"HS256"}"""))
        val verified = jwsVerifyCompact(token, OCT, JwsVerifyOptions(allowedAlgs = listOf("HS256")))
        assertNoMarker("jwsVerifyCompact", verified.toString())
        assertTrue(verified.toString().contains("payload=<redacted, ${MARKED_BYTES.size} bytes>"), verified.toString())

        val kek = jwkGenerateOct(32u)
        val options = JweEncryptOptions(enc = "A256GCM", recipients = listOf(JweRecipient(alg = "A256KW", key = kek)), aad = MARKED_BYTES)
        val jwe = jweEncryptJson(MARKED_BYTES, options, "flattened")
        val decrypted = jweDecryptJson(jwe, kek, JweDecryptOptions(allowedAlgs = listOf("A256KW"), allowedEnc = listOf("A256GCM")))
        assertNoMarker("jweDecryptJson", decrypted.toString())
        assertTrue(decrypted.toString().contains("plaintext=<redacted, ${MARKED_BYTES.size} bytes>"), decrypted.toString())
        assertTrue(decrypted.toString().contains("aad=<redacted, ${MARKED_BYTES.size} bytes>"), decrypted.toString())
        // The fields themselves are unchanged for programmatic use (ADR 0065, consequences).
        assertTrue(decrypted.plaintext.contentEquals(MARKED_BYTES))
    }

    /** ADR 0058 decision 2, ADR 0065 decision 3: JWT claims print as they are. */
    @Test
    fun jwtClaimsAreNotRedacted() {
        val claims = """{"sub":"$MARKER","exp":4000000000}"""
        val jwt = jwtSign(claims, OCT, JwtSignOptions(alg = "HS256"))
        val verified = jwtVerify(jwt, OCT, JwtVerifyOptions(allowedAlgs = listOf("HS256"), now = 2_000_000_000L))
        assertTrue(verified.toString().contains("claims=$claims"), verified.toString())
        val nested = JwtNestedVerified(inner = verified, outerHeader = "{}", recipientIndex = 0u)
        assertTrue(nested.toString().contains(MARKER), nested.toString())
    }

    private fun assertNoMarker(what: String, printed: String) {
        assertFalse(printed.contains(MARKER), "$what: the marker is printed: $printed")
        assertFalse(printed.contains(MARKED_BYTES.joinToString(", ")), "$what: the marker's bytes are printed: $printed")
    }

    private companion object {
        const val MARKER = "pj-REDACT-marker-5c1e"
        val MARKED_BYTES: ByteArray = "payload $MARKER".toByteArray()
        val MARKED_KEY = """{"kty":"oct","k":"$MARKER"}"""
        val KEY_BYTES = MARKED_KEY.toByteArray(Charsets.UTF_8).size

        /** RFC 7515 Appendix A.1's HMAC key. */
        const val OCT = """{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"""

        /** ADR 0065 decision 1, with ADR 0030 §7's other record fields (there are none; F05 log). */
        val ADR_0065_FIELDS = setOf(
            "JwsSigner.key", "JweRecipient.key", "JwsVerified.payload", "JweDecrypted.plaintext",
            "JweDecrypted.aad", "JweEncryptOptions.aad", "JwsVerifyOptions.detachedPayload",
        )
    }
}
