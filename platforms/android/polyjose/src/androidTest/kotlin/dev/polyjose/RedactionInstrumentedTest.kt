package dev.polyjose

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * ADR 0065 on the device (decision 2, 4; feature 0008 F05): the AAR's records carry the same
 * build-patched `toString()` as the JVM jar (`:polyjose-jvm` RedactionTest covers every field),
 * so a secret field prints as `<redacted, N bytes>` and the other fields print unchanged.
 */
class RedactionInstrumentedTest {
    /** A real JWS verify result (RFC 7515 §5.2) and the signer that made it. */
    @Test
    fun aSecretFieldIsRedactedOnAndroid() {
        val payload = "payload $MARKER".toByteArray()
        val key = """{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"""
        val token = jwsSignCompact(payload, key, JwsSignOptions(protectedHeader = """{"alg":"HS256"}"""))
        val verified = jwsVerifyCompact(token, key, JwsVerifyOptions(allowedAlgs = listOf("HS256")))
        val printed = verified.toString()
        assertFalse("the payload is printed: $printed", printed.contains(MARKER))
        assertFalse("the payload's bytes are printed: $printed", printed.contains(payload.joinToString(", ")))
        assertEquals(
            "JwsVerified(alg=HS256, payload=<redacted, ${payload.size} bytes>, protectedHeader={\"alg\":\"HS256\"}, " +
                "unprotectedHeader=null, signatureIndex=0)",
            printed,
        )
        val signer = JwsSigner(key = """{"kty":"oct","k":"$MARKER"}""")
        assertEquals(
            "JwsSigner(key=<redacted, ${signer.key.toByteArray().size} bytes>, protectedHeader=null, protectedB64u=null, unprotectedHeader=null)",
            signer.toString(),
        )
    }

    private companion object {
        const val MARKER = "pj-REDACT-marker-5c1e"
    }
}
