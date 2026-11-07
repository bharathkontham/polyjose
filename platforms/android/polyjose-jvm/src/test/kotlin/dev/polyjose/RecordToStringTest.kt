package dev.polyjose

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * What the UniFFI-generated Kotlin data classes print in `toString()` (feature 0008 F06, review
 * S8). The multi-party records `JwsSigner` and `JweRecipient` hold a key as a `String` field, and
 * a Kotlin data class prints every field: the residual ADR 0030 §3 documents ("the docs warn not
 * to log those two records"). The output comes from UniFFI's generator, not from polyjose, so a
 * UniFFI bump that starts redacting the key fails here, and ADR 0030 §3 and the docs are revisited.
 */
class RecordToStringTest {
    /** The documented residual (ADR 0030 §3): `JwsSigner(key = …).toString()` prints the key. */
    @Test
    fun jwsSignerPrintsItsKeyTheDocumentedResidual() {
        val printed = JwsSigner(key = MARKED_OCT).toString()
        assertTrue(printed.contains(MARKER)) { "JwsSigner no longer prints its key; update ADR 0030 §3 and the docs: $printed" }
    }

    /** The documented residual (ADR 0030 §3): `JweRecipient(alg, key).toString()` prints the key. */
    @Test
    fun jweRecipientPrintsItsKeyTheDocumentedResidual() {
        val printed = JweRecipient(alg = "A256KW", key = MARKED_OCT).toString()
        assertTrue(printed.contains(MARKER)) { "JweRecipient no longer prints its key; update ADR 0030 §3 and the docs: $printed" }
    }

    private companion object {
        /** A distinctive value standing in for key material (SecurityTest's marker). */
        const val MARKER = "pj-SECRET-marker-7f3a"

        /** A valid 256-bit `oct` key whose `k` holds the marker: 21 + 22 = 43 base64url characters, 32 octets. */
        val MARKED_OCT = """{"kty":"oct","k":"$MARKER${"A".repeat(22)}"}"""
    }
}
