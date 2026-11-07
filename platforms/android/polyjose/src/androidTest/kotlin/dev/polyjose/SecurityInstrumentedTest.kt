package dev.polyjose

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * Security properties of the binding on the device (feature 0008 T03), the Android counterparts of
 * a part of `:polyjose-jvm`'s `SecurityTest`: no input in errors for the JWS family (ADR 0030 §5,
 * ADR 0007), and key generation from the OS CSPRNG through `getrandom` on Android (ADR 0005).
 */
class SecurityInstrumentedTest {
    /**
     * ADR 0030 §5: failing JWS calls (RFC 7515) given a key whose secret holds a marker, and other
     * inputs holding it. The marker appears in neither the exception's `code()`, `message`,
     * `localizedMessage` nor `toString()` (the core's `Display`, across the FFI).
     */
    @Test
    fun noFailingJwsCallPutsTheMarkerInTheError() {
        val hs256 = JwsSignOptions(protectedHeader = """{"alg":"HS256"}""")
        val token = jwsSignCompact(PAYLOAD, MARKED_OCT, hs256)
        val allowHs256 = JwsVerifyOptions(allowedAlgs = listOf("HS256"))
        val cases: List<Pair<String, () -> Any>> = listOf(
            "sign with an unparseable key" to { jwsSignCompact(PAYLOAD, MARKED_UNPARSEABLE, hs256) },
            "sign with an unknown alg" to { jwsSignCompact(PAYLOAD, MARKED_OCT, JwsSignOptions(protectedHeader = """{"alg":"$MARKER"}""")) },
            "sign with a broken header" to {
                jwsSignCompact(PAYLOAD, MARKED_OCT, JwsSignOptions(protectedHeader = """{"alg":"HS256","kid":"$MARKER" $MARKER}"""))
            },
            "verify outside the allow-list" to { jwsVerifyCompact(token, MARKED_OCT, JwsVerifyOptions(allowedAlgs = listOf(MARKER))) },
            "verify a marked token" to { jwsVerifyCompact(listOf(MARKER, MARKER, MARKER).joinToString("."), MARKED_OCT, allowHs256) },
            "verify with the wrong key" to { jwsVerifyCompact(token, OTHER_MARKED_OCT, allowHs256) },
            "verify a broken JSON serialization" to { jwsVerifyJson("""{"payload":"$MARKER" $MARKER}""", MARKED_OCT, allowHs256) },
        )
        for ((what, call) in cases) {
            val error = try {
                call()
                fail("$what: the call succeeded; the marker test needs a failing call")
                return
            } catch (e: PolyjoseException) {
                e
            }
            for (rendered in listOf(error.code(), error.message.orEmpty(), error.toString(), error.localizedMessage.orEmpty())) {
                assertFalse("$what (${error.code()}): the error shows the marker: $rendered", rendered.contains(MARKER))
            }
        }
    }

    /**
     * ADR 0005: keys come from the OS CSPRNG (`getrandom`, on Android the `getrandom` syscall), so
     * two generated keys differ, and each one works (RFC 7515 §5.1, §5.2 round trip).
     */
    @Test
    fun twoGeneratedKeysDiffer() {
        val oct = List(2) { JSONObject(jwkGenerateOct(32u)).getString("k") }
        assertNotEquals("two 256-bit oct keys", oct[0], oct[1])

        val ec = List(2) { jwkGenerateEc("P-256") }
        assertNotEquals("two P-256 private scalars", JSONObject(ec[0]).getString("d"), JSONObject(ec[1]).getString("d"))
        assertNotEquals("two P-256 public points", JSONObject(ec[0]).getString("x"), JSONObject(ec[1]).getString("x"))

        val es256 = jwkGenerateForAlg("ES256")
        val token = jwsSignCompact(PAYLOAD, es256, JwsSignOptions(protectedHeader = """{"alg":"ES256"}"""))
        val verified = jwsVerifyCompact(token, jwkToPublic(es256), JwsVerifyOptions(allowedAlgs = listOf("ES256")))
        assertArrayEquals(PAYLOAD, verified.payload)
    }

    private companion object {
        /** A distinctive value standing in for key material and other input (the core's marker style). */
        const val MARKER = "pj-SECRET-marker-7f3a"

        val PAYLOAD = "polyjose on Android".toByteArray()

        /** A valid 256-bit `oct` key whose `k` holds the marker: 21 + 22 = 43 base64url characters, 32 octets. */
        val MARKED_OCT = """{"kty":"oct","k":"$MARKER${"A".repeat(22)}"}"""

        /** Another valid 256-bit key holding the marker, for the wrong-key failure. */
        val OTHER_MARKED_OCT = """{"kty":"oct","k":"$MARKER${"B".repeat(21)}A"}"""

        /** A key that fails to import with the marker as its secret: 21 base64url characters, no valid length. */
        val MARKED_UNPARSEABLE = """{"kty":"oct","k":"$MARKER"}"""
    }
}
