package dev.polyjose.sample

import dev.polyjose.JwsSignOptions
import dev.polyjose.JwsVerifyOptions
import dev.polyjose.PolyjoseException
import dev.polyjose.jwkGenerateEc
import dev.polyjose.jwkParse
import dev.polyjose.jwkToPublic
import dev.polyjose.jwsSignCompact
import dev.polyjose.jwsVerifyCompact
import dev.polyjose.version

/**
 * What the sample app does with polyjose. proguard-rules.pro keeps this object as an app's
 * reachable code; R8 shrinks, optimizes and renames everything it reaches in polyjose and JNA
 * under the AAR's consumer rules alone (ADR 0033 §2). Each call crosses the FFI boundary in a
 * different way: a `String` return, records in both directions through `RustBuffer` (a JNA
 * `Structure` with `@Structure.FieldOrder`), and an error lifted into `PolyjoseException`.
 */
object R8Probe {
    /** The library version (ADR 0030 §4). */
    fun libraryVersion(): String = version()

    /**
     * Signs [payload] as a compact JWS with a fresh P-256 key and ES256 (RFC 7515 §7.1, RFC 7518
     * §3.4), then verifies it with the public key, allowing only ES256 (RFC 8725 §3.1), and
     * returns the verified payload.
     */
    fun es256RoundTrip(payload: ByteArray): ByteArray {
        val key = jwkGenerateEc("P-256")
        val token = jwsSignCompact(payload, key, JwsSignOptions(protectedHeader = """{"alg":"ES256"}"""))
        return jwsVerifyCompact(token, jwkToPublic(key), JwsVerifyOptions(allowedAlgs = listOf("ES256"))).payload
    }

    /**
     * The stable error code for a JWK that is not JSON (RFC 7517 §4: a JWK is a JSON object),
     * read through the exported `code()` (ADR 0033 §3), or null when no error was raised.
     */
    fun invalidJwkCode(): String? =
        try {
            jwkParse("not json")
            null
        } catch (e: PolyjoseException) {
            e.code()
        }
}
