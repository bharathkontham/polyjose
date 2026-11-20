package dev.polyjose.sample

import dev.polyjose.JwsSignOptions
import dev.polyjose.JwsVerifyOptions
import dev.polyjose.PlatformKey
import dev.polyjose.PlatformKeyException
import dev.polyjose.PolyjoseException
import dev.polyjose.base64urlEncode
import dev.polyjose.jwkGenerateEc
import dev.polyjose.jwkParse
import dev.polyjose.jwkToPublic
import dev.polyjose.jwsSignCompact
import dev.polyjose.jwsSignCompactWithPlatformKey
import dev.polyjose.jwsVerifyCompact
import dev.polyjose.version
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * What the sample app does with polyjose. proguard-rules.pro keeps this object as an app's
 * reachable code; R8 shrinks, optimizes and renames everything it reaches in polyjose and JNA
 * under the AAR's consumer rules alone (ADR 0033 §2). Each call crosses the FFI boundary in a
 * different way: a `String` return, records in both directions through `RustBuffer` (a JNA
 * `Structure` with `@Structure.FieldOrder`), an error lifted into `PolyjoseException`, and a
 * Kotlin object of the app's own that Rust calls back through JNA callbacks (the `PlatformKey`
 * interface, ADR 0071 §5), which R8 renames like any app class.
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

    /**
     * Signs [payload] as a compact ES256 JWS with [SoftwareKey], the app's own implementation of
     * `PlatformKey` (ADR 0071 §5), then verifies it with the key's public JWK and returns the
     * verified payload: Rust calls `publicJwk`, `algorithms` and `sign` back into the minified app.
     */
    fun platformKeyRoundTrip(payload: ByteArray): ByteArray {
        val key = SoftwareKey(KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair())
        val token = jwsSignCompactWithPlatformKey(payload, key, JwsSignOptions(protectedHeader = """{"alg":"ES256"}"""))
        return jwsVerifyCompact(token, key.publicJwk(), JwsVerifyOptions(allowedAlgs = listOf("ES256"))).payload
    }

    /**
     * The code of a sign call whose `PlatformKey` throws `PlatformKeyException.NotFound`, an
     * error lowered from Kotlin into Rust (ADR 0071 §6: `KeyNotFound`), or null when none.
     */
    fun platformKeyNotFoundCode(): String? =
        try {
            jwsSignCompactWithPlatformKey(byteArrayOf(1), MissingKey(), JwsSignOptions(protectedHeader = """{"alg":"ES256"}"""))
            null
        } catch (e: PolyjoseException) {
            e.code()
        }

    /** A P-256 `PlatformKey` over a `java.security` key pair: DER ECDSA signatures (RFC 3279 §2.2.3). */
    private class SoftwareKey(private val pair: KeyPair) : PlatformKey {
        override fun publicJwk(): String {
            val w = (pair.public as ECPublicKey).w
            return """{"kty":"EC","crv":"P-256","x":"${coordinate(w.affineX)}","y":"${coordinate(w.affineY)}"}"""
        }

        override fun algorithms(): List<String> = listOf("ES256")

        override fun sign(alg: String, signingInput: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private)
                update(signingInput)
                sign()
            }

        override fun agree(peerPublicKey: ByteArray): ByteArray = throw PlatformKeyException.Failed()

        override fun decryptKey(alg: String, encryptedKey: ByteArray): ByteArray = throw PlatformKeyException.Failed()

        private fun coordinate(value: BigInteger): String {
            val bytes = value.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return base64urlEncode(ByteArray(32 - bytes.size) + bytes)
        }
    }

    /** A `PlatformKey` that is never there. */
    private class MissingKey : PlatformKey {
        override fun publicJwk(): String = throw PlatformKeyException.NotFound()
        override fun algorithms(): List<String> = throw PlatformKeyException.NotFound()
        override fun sign(alg: String, signingInput: ByteArray): ByteArray = throw PlatformKeyException.NotFound()
        override fun agree(peerPublicKey: ByteArray): ByteArray = throw PlatformKeyException.NotFound()
        override fun decryptKey(alg: String, encryptedKey: ByteArray): ByteArray = throw PlatformKeyException.NotFound()
    }
}
