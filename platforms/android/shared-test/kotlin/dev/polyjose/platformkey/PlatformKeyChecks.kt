package dev.polyjose.platformkey

import dev.polyjose.JweDecryptOptions
import dev.polyjose.JweEncryptOptions
import dev.polyjose.JweRecipient
import dev.polyjose.JwsSignOptions
import dev.polyjose.JwsVerifyOptions
import dev.polyjose.JwtSignOptions
import dev.polyjose.JwtVerifyOptions
import dev.polyjose.PlatformKey
import dev.polyjose.PlatformKeyException
import dev.polyjose.PolyjoseException
import dev.polyjose.base64urlEncode
import dev.polyjose.jweDecryptCompactWithPlatformKey
import dev.polyjose.jweDecryptJsonWithPlatformKey
import dev.polyjose.jweEncryptCompact
import dev.polyjose.jweEncryptJson
import dev.polyjose.jwsSignCompactWithPlatformKey
import dev.polyjose.jwsVerifyCompact
import dev.polyjose.jwtDecryptNestedWithPlatformKey
import dev.polyjose.jwtDecryptNestedWithPlatformKeyAndJwks
import dev.polyjose.jwtEncryptNested
import dev.polyjose.jwtSignWithPlatformKey
import dev.polyjose.jwtVerify
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * The `PlatformKey` callback path through the generated Kotlin (feature 0025 T02; ADR 0071 §5),
 * shared by `:polyjose-jvm`'s `PlatformKeyTest` (JUnit 5, host JVM) and `:polyjose`'s
 * `PlatformKeyInstrumentedTest` (the emulator). Plain Kotlin and `java.security` only, no test
 * framework (shared-test/README.md).
 *
 * The keys are software keys made with `java.security` (a P-256 key and an RSA-2048 key), wrapped
 * in [SoftKey], an implementation of the interface written here: the stand-in for a Keystore or
 * Secure Enclave key, which features 0025 T03 and T04 add. Each check is a name and a function
 * that throws on failure.
 */
object PlatformKeyChecks {
    /** Every check, by name. */
    val all: List<Pair<String, () -> Unit>> = listOf(
        "ES256 JWS and JWT sign, verified with the public JWK" to ::es256Signs,
        "RS256 JWS and JWT sign, verified with the public JWK" to ::rs256Signs,
        "ECDH-ES and ECDH-ES+A256KW (P-256) decrypt, compact and JSON" to ::ecdhDecrypts,
        "RSA-OAEP-256 decrypts, compact and JSON" to ::rsaOaepDecrypts,
        "nested JWT decrypts, with one key and with a JWK Set" to ::nestedDecrypts,
        "misuse is refused before the private key is used" to ::misuseIsRefusedFirst,
        "a signature by another key is PlatformKeyFailed" to ::verifyAfterSign,
        "the key's errors surface as the polyjose codes" to ::platformErrors,
        "an unexpected host exception fails the call and its text is dropped" to ::unexpectedHostErrors,
    )

    const val MARKER = "host-exception-marker-5c1e"
    private val PAYLOAD = "platform keys sign and decrypt".toByteArray()
    private const val CLAIMS = """{"iss":"joe","sub":"platform"}"""

    private val ecKeys: KeyPair by lazy {
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    }
    private val otherEcKeys: KeyPair by lazy {
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    }
    private val rsaKeys: KeyPair by lazy {
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    }

    /** Where a [SoftKey] throws instead of returning, and what. */
    enum class Method { PUBLIC_JWK, ALGORITHMS, SIGN, AGREE, DECRYPT_KEY }

    /**
     * A software `PlatformKey` over a `java.security` key pair: `sign` returns the DER
     * `Ecdsa-Sig-Value` of `SHA256withECDSA` (RFC 3279 §2.2.3) or the `SHA256withRSA` signature,
     * `agree` the ECDH shared secret Z (RFC 7518 §4.6.2), `decryptKey` the RSAES-OAEP-256
     * plaintext (RFC 7518 §4.3). It counts the private-key calls, and throws [failure] from
     * [failAt] when both are set.
     */
    class SoftKey(
        private val keys: KeyPair,
        private val algs: List<String>,
        private val signer: KeyPair = keys,
        private val failAt: Method? = null,
        private val failure: Exception? = null,
    ) : PlatformKey {
        var privateCalls = 0
            private set

        private fun maybeFail(method: Method) {
            if (method == failAt && failure != null) throw failure
        }

        override fun publicJwk(): String {
            maybeFail(Method.PUBLIC_JWK)
            return publicJwkOf(keys)
        }

        override fun algorithms(): List<String> {
            maybeFail(Method.ALGORITHMS)
            return algs
        }

        override fun sign(alg: String, signingInput: ByteArray): ByteArray {
            privateCalls++
            maybeFail(Method.SIGN)
            val name = if (alg == "ES256") "SHA256withECDSA" else "SHA256withRSA"
            return Signature.getInstance(name).run {
                initSign(signer.private)
                update(signingInput)
                sign()
            }
        }

        override fun agree(peerPublicKey: ByteArray): ByteArray {
            privateCalls++
            maybeFail(Method.AGREE)
            check(peerPublicKey.size == 65 && peerPublicKey[0] == 4.toByte()) { "agree gets 0x04 || X || Y" }
            val params = (keys.public as ECPublicKey).params
            val point = ECPoint(BigInteger(1, peerPublicKey.copyOfRange(1, 33)), BigInteger(1, peerPublicKey.copyOfRange(33, 65)))
            val peer = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
            return KeyAgreement.getInstance("ECDH").run {
                init(keys.private)
                doPhase(peer, true)
                generateSecret()
            }
        }

        override fun decryptKey(alg: String, encryptedKey: ByteArray): ByteArray {
            privateCalls++
            maybeFail(Method.DECRYPT_KEY)
            check(alg == "RSA-OAEP-256") { "decryptKey is asked for RSA-OAEP-256" }
            val spec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
            return Cipher.getInstance("RSA/ECB/OAEPPadding").run {
                init(Cipher.DECRYPT_MODE, keys.private, spec)
                doFinal(encryptedKey)
            }
        }
    }

    /** The public JWK (RFC 7517 §4; RFC 7518 §6.2.1, §6.3.1) of an EC P-256 or RSA key pair. */
    fun publicJwkOf(keys: KeyPair): String = when (val public = keys.public) {
        is ECPublicKey -> {
            val x = base64urlEncode(unsigned(public.w.affineX, 32))
            val y = base64urlEncode(unsigned(public.w.affineY, 32))
            """{"kty":"EC","crv":"P-256","x":"$x","y":"$y"}"""
        }
        is RSAPublicKey -> {
            val n = base64urlEncode(unsigned(public.modulus, (public.modulus.bitLength() + 7) / 8))
            val e = base64urlEncode(unsigned(public.publicExponent, (public.publicExponent.bitLength() + 7) / 8))
            """{"kty":"RSA","n":"$n","e":"$e"}"""
        }
        else -> error("not an EC or RSA key")
    }

    /** The big-endian unsigned octets of [value], left-padded to [size]. */
    private fun unsigned(value: BigInteger, size: Int): ByteArray {
        val bytes = value.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(size - bytes.size) + bytes
    }

    private fun signOptions(alg: String) = JwsSignOptions(protectedHeader = """{"alg":"$alg"}""")
    private fun verifyOptions(alg: String) = JwtVerifyOptions(allowedAlgs = listOf(alg), now = 1_700_000_000L, allowMissingExp = true)
    private fun decryptOptions(vararg algs: String) = JweDecryptOptions(allowedAlgs = algs.toList(), allowedEnc = listOf("A256GCM"))
    private fun encryptOptions(alg: String, keys: KeyPair) =
        JweEncryptOptions(enc = "A256GCM", recipients = listOf(JweRecipient(alg = alg, key = publicJwkOf(keys))))

    /** The [PolyjoseException] [call] throws; fails if it returns. */
    private fun failure(what: String, call: () -> Any): PolyjoseException {
        try {
            call()
        } catch (e: PolyjoseException) {
            return e
        }
        error("$what: the call succeeded")
    }

    private fun expectCode(what: String, expected: String, call: () -> Any) {
        val code = failure(what, call).code()
        check(code == expected) { "$what: expected $expected, got $code" }
    }

    private fun signs(keys: KeyPair, alg: String) {
        val key = SoftKey(keys, listOf(alg))
        val token = jwsSignCompactWithPlatformKey(PAYLOAD, key, signOptions(alg))
        check(key.privateCalls == 1) { "$alg: sign was called ${key.privateCalls} times" }
        val verified = jwsVerifyCompact(token, publicJwkOf(keys), JwsVerifyOptions(allowedAlgs = listOf(alg)))
        check(verified.payload.contentEquals(PAYLOAD)) { "$alg: the payload changed" }
        val jwt = jwtSignWithPlatformKey(CLAIMS, key, JwtSignOptions(alg = alg))
        val claims = jwtVerify(jwt, publicJwkOf(keys), verifyOptions(alg)).claims
        check(claims == CLAIMS) { "$alg: the claims changed: $claims" }
    }

    fun es256Signs() = signs(ecKeys, "ES256")

    fun rs256Signs() = signs(rsaKeys, "RS256")

    private fun decrypts(keys: KeyPair, alg: String) {
        val key = SoftKey(keys, listOf(alg))
        val compact = jweEncryptCompact(PAYLOAD, encryptOptions(alg, keys))
        val decrypted = jweDecryptCompactWithPlatformKey(compact, key, decryptOptions(alg))
        check(decrypted.plaintext.contentEquals(PAYLOAD)) { "$alg compact: wrong plaintext" }
        val json = jweEncryptJson(PAYLOAD, encryptOptions(alg, keys), "general")
        val fromJson = jweDecryptJsonWithPlatformKey(json, key, decryptOptions(alg))
        check(fromJson.plaintext.contentEquals(PAYLOAD)) { "$alg JSON: wrong plaintext" }
        check(key.privateCalls == 2) { "$alg: the key was called ${key.privateCalls} times" }
    }

    fun ecdhDecrypts() {
        decrypts(ecKeys, "ECDH-ES")
        decrypts(ecKeys, "ECDH-ES+A256KW")
    }

    fun rsaOaepDecrypts() = decrypts(rsaKeys, "RSA-OAEP-256")

    fun nestedDecrypts() {
        val signed = jwtSignWithPlatformKey(CLAIMS, SoftKey(ecKeys, listOf("ES256")), JwtSignOptions(alg = "ES256"))
        for ((keys, alg) in listOf(ecKeys to "ECDH-ES", rsaKeys to "RSA-OAEP-256")) {
            val token = jwtEncryptNested(signed, encryptOptions(alg, keys))
            val key = SoftKey(keys, listOf(alg))
            val one = jwtDecryptNestedWithPlatformKey(token, key, decryptOptions(alg), publicJwkOf(ecKeys), verifyOptions("ES256"))
            check(one.inner.claims == CLAIMS) { "$alg: nested claims changed" }
            val jwks = """{"keys":[${publicJwkOf(ecKeys)}]}"""
            val set = jwtDecryptNestedWithPlatformKeyAndJwks(token, key, decryptOptions(alg), jwks, verifyOptions("ES256"))
            check(set.inner.claims == CLAIMS && set.inner.keyIndex == 0u) { "$alg: nested claims or key index changed" }
        }
    }

    fun misuseIsRefusedFirst() {
        // Wrong family: an EC key asked for RS256 (RFC 8725 §3.1).
        val ec = SoftKey(ecKeys, listOf("RS256"))
        expectCode("wrong family", "KeyAlgorithmMismatch") { jwsSignCompactWithPlatformKey(PAYLOAD, ec, signOptions("RS256")) }
        check(ec.privateCalls == 0) { "wrong family: the private key was used" }
        // algorithms() does not list the requested algorithm.
        val es384Only = SoftKey(ecKeys, listOf("ES384"))
        expectCode("wrong algorithms()", "KeyAlgorithmMismatch") { jwtSignWithPlatformKey(CLAIMS, es384Only, JwtSignOptions(alg = "ES256")) }
        check(es384Only.privateCalls == 0) { "wrong algorithms(): the private key was used" }
        // An alg outside allowedAlgs never reaches the key.
        val ecdh = SoftKey(ecKeys, listOf("ECDH-ES"))
        val token = jweEncryptCompact(PAYLOAD, encryptOptions("ECDH-ES", ecKeys))
        expectCode("outside allowedAlgs", "AlgorithmNotAllowed") {
            jweDecryptCompactWithPlatformKey(token, ecdh, decryptOptions("ECDH-ES+A256KW"))
        }
        check(ecdh.privateCalls == 0) { "outside allowedAlgs: the private key was used" }
    }

    fun verifyAfterSign() {
        val impostor = SoftKey(ecKeys, listOf("ES256"), signer = otherEcKeys)
        expectCode("another key's signature", "PlatformKeyFailed") { jwsSignCompactWithPlatformKey(PAYLOAD, impostor, signOptions("ES256")) }
        expectCode("another key's JWT signature", "PlatformKeyFailed") { jwtSignWithPlatformKey(CLAIMS, impostor, JwtSignOptions(alg = "ES256")) }
    }

    fun platformErrors() {
        val ecdhToken = jweEncryptCompact(PAYLOAD, encryptOptions("ECDH-ES", ecKeys))
        val rsaToken = jweEncryptCompact(PAYLOAD, encryptOptions("RSA-OAEP-256", rsaKeys))
        for ((thrown, code) in listOf(
            PlatformKeyException.NotFound() to "KeyNotFound",
            PlatformKeyException.UserAuthenticationRequired() to "UserAuthenticationRequired",
        )) {
            val signer = SoftKey(ecKeys, listOf("ES256"), failAt = Method.SIGN, failure = thrown)
            expectCode("sign throws $thrown", code) { jwsSignCompactWithPlatformKey(PAYLOAD, signer, signOptions("ES256")) }
            val agreer = SoftKey(ecKeys, listOf("ECDH-ES"), failAt = Method.AGREE, failure = thrown)
            expectCode("agree throws $thrown", code) { jweDecryptCompactWithPlatformKey(ecdhToken, agreer, decryptOptions("ECDH-ES")) }
            val decrypter = SoftKey(rsaKeys, listOf("RSA-OAEP-256"), failAt = Method.DECRYPT_KEY, failure = thrown)
            expectCode("decryptKey throws $thrown", code) { jweDecryptCompactWithPlatformKey(rsaToken, decrypter, decryptOptions("RSA-OAEP-256")) }
        }
        // `failed` on decrypt is one DecryptionFailed (RFC 7516 §11.5, ADR 0071 §4); on sign, PlatformKeyFailed.
        val agreer = SoftKey(ecKeys, listOf("ECDH-ES"), failAt = Method.AGREE, failure = PlatformKeyException.Failed())
        expectCode("agree throws failed", "DecryptionFailed") { jweDecryptCompactWithPlatformKey(ecdhToken, agreer, decryptOptions("ECDH-ES")) }
        val decrypter = SoftKey(rsaKeys, listOf("RSA-OAEP-256"), failAt = Method.DECRYPT_KEY, failure = PlatformKeyException.Failed())
        expectCode("decryptKey throws failed", "DecryptionFailed") {
            jweDecryptCompactWithPlatformKey(rsaToken, decrypter, decryptOptions("RSA-OAEP-256"))
        }
        val signer = SoftKey(ecKeys, listOf("ES256"), failAt = Method.SIGN, failure = PlatformKeyException.Failed())
        expectCode("sign throws failed", "PlatformKeyFailed") { jwsSignCompactWithPlatformKey(PAYLOAD, signer, signOptions("ES256")) }
    }

    /**
     * ADR 0071 §5: any other exception from any method becomes `failed`, so a signing call fails
     * with PlatformKeyFailed and a decrypting call with DecryptionFailed (ADR 0071 §4). The
     * exception's message holds [MARKER], which appears in no polyjose message or printed form.
     */
    fun unexpectedHostErrors() {
        val ecdhToken = jweEncryptCompact(PAYLOAD, encryptOptions("ECDH-ES", ecKeys))
        val rsaToken = jweEncryptCompact(PAYLOAD, encryptOptions("RSA-OAEP-256", rsaKeys))
        val thrown = IllegalStateException("the platform said $MARKER")
        val cases = mutableListOf<Triple<String, String, () -> Any>>()
        for (method in listOf(Method.PUBLIC_JWK, Method.ALGORITHMS, Method.SIGN)) {
            val key = SoftKey(ecKeys, listOf("ES256"), failAt = method, failure = thrown)
            cases += Triple("JWS sign, $method throws", "PlatformKeyFailed") { jwsSignCompactWithPlatformKey(PAYLOAD, key, signOptions("ES256")) }
            cases += Triple("JWT sign, $method throws", "PlatformKeyFailed") { jwtSignWithPlatformKey(CLAIMS, key, JwtSignOptions(alg = "ES256")) }
        }
        for (method in listOf(Method.PUBLIC_JWK, Method.ALGORITHMS, Method.AGREE)) {
            val key = SoftKey(ecKeys, listOf("ECDH-ES"), failAt = method, failure = thrown)
            cases += Triple("ECDH-ES decrypt, $method throws", "DecryptionFailed") { jweDecryptCompactWithPlatformKey(ecdhToken, key, decryptOptions("ECDH-ES")) }
        }
        val key = SoftKey(rsaKeys, listOf("RSA-OAEP-256"), failAt = Method.DECRYPT_KEY, failure = thrown)
        cases += Triple("RSA-OAEP-256 decrypt, DECRYPT_KEY throws", "DecryptionFailed") {
            jweDecryptCompactWithPlatformKey(rsaToken, key, decryptOptions("RSA-OAEP-256"))
        }
        for ((what, code, call) in cases) {
            val e = failure(what, call)
            check(e.code() == code) { "$what: expected $code, got ${e.code()}" }
            for (text in listOf(e.code(), e.message, e.localizedMessage, e.toString())) {
                check(text == null || !text.contains(MARKER)) { "$what: the host exception's text reached polyjose: $text" }
            }
            check(e.cause == null) { "$what: the host exception is attached as the cause" }
        }
    }
}
