package dev.polyjose

import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import java.math.BigInteger
import java.security.KeyStore
import java.security.PrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * [AndroidKeystoreKey] against the device's Android Keystore (feature 0025 T04; ADR 0072 §2–§5):
 * every TEE row of the ADR 0072 §2 table through the `…WithPlatformKey` operations, the fixed key
 * parameters, reuse, StrongBox without a silent downgrade, the RSA-OAEP-256 self-test, and
 * printing. The AVD's KeyMint is software: a pass here proves function, not hardware (ADR 0072 §6).
 * The tests that need a secure lock screen are in [AndroidKeystoreKeyAuthTest].
 */
class AndroidKeystoreKeyTest {
    private val store: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val aliases = mutableListOf<String>()

    private fun alias(): String = ("polyjose-t04-" + UUID.randomUUID()).also { aliases += it }

    @After
    fun deleteKeys() {
        for (a in aliases) store.deleteEntry(a)
    }

    private fun signAndVerify(key: AndroidKeystoreKey, alg: String) {
        val token = jwsSignCompactWithPlatformKey(PAYLOAD, key, JwsSignOptions(protectedHeader = """{"alg":"$alg"}"""))
        // Verified in pure Rust (and verified once already inside the sign call, ADR 0071 §3).
        val verified = jwsVerifyCompact(token, key.publicJwk(), JwsVerifyOptions(allowedAlgs = listOf(alg)))
        assertArrayEquals("$alg: payload", PAYLOAD, verified.payload)
    }

    private fun encryptTo(key: AndroidKeystoreKey, alg: String): String = jweEncryptCompact(
        PAYLOAD,
        JweEncryptOptions(enc = "A256GCM", recipients = listOf(JweRecipient(alg = alg, key = key.publicJwk()))),
    )

    private fun decryptOptions(alg: String) = JweDecryptOptions(allowedAlgs = listOf(alg), allowedEnc = listOf("A256GCM"))

    private fun decrypt(key: AndroidKeystoreKey, alg: String) {
        val decrypted = jweDecryptCompactWithPlatformKey(encryptTo(key, alg), key, decryptOptions(alg))
        assertArrayEquals("$alg: plaintext", PAYLOAD, decrypted.plaintext)
    }

    @Test
    fun everySigningRowSignsAndVerifies() {
        val rows = listOf("ES256", "ES384", "ES512").map { it to null } +
            listOf("RS256", "RS384", "RS512", "PS256", "PS384", "PS512").map { it to 2048 } +
            listOf("RS256", "PS256").flatMap { alg -> listOf(alg to 3072, alg to 4096) }
        for ((alg, size) in rows) {
            val key = AndroidKeystoreKey.generate(alias(), alg, keySize = size)
            assertEquals(listOf(alg), key.algorithms())
            signAndVerify(key, alg)
            // A JWT too (RFC 7519 §7.1).
            val jwt = jwtSignWithPlatformKey(CLAIMS, key, JwtSignOptions(alg = alg))
            val claims = jwtVerify(jwt, key.publicJwk(), JwtVerifyOptions(allowedAlgs = listOf(alg), now = 1_700_000_000L, allowMissingExp = true)).claims
            assertEquals("$alg/$size: claims", CLAIMS, claims)
        }
    }

    /**
     * RFC 7518 §3.5 fixes the PSS salt at the hash length. The Keystore's PS* signatures verify
     * with polyjose's pure-Rust RSASSA-PSS, which uses exactly that, so its salt is the hash length
     * (research §3 note 4, the Nimbus report).
     */
    @Test
    fun aKeystorePssSignatureVerifiesInPureRust() {
        for (alg in listOf("PS256", "PS384", "PS512")) {
            val key = AndroidKeystoreKey.generate(alias(), alg)
            val token = jwsSignCompactWithPlatformKey(PAYLOAD, key, JwsSignOptions(protectedHeader = """{"alg":"$alg"}"""))
            val verified = jwsVerifyCompact(token, key.publicJwk(), JwsVerifyOptions(allowedAlgs = listOf(alg)))
            assertArrayEquals(PAYLOAD, verified.payload)
        }
    }

    @Test
    fun everyEcdhRowDecrypts() {
        for (curve in listOf(256, 384, 521)) {
            val key = AndroidKeystoreKey.generate(alias(), "ECDH-ES", keySize = curve)
            assertEquals(KeyParameters.ECDH_ES_FAMILY, key.algorithms())
            for (alg in listOf("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW")) decrypt(key, alg)
        }
    }

    @Test
    fun rsaOaep256DecryptsAndATamperedKeyIsDecryptionFailed() {
        Log.i(TAG, "RSA-OAEP-256 on API ${Build.VERSION.SDK_INT}, floor $RSA_OAEP_256_MIN_API")
        if (Build.VERSION.SDK_INT < RSA_OAEP_256_MIN_API) {
            AndroidKeystoreKeyTableTest.expectUnsupported("RSA-OAEP-256 below the floor") {
                AndroidKeystoreKey.generate(alias(), "RSA-OAEP-256")
            }
            return
        }
        for (size in listOf(2048, 3072)) {
            // generate ran the self-test (ADR 0072 §5) before returning.
            val key = AndroidKeystoreKey.generate(alias(), "RSA-OAEP-256", keySize = size)
            assertEquals(listOf("RSA-OAEP-256"), key.algorithms())
            decrypt(key, "RSA-OAEP-256")
            // RFC 7516 §11.5: a tampered JWE Encrypted Key is one DecryptionFailed.
            val parts = encryptTo(key, "RSA-OAEP-256").split('.').toMutableList()
            val ek = base64urlDecode(parts[1])
            ek[ek.size / 2] = (ek[ek.size / 2].toInt() xor 0x01).toByte()
            parts[1] = base64urlEncode(ek)
            try {
                jweDecryptCompactWithPlatformKey(parts.joinToString("."), key, decryptOptions("RSA-OAEP-256"))
                fail("a tampered encrypted key decrypted")
            } catch (e: PolyjoseException) {
                assertEquals("DecryptionFailed", e.code())
            }
        }
        Log.i(TAG, "RSA-OAEP-256 on API ${Build.VERSION.SDK_INT}: PASS")
    }

    @Test
    fun aFailingSelfTestDeletesTheKeyAndIsUnsupportedAlgorithm() {
        if (Build.VERSION.SDK_INT < RSA_OAEP_256_MIN_API) return
        val alias = alias()
        var calls = 0
        AndroidKeystoreKeyTableTest.expectUnsupported("self-test fails") {
            AndroidKeystoreKey.generateKey(alias, "RSA-OAEP-256", AndroidKeystoreKey.StrongBox.Off, null, null, null) { real ->
                object : PlatformKey by real {
                    override fun decryptKey(alg: String, encryptedKey: ByteArray): ByteArray {
                        calls++
                        throw PlatformKeyException.Failed()
                    }
                }
            }
        }
        assertEquals("the self-test decrypted once", 1, calls)
        assertFalse("the key that failed its self-test is still there", store.containsAlias(alias))
    }

    @Test
    fun generatedKeysHaveTheFixedParameters() {
        val rows = mutableListOf(
            Triple("ES256", KeyProperties.PURPOSE_SIGN, KeyProperties.DIGEST_SHA256),
            Triple("ES512", KeyProperties.PURPOSE_SIGN, KeyProperties.DIGEST_SHA512),
            Triple("RS384", KeyProperties.PURPOSE_SIGN, KeyProperties.DIGEST_SHA384),
            Triple("PS256", KeyProperties.PURPOSE_SIGN, KeyProperties.DIGEST_SHA256),
            Triple("ECDH-ES", KeyProperties.PURPOSE_AGREE_KEY, null),
        )
        if (Build.VERSION.SDK_INT >= RSA_OAEP_256_MIN_API) rows += Triple("RSA-OAEP-256", KeyProperties.PURPOSE_DECRYPT, KeyProperties.DIGEST_SHA256)
        for ((alg, purpose, digest) in rows) {
            val alias = alias()
            AndroidKeystoreKey.generate(alias, alg)
            val privateKey = store.getKey(alias, null) as PrivateKey
            val info = AndroidKeystoreKey.keyInfo(privateKey)
            assertEquals("$alg: one purpose", purpose, info.purposes)
            assertEquals("$alg: exactly the digest", listOfNotNull(digest), info.digests.toList())
            assertFalse("$alg: DIGEST_NONE", KeyProperties.DIGEST_NONE in info.digests)
            val signaturePaddings = when {
                alg.matches(Regex("RS[0-9]+")) -> listOf(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                alg.startsWith("PS") -> listOf(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                else -> emptyList()
            }
            assertEquals("$alg: signature paddings", signaturePaddings, info.signaturePaddings.toList())
            val encryptionPaddings = if (alg == "RSA-OAEP-256") listOf(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP) else emptyList()
            assertEquals("$alg: encryption paddings", encryptionPaddings, info.encryptionPaddings.toList())
            assertNull("$alg: the private key is exportable", privateKey.encoded)
            assertFalse("$alg: needs no user authentication", info.isUserAuthenticationRequired)
            val publicKey = store.getCertificate(alias).publicKey
            if (publicKey is RSAPublicKey) assertEquals("$alg: e", BigInteger.valueOf(65537), publicKey.publicExponent)
        }
        // RSA-OAEP-256 on API 35+ is created with setMgf1Digests(SHA-256) (ADR 0072 §2).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            val spec = AndroidKeystoreKey.keyGenSpec("spec-only", KeyParameters.of("RSA-OAEP-256", null), false, null)
            assertTrue(spec.isMgf1DigestsSpecified)
            assertEquals(setOf(KeyProperties.DIGEST_SHA256), spec.mgf1Digests)
            assertEquals(setOf(KeyProperties.DIGEST_SHA256), spec.digests.toSet())
        }
    }

    @Test
    fun aKeyIsFoundAgainByAliasAndBoundToItsAlgorithm() {
        val alias = alias()
        val created = AndroidKeystoreKey.generate(alias, "ES256")
        val opened = AndroidKeystoreKey.open(alias, "ES256")
        assertEquals(created.publicJwk(), opened.publicJwk())
        assertEquals(created.securityLevel, opened.securityLevel)
        signAndVerify(opened, "ES256")
        // Another algorithm than the key permits is refused (ADR 0072 §2, RFC 8725 §3.1).
        for (other in listOf("ES384", "ES512", "RS256", "PS256", "ECDH-ES", "RSA-OAEP-256")) {
            try {
                AndroidKeystoreKey.open(alias, other)
                fail("$other: opened an ES256 key")
            } catch (e: PolyjoseException) {
                assertTrue("$other: ${e.code()}", e.code() == "KeyAlgorithmMismatch" || e.code() == "UnsupportedAlgorithm")
            }
        }
        // An RSA key is bound to its padding: a PS256 key is not an RS256 key.
        val pss = alias()
        AndroidKeystoreKey.generate(pss, "PS256")
        expectCode("PS256 key as RS256", "KeyAlgorithmMismatch") { AndroidKeystoreKey.open(pss, "RS256") }
        expectCode("PS256 key as PS384", "KeyAlgorithmMismatch") { AndroidKeystoreKey.open(pss, "PS384") }
        // A JWE can't be decrypted with a signing key (the core's key binding).
        expectCode("ES256 key decrypts", "KeyAlgorithmMismatch") {
            val ecdh = alias()
            jweDecryptCompactWithPlatformKey(encryptTo(AndroidKeystoreKey.generate(ecdh, "ECDH-ES"), "ECDH-ES"), opened, decryptOptions("ECDH-ES"))
        }
        // An alias that already holds a key is never replaced.
        expectCode("generate over a key", "PlatformKeyFailed") { AndroidKeystoreKey.generate(alias, "ES256") }
        assertEquals(created.publicJwk(), AndroidKeystoreKey.open(alias, "ES256").publicJwk())
        AndroidKeystoreKey.delete(alias)
        expectCode("open after delete", "KeyNotFound") { AndroidKeystoreKey.open(alias, "ES256") }
        // The object of a deleted key: keystore2 reports ERROR_KEY_DOES_NOT_EXIST (API 33+), KeyNotFound.
        try {
            jwsSignCompactWithPlatformKey(PAYLOAD, opened, JwsSignOptions(protectedHeader = """{"alg":"ES256"}"""))
            fail("a deleted key signed")
        } catch (e: PolyjoseException) {
            Log.i(TAG, "sign with a deleted key: ${e.code()}")
            assertEquals(if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) "KeyNotFound" else e.code(), e.code())
            assertTrue(e.code(), e.code() == "KeyNotFound" || e.code() == "PlatformKeyFailed")
        }
        AndroidKeystoreKey.delete(alias) // nothing there: no error
        expectCode("open of an unknown alias", "KeyNotFound") { AndroidKeystoreKey.open("polyjose-t04-never-created", "ES256") }
    }

    @Test
    fun strongBoxIsNeverASilentDowngrade() {
        val hasStrongBox = InstrumentationRegistry.getInstrumentation().targetContext.packageManager
            .hasSystemFeature("android.hardware.strongbox_keystore")
        Log.i(TAG, "device ${Build.MODEL}, API ${Build.VERSION.SDK_INT}, StrongBox feature: $hasStrongBox")
        if (!hasStrongBox) {
            // Required fails and leaves no key behind (F1).
            for (alg in listOf("ES256", "RS256")) {
                val alias = alias()
                expectCode("$alg Required", "PlatformKeyFailed") { AndroidKeystoreKey.generate(alias, alg, AndroidKeystoreKey.StrongBox.Required) }
                assertFalse("$alg Required left a key", store.containsAlias(alias))
            }
            // Preferred falls back, and says so (F2).
            val preferred = AndroidKeystoreKey.generate(alias(), "ES256", AndroidKeystoreKey.StrongBox.Preferred)
            assertNotEquals(AndroidKeystoreKey.SecurityLevel.StrongBox, preferred.securityLevel)
            signAndVerify(preferred, "ES256")
            Log.i(TAG, "securityLevel of a Preferred ES256 key: ${preferred.securityLevel} (not hardware evidence)")
        } else {
            // A StrongBox device (DEVICE-TESTS.md step 1): Required gives StrongBox keys that work.
            for (alg in listOf("ES256", "RS256")) {
                val key = AndroidKeystoreKey.generate(alias(), alg, AndroidKeystoreKey.StrongBox.Required)
                assertEquals("$alg Required", AndroidKeystoreKey.SecurityLevel.StrongBox, key.securityLevel)
                signAndVerify(key, alg)
                Log.i(TAG, "StrongBox $alg: ${key.securityLevel}, signs")
            }
            val ecdh = AndroidKeystoreKey.generate(alias(), "ECDH-ES", AndroidKeystoreKey.StrongBox.Required)
            assertEquals("ECDH-ES Required", AndroidKeystoreKey.SecurityLevel.StrongBox, ecdh.securityLevel)
            decrypt(ecdh, "ECDH-ES")
            Log.i(TAG, "StrongBox ECDH-ES P-256: ${ecdh.securityLevel}, decrypts")
            // Not verified (ADR 0072 §5): recorded, not asserted (DEVICE-TESTS.md step 2).
            val oaep = runCatching {
                val key = AndroidKeystoreKey.generate(alias(), "RSA-OAEP-256", AndroidKeystoreKey.StrongBox.Required)
                decrypt(key, "RSA-OAEP-256")
                key.securityLevel
            }
            Log.i(TAG, "StrongBox RSA-OAEP-256: " + oaep.fold({ "PASS ($it)" }, { "FAIL (${(it as? PolyjoseException)?.code() ?: it.javaClass.simpleName})" }))
        }
        // StrongBox can't hold ES384: Required is refused by the table, Preferred uses the TEE.
        AndroidKeystoreKeyTableTest.expectUnsupported("ES384 Required") {
            AndroidKeystoreKey.generate(alias(), "ES384", AndroidKeystoreKey.StrongBox.Required)
        }
        val es384 = AndroidKeystoreKey.generate(alias(), "ES384", AndroidKeystoreKey.StrongBox.Preferred)
        assertNotEquals(AndroidKeystoreKey.SecurityLevel.StrongBox, es384.securityLevel)
        // Off never asks for StrongBox.
        val spec = AndroidKeystoreKey.keyGenSpec("spec-only", KeyParameters.of("ES256", null), false, null)
        assertFalse(spec.isStrongBoxBacked)
        val off = AndroidKeystoreKey.generate(alias(), "ES256")
        assertNotEquals(AndroidKeystoreKey.SecurityLevel.StrongBox, off.securityLevel)
        // The level is the platform's (KeyInfo), never the request's.
        val level = AndroidKeystoreKey.securityLevelOf(AndroidKeystoreKey.keyInfo(store.getKey(aliases.last(), null) as PrivateKey))
        assertEquals(level, off.securityLevel)
        Log.i(TAG, "securityLevel of a default ES256 key: ${off.securityLevel} (not hardware evidence)")
    }

    @Test
    fun ecdhPerUseIsUnsupportedAlgorithm() {
        val alias = alias()
        AndroidKeystoreKeyTableTest.expectUnsupported("ECDH per use") {
            AndroidKeystoreKey.generate(alias, "ECDH-ES", userAuthentication = AndroidKeystoreKey.UserAuthentication(0, true))
        }
        assertFalse(store.containsAlias(alias))
    }

    @Test
    fun biometricPromptAuthorizerRefusesTheMainThread() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val authorizer = BiometricPromptAuthorizer(instrumentation.targetContext, "polyjose", "Cancel")
        val signature = java.security.Signature.getInstance("SHA256withECDSA")
        var thrown: Throwable? = null
        instrumentation.runOnMainSync {
            try {
                authorizer.authorize(BiometricPrompt.CryptoObject(signature))
            } catch (t: Throwable) {
                thrown = t
            }
        }
        assertTrue("authorize on the main thread: $thrown", thrown is IllegalStateException)
    }

    @Test
    fun printingShowsTheTypeAndLevelOnly() {
        val alias = "polyjose-t04-print-" + AndroidKeystoreKeyTableTest.MARKER
        aliases += alias
        val key = AndroidKeystoreKey.generate(alias, "ES256")
        val printed = key.toString()
        assertEquals("AndroidKeystoreKey(securityLevel=${key.securityLevel})", printed)
        assertFalse(printed.contains(AndroidKeystoreKeyTableTest.MARKER))
        val x = Regex("\"x\":\"([^\"]+)\"").find(key.publicJwk())!!.groupValues[1]
        assertFalse(printed.contains(x))
        assertFalse("$key".contains(alias))
    }

    companion object {
        const val TAG = "polyjose-t04"
        val PAYLOAD = "signed and decrypted by the Android Keystore".toByteArray()
        const val CLAIMS = """{"iss":"joe","sub":"keystore"}"""

        fun expectCode(what: String, code: String, call: () -> Any) {
            try {
                call()
            } catch (e: PolyjoseException) {
                assertEquals(what, code, e.code())
                return
            }
            fail("$what: succeeded")
        }
    }
}
