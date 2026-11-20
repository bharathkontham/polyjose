package dev.polyjose

import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.security.keystore.KeyProperties
import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import java.security.PrivateKey
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * User authentication of [AndroidKeystoreKey] (feature 0025 T04; ADR 0072 §4). These tests need a
 * secure lock screen: `scripts/run-instrumented.sh` sets a PIN only on an emulator it started, runs
 * this class, and clears the PIN on exit. Otherwise it excludes this class and reports the live
 * check `SKIPPED (no secure lock screen on the AVD)`; the pure mapping test
 * ([AndroidKeystoreKeyTableTest]) still covers the code path. Nothing here authenticates: a real
 * prompt is a step of `bindings/kotlin/DEVICE-TESTS.md`.
 */
class AndroidKeystoreKeyAuthTest {
    private val store: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val aliases = mutableListOf<String>()

    private fun alias(): String = ("polyjose-t04-auth-" + UUID.randomUUID()).also { aliases += it }

    @Before
    fun aSecureLockScreenIsSet() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        assertTrue("this class needs a secure lock screen (run-instrumented.sh sets a PIN)", keyguard.isDeviceSecure)
    }

    @After
    fun deleteKeys() {
        for (a in aliases) store.deleteEntry(a)
    }

    private fun info(alias: String) = AndroidKeystoreKey.keyInfo(store.getKey(alias, null) as PrivateKey)

    @Test
    fun aTimeBoundKeyHasThePlatformsTimeBoundParameters() {
        // The device credential admitted: a time-bound biometric-only key needs an enrolled biometric.
        val alias = alias()
        AndroidKeystoreKey.generate(alias, "ES256", userAuthentication = AndroidKeystoreKey.UserAuthentication(30, true))
        val info = info(alias)
        assertTrue(info.isUserAuthenticationRequired)
        assertEquals(30, info.userAuthenticationValidityDurationSeconds)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL, info.userAuthenticationType)
        }
    }

    /** Live check: a time-bound key used without authenticating is UserAuthenticationRequired. */
    @Test
    fun aTimeBoundKeyWithoutAuthenticationIsUserAuthenticationRequired() {
        // One second: no authentication has happened in the last second on this emulator.
        val auth = AndroidKeystoreKey.UserAuthentication(1, true)
        val signer = AndroidKeystoreKey.generate(alias(), "ES256", userAuthentication = auth)
        AndroidKeystoreKeyTest.expectCode("time-bound sign", "UserAuthenticationRequired") {
            jwsSignCompactWithPlatformKey(PAYLOAD, signer, JwsSignOptions(protectedHeader = """{"alg":"ES256"}"""))
        }
        val agreer = AndroidKeystoreKey.generate(alias(), "ECDH-ES", userAuthentication = auth)
        AndroidKeystoreKeyTest.expectCode("time-bound ECDH", "UserAuthenticationRequired") {
            jweDecryptCompactWithPlatformKey(encryptTo(agreer, "ECDH-ES"), agreer, decryptOptions("ECDH-ES"))
        }
        if (Build.VERSION.SDK_INT >= RSA_OAEP_256_MIN_API) {
            val decrypter = AndroidKeystoreKey.generate(alias(), "RSA-OAEP-256", userAuthentication = auth)
            AndroidKeystoreKeyTest.expectCode("time-bound RSA-OAEP-256", "UserAuthenticationRequired") {
                jweDecryptCompactWithPlatformKey(encryptTo(decrypter, "RSA-OAEP-256"), decrypter, decryptOptions("RSA-OAEP-256"))
            }
        }
    }

    /** A [PlatformKeyAuthorizer] that only records what it was handed, and authenticates nothing. */
    private class RecordingAuthorizer : PlatformKeyAuthorizer {
        val received = mutableListOf<BiometricPrompt.CryptoObject>()
        override fun authorize(cryptoObject: BiometricPrompt.CryptoObject) {
            received += cryptoObject
        }
    }

    @Test
    fun aPerUseKeyHandsTheAuthorizerAnInitialisedCryptoObject() {
        val perUse = AndroidKeystoreKey.UserAuthentication(0, allowDeviceCredential = true)
        val signing = RecordingAuthorizer()
        val signer = AndroidKeystoreKey.generate(alias(), "ES256", userAuthentication = perUse, authorizer = signing)
        val signResult = runCatching {
            jwsSignCompactWithPlatformKey(PAYLOAD, signer, JwsSignOptions(protectedHeader = """{"alg":"ES256"}"""))
        }
        assertEquals("the authorizer was called once", 1, signing.received.size)
        val signature = signing.received[0].signature
        assertTrue("a Signature was handed over", signature != null)
        // Initialised: the JCA chose the Keystore's provider at initSign.
        assertTrue("initialised by the Keystore: ${signature!!.provider.name}", signature.provider.name.startsWith("AndroidKeyStore"))
        assertEquals("unauthenticated sign", "UserAuthenticationRequired", (signResult.exceptionOrNull() as PolyjoseException).code())

        if (Build.VERSION.SDK_INT >= RSA_OAEP_256_MIN_API) {
            val decrypting = RecordingAuthorizer()
            val decrypter = AndroidKeystoreKey.generate(alias(), "RSA-OAEP-256", userAuthentication = perUse, authorizer = decrypting)
            val decryptResult = runCatching {
                jweDecryptCompactWithPlatformKey(encryptTo(decrypter, "RSA-OAEP-256"), decrypter, decryptOptions("RSA-OAEP-256"))
            }
            assertEquals("the authorizer was called once", 1, decrypting.received.size)
            val cipher = decrypting.received[0].cipher
            assertTrue("a Cipher was handed over", cipher != null)
            assertTrue("initialised by the Keystore: ${cipher!!.provider.name}", cipher.provider.name.startsWith("AndroidKeyStore"))
            assertEquals("unauthenticated decrypt", "UserAuthenticationRequired", (decryptResult.exceptionOrNull() as PolyjoseException).code())
        }
    }

    private fun encryptTo(key: AndroidKeystoreKey, alg: String): String = jweEncryptCompact(
        PAYLOAD,
        JweEncryptOptions(enc = "A256GCM", recipients = listOf(JweRecipient(alg = alg, key = key.publicJwk()))),
    )

    private fun decryptOptions(alg: String) = JweDecryptOptions(allowedAlgs = listOf(alg), allowedEnc = listOf("A256GCM"))

    companion object {
        val PAYLOAD = "needs the user".toByteArray()
    }
}
