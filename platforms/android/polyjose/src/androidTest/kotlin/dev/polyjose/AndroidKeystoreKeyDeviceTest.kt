package dev.polyjose

import android.app.Activity
import android.content.Intent
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** An empty activity in the test APK, so a prompt has a foreground window (AndroidManifest.xml of androidTest). */
class PromptTestActivity : Activity()

/**
 * Manual steps 3 and 4 of `platforms/android/DEVICE-TESTS.md` (feature 0025 T04; ADR 0072 §4): a
 * person answers a real prompt on a device with a secure lock screen and an enrolled biometric.
 * Never part of an automated run: `scripts/run-instrumented.sh` excludes this class, and it is
 * run only with `-e class dev.polyjose.AndroidKeystoreKeyDeviceTest#<test>` and the instrumentation
 * argument `polyjoseExpect` (`success`: authenticate when asked; `cancel`: cancel the prompt).
 * `polyjoseCredential=true` lets step 4 use the device credential instead of a biometric (a device
 * or emulator without an enrolled biometric).
 */
class AndroidKeystoreKeyDeviceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val expect = InstrumentationRegistry.getArguments().getString("polyjoseExpect", "")
    private val credential = InstrumentationRegistry.getArguments().getString("polyjoseCredential", "") == "true"
    private val store: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val aliases = mutableListOf<String>()
    private val payload = "signed after a prompt".toByteArray()

    private fun alias(): String = ("polyjose-t04-device-" + UUID.randomUUID()).also { aliases += it }

    @After
    fun deleteKeys() {
        for (a in aliases) store.deleteEntry(a)
    }

    private fun activity(): Activity {
        val intent = Intent(instrumentation.targetContext, PromptTestActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return instrumentation.startActivitySync(intent)
    }

    private fun sign(key: AndroidKeystoreKey) =
        jwsSignCompactWithPlatformKey(payload, key, JwsSignOptions(protectedHeader = """{"alg":"ES256"}"""))

    /** Step 3: a time-bound key fails before a prompt and signs within 30 s after one. */
    @Test
    fun timeBoundKeyBeforeAndAfterAPrompt() {
        assertEquals("run with -e polyjoseExpect success", "success", expect)
        val key = AndroidKeystoreKey.generate(alias(), "ES256", userAuthentication = AndroidKeystoreKey.UserAuthentication(30, true))
        AndroidKeystoreKeyTest.expectCode("before the prompt", "UserAuthenticationRequired") { sign(key) }
        val activity = activity()
        val done = CountDownLatch(1)
        var ok = false
        instrumentation.runOnMainSync {
            val builder = BiometricPrompt.Builder(activity).setTitle("polyjose DEVICE-TESTS step 3")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setAllowedAuthenticators(
                    android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
            } else {
                builder.setNegativeButton("Cancel", activity.mainExecutor) { _, _ -> done.countDown() }
            }
            builder.build().authenticate(CancellationSignal(), activity.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    ok = true
                    done.countDown()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    done.countDown()
                }
            })
        }
        assertTrue("no answer to the prompt within 120 s", done.await(120, TimeUnit.SECONDS))
        activity.finish()
        assertTrue("the prompt was not authenticated", ok)
        val token = sign(key)
        assertArrayEquals(payload, jwsVerifyCompact(token, key.publicJwk(), JwsVerifyOptions(allowedAlgs = listOf("ES256"))).payload)
        Log.i(AndroidKeystoreKeyTest.TAG, "step 3: time-bound key failed before the prompt and signed after it")
    }

    /** Step 4: a per-use key prompts through BiometricPromptAuthorizer for each signature. */
    @Test
    fun perUseKeyWithBiometricPromptAuthorizer() {
        assertTrue("run with -e polyjoseExpect success or cancel", expect == "success" || expect == "cancel")
        val activity = activity()
        val authorizer = BiometricPromptAuthorizer(activity, "polyjose DEVICE-TESTS step 4", "Cancel", allowDeviceCredential = credential)
        val key = AndroidKeystoreKey.generate(
            alias(), "ES256", userAuthentication = AndroidKeystoreKey.UserAuthentication(0, credential), authorizer = authorizer,
        )
        try {
            if (expect == "success") {
                val token = sign(key)
                assertArrayEquals(payload, jwsVerifyCompact(token, key.publicJwk(), JwsVerifyOptions(allowedAlgs = listOf("ES256"))).payload)
            } else {
                AndroidKeystoreKeyTest.expectCode("a cancelled prompt", "UserAuthenticationRequired") { sign(key) }
            }
            Log.i(AndroidKeystoreKeyTest.TAG, "step 4 ($expect, credential=$credential): as expected")
        } finally {
            activity.finish()
        }
    }
}
