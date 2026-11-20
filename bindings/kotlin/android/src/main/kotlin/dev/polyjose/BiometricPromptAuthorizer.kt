package dev.polyjose

import android.annotation.SuppressLint
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import java.util.concurrent.CountDownLatch

/**
 * A [PlatformKeyAuthorizer] that shows the framework's `android.hardware.biometrics.BiometricPrompt`
 * (API 28+; no AndroidX, ADR 0072 §4) for each operation of a per-use [AndroidKeystoreKey], and
 * blocks the calling thread until the user has authenticated or the prompt ends.
 *
 * - **Never on the main thread.** The prompt's result arrives on the main thread, so waiting for it
 *   there would deadlock: [authorize] throws `IllegalStateException` at once, before showing
 *   anything, when called on the main thread. Call polyjose from a background thread.
 * - A cancelled or failed prompt, or one the device can't show (no biometric enrolled, lockout),
 *   throws `PlatformKeyException.UserAuthenticationRequired`.
 * - [allowDeviceCredential] (API 30+) lets the PIN, pattern or password stand in for a strong
 *   biometric; the prompt then has no [negativeButtonText] button. It must match the key's
 *   `UserAuthentication.allowDeviceCredential`. Below API 30 the prompt is biometric only.
 *
 * - **Permission.** The app declares `android.permission.USE_BIOMETRIC` in its manifest (a normal,
 *   install-time permission). The AAR doesn't, so apps that never prompt don't get it.
 *
 * @param context a context to show the prompt from, normally the current `Activity`.
 */
class BiometricPromptAuthorizer @JvmOverloads constructor(
    private val context: Context,
    private val title: CharSequence,
    private val negativeButtonText: CharSequence,
    private val allowDeviceCredential: Boolean = false,
    private val subtitle: CharSequence? = null,
) : PlatformKeyAuthorizer {

    // USE_BIOMETRIC is the app's to declare (see the class documentation).
    @SuppressLint("MissingPermission")
    override fun authorize(cryptoObject: BiometricPrompt.CryptoObject) {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "BiometricPromptAuthorizer.authorize must not be called on the main thread"
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) throw PlatformKeyException.Failed()
        val done = CountDownLatch(1)
        var succeeded = false
        val cancel = CancellationSignal()
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                succeeded = true
                done.countDown()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                done.countDown()
            }
            // onAuthenticationFailed: one attempt did not match; the prompt stays up.
        }
        val main = Handler(Looper.getMainLooper())
        main.post {
            try {
                prompt(done).authenticate(cryptoObject, cancel, context.mainExecutor, callback)
            } catch (_: Throwable) {
                done.countDown()
            }
        }
        try {
            done.await()
        } catch (_: InterruptedException) {
            main.post { cancel.cancel() }
            Thread.currentThread().interrupt()
            throw PlatformKeyException.UserAuthenticationRequired()
        }
        // The callback ran on the main thread before countDown, which publishes `succeeded`.
        if (!succeeded) throw PlatformKeyException.UserAuthenticationRequired()
    }

    /** The prompt; its negative button ends the wait as a cancel (the framework calls only its listener). */
    private fun prompt(done: CountDownLatch): BiometricPrompt {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) throw PlatformKeyException.Failed()
        val builder = BiometricPrompt.Builder(context).setTitle(title)
        subtitle?.let { builder.setSubtitle(it) }
        if (allowDeviceCredential && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
        } else {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            }
            builder.setNegativeButton(negativeButtonText, context.mainExecutor) { _, _ -> done.countDown() }
        }
        return builder.build()
    }
}
