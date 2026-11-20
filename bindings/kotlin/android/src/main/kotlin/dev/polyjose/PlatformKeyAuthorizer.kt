package dev.polyjose

import android.hardware.biometrics.BiometricPrompt

/**
 * The per-use authentication hook of an [AndroidKeystoreKey] (ADR 0072 §4): a key created with
 * `UserAuthentication(validitySeconds = 0, …)` hands each initialised operation (a `Signature` or
 * a `Cipher`) to [authorize] before it runs. API 28+.
 *
 * [authorize] is called on the thread of the polyjose call and blocks it: it returns once the user
 * has authenticated [cryptoObject], and throws `PlatformKeyException.UserAuthenticationRequired`
 * when they cancel, fail or can't (polyjose then reports `UserAuthenticationRequired`). Any other
 * exception fails the call (`PlatformKeyFailed` or `DecryptionFailed`). polyjose ships one
 * implementation, [BiometricPromptAuthorizer].
 */
fun interface PlatformKeyAuthorizer {
    /** Authenticates [cryptoObject]; returns when the user has, throws otherwise (see the type). */
    fun authorize(cryptoObject: BiometricPrompt.CryptoObject)
}
