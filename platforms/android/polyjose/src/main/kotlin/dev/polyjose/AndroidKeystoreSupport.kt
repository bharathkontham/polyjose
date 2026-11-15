package dev.polyjose

import android.os.Build
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException

// The pure parts of AndroidKeystoreKey (feature 0025 T04; ADR 0072 §2, §4, §5): which algorithms
// the Android Keystore can serve at which API level, the fixed parameters of each key, and how a
// platform throwable maps onto the three platform-key outcomes. Everything here is internal: the
// public API is AndroidKeystoreKey, PlatformKeyAuthorizer and BiometricPromptAuthorizer
// (scripts/check-binding-api.d/kotlin.host-types). Nothing here makes a Keystore call, so the
// instrumented tests check every row without depending on the device's API level.

/**
 * The lowest API level at which polyjose offers RSA-OAEP-256 on the Android Keystore (ADR 0072 §5;
 * RFC 7518 §4.3: SHA-256 and MGF1 with SHA-256). The framework rejects an MGF1 digest other than
 * SHA-1 for keys generated below API 34, and documents `setMgf1Digests` from API 35. The floor is
 * 34 only because the RSA-OAEP-256 tests pass on an API 34 system image (feature 0025 T04 report);
 * below it, RSA-OAEP-256 is `UnsupportedAlgorithm`, never a fallback to MGF1-SHA-1.
 */
internal const val RSA_OAEP_256_MIN_API = 34

/** The lowest API level of `PURPOSE_AGREE_KEY`, so of ECDH-ES (ADR 0072 §2). */
internal const val ECDH_MIN_API = 31

/** The lowest API level of StrongBox (`setIsStrongBoxBacked`) and of `BiometricPrompt` (ADR 0072 §2, §4). */
internal const val STRONGBOX_MIN_API = 28

/** The lowest API level of per-use authentication (`BiometricPrompt.CryptoObject`, ADR 0072 §4). */
internal const val PER_USE_MIN_API = 28

/** The lowest API level of `setUserAuthenticationParameters` (one call for both authenticator kinds). */
internal const val AUTH_PARAMETERS_MIN_API = 30

/**
 * Fixed messages, equal to the core `polyjose::Error` `Display` text of each code (ADR 0030 §5,
 * ADR 0071 §6): no alias, algorithm name or platform text is ever part of a message.
 */
internal object KeystoreMessages {
    const val UNSUPPORTED_ALGORITHM = "unsupported algorithm"
    const val KEY_ALGORITHM_MISMATCH = "key does not match the algorithm"
    const val KEY_NOT_FOUND = "platform key not found"
    const val USER_AUTHENTICATION_REQUIRED = "user authentication required"
    const val PLATFORM_KEY_FAILED = "platform key operation failed"
}

internal fun unsupportedAlgorithm() = PolyjoseException.UnsupportedAlgorithm(KeystoreMessages.UNSUPPORTED_ALGORITHM)

internal fun keyAlgorithmMismatch() = PolyjoseException.KeyAlgorithmMismatch(KeystoreMessages.KEY_ALGORITHM_MISMATCH)

/** The four kinds of key ADR 0072 §2 offers, one purpose each. */
internal enum class KeyFamily { EcSign, RsaSign, Ecdh, RsaOaep }

/**
 * The fixed parameters of one Keystore key (ADR 0072 §2): one JOSE algorithm (for ECDH-ES the
 * family of RFC 7518 §4.6), the key type and size, exactly one digest and one padding where the
 * algorithm has them (never `DIGEST_NONE`, never raw RSA), and the JCA names of the operation.
 */
internal class KeyParameters(
    val algorithm: String,
    val family: KeyFamily,
    /** RSA modulus bits, or the curve's size (256, 384, 521). */
    val keySize: Int,
    /** `KeyProperties.DIGEST_*`, or null for ECDH, which has none. */
    val digest: String?,
    /** `KeyProperties.SIGNATURE_PADDING_*` for RS* and PS*. */
    val signaturePadding: String?,
    /** `KeyProperties.ENCRYPTION_PADDING_*` for RSA-OAEP-256. */
    val encryptionPadding: String?,
    /** The `java.security.Signature` algorithm (RFC 7518 §3.3, §3.4, §3.5). */
    val jcaSignature: String?,
) {
    val keyAlgorithm: String get() = if (family == KeyFamily.EcSign || family == KeyFamily.Ecdh) KeyProperties.KEY_ALGORITHM_EC else KeyProperties.KEY_ALGORITHM_RSA
    val isRsa: Boolean get() = family == KeyFamily.RsaSign || family == KeyFamily.RsaOaep

    /** The JOSE names this key serves (RFC 7518 §3.1, §4.1): one, or the ECDH-ES family. */
    val algorithms: List<String> get() = if (family == KeyFamily.Ecdh) ECDH_ES_FAMILY else listOf(algorithm)

    /** The SEC 2 curve name of an EC key. */
    val curveName: String get() = when (keySize) {
        256 -> "secp256r1"
        384 -> "secp384r1"
        else -> "secp521r1"
    }

    companion object {
        /** ECDH-ES and its key-wrap forms (RFC 7518 §4.6): one ECDH key serves all four. */
        val ECDH_ES_FAMILY = listOf("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")

        /** RSA modulus sizes polyjose offers on the Keystore (ADR 0072 §2). */
        val RSA_SIZES = listOf(2048, 3072, 4096)

        /** EC curve sizes: P-256, P-384, P-521. */
        val CURVE_SIZES = listOf(256, 384, 521)

        /** Every JOSE algorithm name `generate` and `open` accept. */
        val NAMES = listOf(
            "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ECDH-ES", "RSA-OAEP-256",
        )

        /**
         * The parameters of [algorithm] with [keySize] (RSA bits, or the ECDH curve size; null is the
         * default, 2048 or P-256; for ES* the size is the algorithm's curve). Anything else is
         * `UnsupportedAlgorithm` (ADR 0071 §6): EdDSA, HS*, the ECDH-ES+A*KW names (a key is made
         * for the family under `ECDH-ES`), RSA1_5, RSA-OAEP, and sizes outside the table.
         */
        fun of(algorithm: String, keySize: Int?): KeyParameters {
            fun ec(size: Int, digest: String, jca: String): KeyParameters {
                if (keySize != null && keySize != size) throw unsupportedAlgorithm()
                return KeyParameters(algorithm, KeyFamily.EcSign, size, digest, null, null, jca)
            }
            fun rsaSign(digest: String, padding: String, jca: String): KeyParameters {
                val size = keySize ?: 2048
                if (size !in RSA_SIZES) throw unsupportedAlgorithm()
                return KeyParameters(algorithm, KeyFamily.RsaSign, size, digest, padding, null, jca)
            }
            val pkcs1 = KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
            val pss = KeyProperties.SIGNATURE_PADDING_RSA_PSS
            return when (algorithm) {
                // RFC 7518 §3.4: ECDSA with P-256/SHA-256, P-384/SHA-384, P-521/SHA-512.
                "ES256" -> ec(256, KeyProperties.DIGEST_SHA256, "SHA256withECDSA")
                "ES384" -> ec(384, KeyProperties.DIGEST_SHA384, "SHA384withECDSA")
                "ES512" -> ec(521, KeyProperties.DIGEST_SHA512, "SHA512withECDSA")
                // RFC 7518 §3.3: RSASSA-PKCS1-v1_5.
                "RS256" -> rsaSign(KeyProperties.DIGEST_SHA256, pkcs1, "SHA256withRSA")
                "RS384" -> rsaSign(KeyProperties.DIGEST_SHA384, pkcs1, "SHA384withRSA")
                "RS512" -> rsaSign(KeyProperties.DIGEST_SHA512, pkcs1, "SHA512withRSA")
                // RFC 7518 §3.5: RSASSA-PSS, MGF1 with the same hash, salt = hash length (the
                // Keystore's fixed choice: KeyMint requires salt size = digest size).
                "PS256" -> rsaSign(KeyProperties.DIGEST_SHA256, pss, "SHA256withRSA/PSS")
                "PS384" -> rsaSign(KeyProperties.DIGEST_SHA384, pss, "SHA384withRSA/PSS")
                "PS512" -> rsaSign(KeyProperties.DIGEST_SHA512, pss, "SHA512withRSA/PSS")
                // RFC 7518 §4.6: ECDH-ES on P-256, P-384 or P-521; no digest.
                "ECDH-ES" -> {
                    val size = keySize ?: 256
                    if (size !in CURVE_SIZES) throw unsupportedAlgorithm()
                    KeyParameters(algorithm, KeyFamily.Ecdh, size, null, null, null, null)
                }
                // RFC 7518 §4.3: RSAES-OAEP with SHA-256 and MGF1 with SHA-256.
                "RSA-OAEP-256" -> {
                    val size = keySize ?: 2048
                    if (size !in RSA_SIZES) throw unsupportedAlgorithm()
                    KeyParameters(algorithm, KeyFamily.RsaOaep, size, KeyProperties.DIGEST_SHA256, null, KeyProperties.ENCRYPTION_PADDING_RSA_OAEP, null)
                }
                else -> throw unsupportedAlgorithm()
            }
        }
    }
}

/**
 * The lowest API level at which the Keystore serves [p] (ADR 0072 §2 table), in StrongBox when
 * [strongBox], else in the TEE; null when that backend can't serve it at any level.
 */
internal fun minimumApi(p: KeyParameters, strongBox: Boolean): Int? = when (p.family) {
    KeyFamily.EcSign -> when {
        !strongBox -> 23
        p.algorithm == "ES256" -> STRONGBOX_MIN_API
        else -> null // StrongBox has P-256 only.
    }
    KeyFamily.RsaSign -> when {
        !strongBox -> 23
        // StrongBox: RSA-2048 with SHA-256 only.
        (p.algorithm == "RS256" || p.algorithm == "PS256") && p.keySize == 2048 -> STRONGBOX_MIN_API
        else -> null
    }
    KeyFamily.Ecdh -> when {
        !strongBox -> ECDH_MIN_API
        p.keySize == 256 -> ECDH_MIN_API
        else -> null
    }
    KeyFamily.RsaOaep -> when {
        !strongBox -> RSA_OAEP_256_MIN_API
        p.keySize == 2048 -> RSA_OAEP_256_MIN_API // unverified in StrongBox (ADR 0072 §5)
        else -> null
    }
}

/** Whether the Keystore serves [p] at [apiLevel] (ADR 0072 §2): one pure function of the table. */
internal fun isSupported(p: KeyParameters, apiLevel: Int, strongBox: Boolean): Boolean =
    minimumApi(p, strongBox)?.let { apiLevel >= it } ?: false

/** `UnsupportedAlgorithm` unless [isSupported] (ADR 0072 §2: at generate or open, never at first use). */
internal fun requireSupported(p: KeyParameters, apiLevel: Int, strongBox: Boolean) {
    if (!isSupported(p, apiLevel, strongBox)) throw unsupportedAlgorithm()
}

/**
 * `UnsupportedAlgorithm` for a user-authentication request the platform can't meet at [apiLevel]
 * (ADR 0072 §4):
 * - per use (`validitySeconds = 0`) on an ECDH key: `CryptoObject` takes a `KeyAgreement` only from
 *   Android 16 QPR2, so ECDH keys are time-bound only;
 * - per use below API 28 (no `BiometricPrompt`);
 * - below API 30 the only call is `setUserAuthenticationValidityDurationSeconds`: a time-bound key
 *   there always admits the device credential, and a per-use key never does, so the other choice
 *   of [UserAuthentication.allowDeviceCredential] is refused rather than silently changed.
 */
internal fun requireAuthenticationSupported(p: KeyParameters, auth: AndroidKeystoreKey.UserAuthentication?, apiLevel: Int) {
    if (auth == null) return
    val perUse = auth.validitySeconds == 0
    if (perUse && p.family == KeyFamily.Ecdh) throw unsupportedAlgorithm()
    if (perUse && apiLevel < PER_USE_MIN_API) throw unsupportedAlgorithm()
    if (apiLevel < AUTH_PARAMETERS_MIN_API && perUse == auth.allowDeviceCredential) throw unsupportedAlgorithm()
}

/** The three outcomes of a failed platform call (ADR 0071 §1, §6). */
internal enum class KeyFailure { NotFound, UserAuthenticationRequired, Failed }

/** No key under the alias: what `KeyStore.getKey` returning null means. */
internal class AliasNotFound : Exception()

/**
 * The outcome of a throwable from a Keystore call (ADR 0072 §2 "Errors"), looking through its
 * cause chain:
 * - no key under the alias ([AliasNotFound]) and `KeyPermanentlyInvalidatedException` (the lock
 *   screen was removed or reset, or biometrics changed): `NotFound`;
 * - `UserNotAuthenticatedException`: `UserAuthenticationRequired`;
 * - on API 33+, an `android.security.KeyStoreException` (keystore2's error for an operation) with
 *   `ERROR_USER_AUTHENTICATION_REQUIRED` (a per-use key whose `CryptoObject` was not
 *   authenticated): `UserAuthenticationRequired`, and with `ERROR_KEY_DOES_NOT_EXIST` (the key
 *   was deleted after it was opened): `NotFound`;
 * - a `PlatformKeyException` (from a [PlatformKeyAuthorizer]) keeps its kind;
 * - everything else, including `StrongBoxUnavailableException`, `KeyStoreException`,
 *   `ProviderException` and `InvalidKeyException`: `Failed`.
 * Only the type is read, never the message, so no platform text reaches polyjose. The two
 * reported conditions depend on the key and the user, never on a ciphertext (ADR 0071 §4).
 */
internal fun classify(t: Throwable): KeyFailure {
    var c: Throwable? = t
    var depth = 0
    while (c != null && depth < 16) {
        when (c) {
            is AliasNotFound, is KeyPermanentlyInvalidatedException, is PlatformKeyException.NotFound -> return KeyFailure.NotFound
            is UserNotAuthenticatedException, is PlatformKeyException.UserAuthenticationRequired -> return KeyFailure.UserAuthenticationRequired
            is PlatformKeyException.Failed -> return KeyFailure.Failed
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && c is android.security.KeyStoreException) {
            // The keystore2 error of an operation on API 33+ (for example a per-use key whose
            // CryptoObject was not authenticated): its numeric code, never its text.
            val code = c.numericErrorCode
            if (code == android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED) return KeyFailure.UserAuthenticationRequired
            if (code == android.security.KeyStoreException.ERROR_KEY_DOES_NOT_EXIST) return KeyFailure.NotFound
        }
        if (c.cause === c) break
        c = c.cause
        depth++
    }
    return KeyFailure.Failed
}

/** The exception a [PlatformKey] method throws for [failure] (ADR 0071 §5). */
internal fun KeyFailure.toPlatformKeyException(): PlatformKeyException = when (this) {
    KeyFailure.NotFound -> PlatformKeyException.NotFound()
    KeyFailure.UserAuthenticationRequired -> PlatformKeyException.UserAuthenticationRequired()
    KeyFailure.Failed -> PlatformKeyException.Failed()
}

/** The exception `generate`, `open` and `delete` throw for [failure] (ADR 0071 §6), with its fixed message. */
internal fun KeyFailure.toPolyjoseException(): PolyjoseException = when (this) {
    KeyFailure.NotFound -> PolyjoseException.KeyNotFound(KeystoreMessages.KEY_NOT_FOUND)
    KeyFailure.UserAuthenticationRequired -> PolyjoseException.UserAuthenticationRequired(KeystoreMessages.USER_AUTHENTICATION_REQUIRED)
    KeyFailure.Failed -> PolyjoseException.PlatformKeyFailed(KeystoreMessages.PLATFORM_KEY_FAILED)
}
