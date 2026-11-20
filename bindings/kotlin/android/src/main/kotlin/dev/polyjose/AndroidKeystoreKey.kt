package dev.polyjose

import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * A private key held by the Android Keystore (the TEE, or StrongBox), which signs or decrypts for
 * polyjose and never leaves the platform (ADR 0070, ADR 0072 §2). Pass it to the
 * `…WithPlatformKey` operations, for example `jwsSignCompactWithPlatformKey` or
 * `jweDecryptCompactWithPlatformKey`. This class runs only the platform call: every JOSE check
 * (allow-lists, key binding, `epk` validation, the KDF, content decryption, verify after sign)
 * stays in polyjose (ADR 0071 §2–§4).
 *
 * - **One algorithm per key** (RFC 8725 §3.1): a signing algorithm, `ECDH-ES` (which serves
 *   `ECDH-ES` and `ECDH-ES+A128KW`/`A192KW`/`A256KW`, RFC 7518 §4.6) or `RSA-OAEP-256`
 *   (RFC 7518 §4.3). The key has one purpose, exactly that algorithm's digest and padding, and
 *   never `DIGEST_NONE` or raw RSA.
 * - **API levels** (ADR 0072 §2; minSdk stays 23): ES256/384/512, RS* and PS* from 23; ECDH-ES
 *   from 31; RSA-OAEP-256 from 34, for keys generated on 34 or later. StrongBox (from 28) serves
 *   ES256, RS256 and PS256 at 2048 bits, ECDH-ES on P-256 (31), and RSA-OAEP-256 at 2048 bits
 *   (34; not verified on a StrongBox device). Anything else is `UnsupportedAlgorithm` from
 *   [generate] or [open], never at first use.
 * - **Blocking.** A key that needs user authentication may block its thread inside a polyjose call
 *   while a prompt is up (ADR 0072 §4). Call polyjose off the main thread.
 * - **Errors** (ADR 0071 §6): no key under the alias, or a key the platform invalidated, is
 *   `KeyNotFound`; a user who has not authenticated is `UserAuthenticationRequired`; anything
 *   else is `PlatformKeyFailed` (when signing) or `DecryptionFailed` (when decrypting, RFC 7516
 *   §11.5). No platform message is ever kept.
 * - **Printing** shows the type and [securityLevel] only, never the alias or the public key
 *   (ADR 0071 §7).
 */
class AndroidKeystoreKey private constructor(
    private val parameters: KeyParameters,
    private val privateKey: PrivateKey,
    private val publicKey: PublicKey,
    private val jwk: String,
    /** Per-use authentication: each operation first goes through [authorizer] (ADR 0072 §4). */
    private val perUse: Boolean,
    private val authorizer: PlatformKeyAuthorizer?,
    /**
     * Where the key lives, as the platform reports it in `KeyInfo` (API 31+), never as requested
     * (ADR 0072 §3).
     */
    val securityLevel: SecurityLevel,
) : PlatformKey {

    /** Whether to ask for StrongBox (ADR 0072 §3): there is never a silent downgrade. */
    enum class StrongBox {
        /** The TEE. StrongBox is never asked for. */
        Off,

        /**
         * StrongBox when the device has it and it can serve the algorithm, else the TEE; the key's
         * [securityLevel] says which (both are hardware on a real device).
         */
        Preferred,

        /**
         * StrongBox or nothing: `generate` fails with `PlatformKeyFailed` when the device has no
         * StrongBox, and with `UnsupportedAlgorithm` when StrongBox can't serve the algorithm.
         */
        Required,
    }

    /**
     * Where the key lives, read from `KeyInfo` (ADR 0072 §2). An emulator's keys are software
     * whatever it reports: an emulator run is never hardware evidence (ADR 0072 §6).
     */
    enum class SecurityLevel {
        /** A StrongBox secure element (`SECURITY_LEVEL_STRONGBOX`, API 31+). */
        StrongBox,

        /** The trusted execution environment (`SECURITY_LEVEL_TRUSTED_ENVIRONMENT`, API 31+). */
        TrustedEnvironment,

        /** Not in secure hardware (`SECURITY_LEVEL_SOFTWARE`, or `isInsideSecureHardware` false). */
        Software,

        /** Secure hardware of a kind the platform doesn't say: below API 31, or `SECURITY_LEVEL_UNKNOWN_SECURE`. */
        SecureHardware,

        /** The platform reports no level (`SECURITY_LEVEL_UNKNOWN`). */
        Unknown,
    }

    /**
     * User authentication for a new key (ADR 0072 §4). The device needs a secure lock screen.
     *
     * - [validitySeconds] > 0, **time-bound**: the app shows its own `BiometricPrompt` (or the
     *   device credential screen); the key then works for that many seconds. Outside the window a
     *   call fails with `UserAuthenticationRequired`. Every key kind.
     * - [validitySeconds] = 0, **per use**: each sign or decrypt goes through the
     *   [PlatformKeyAuthorizer] given to [generate] or [open], which authenticates the operation's
     *   `CryptoObject`. Signing and RSA-OAEP-256 keys only, API 28+; an ECDH key is time-bound only
     *   (`UnsupportedAlgorithm`).
     * - [allowDeviceCredential]: the PIN, pattern or password may stand in for a strong biometric.
     *   Below API 30 the platform decides it (a time-bound key admits the credential, a per-use key
     *   doesn't); asking for the other choice there is `UnsupportedAlgorithm`.
     */
    class UserAuthentication(
        val validitySeconds: Int,
        val allowDeviceCredential: Boolean,
    ) {
        init {
            require(validitySeconds >= 0) { "validitySeconds must be 0 (per use) or more (time-bound)" }
        }

        override fun toString(): String = "UserAuthentication(validitySeconds=$validitySeconds, allowDeviceCredential=$allowDeviceCredential)"
    }

    /** The key's public JWK as JSON text, public members only (RFC 7517 §4; RFC 7518 §6.2.1, §6.3.1). */
    override fun publicJwk(): String = jwk

    /** The one JOSE algorithm this key serves, or the ECDH-ES family (RFC 7518 §4.6). */
    override fun algorithms(): List<String> = parameters.algorithms

    /**
     * Signs the JWS Signing Input (RFC 7515 §5.1) with the Keystore's `Signature`, which hashes it:
     * DER `Ecdsa-Sig-Value` for ES* (RFC 3279 §2.2.3), PKCS #1 v1.5 for RS* (RFC 7518 §3.3), PSS
     * with MGF1 of the same hash and a salt of the hash length for PS* (RFC 7518 §3.5).
     */
    override fun sign(alg: String, signingInput: ByteArray): ByteArray = platformCall {
        if (parameters.family == KeyFamily.Ecdh || parameters.family == KeyFamily.RsaOaep || alg != parameters.algorithm) {
            throw PlatformKeyException.Failed()
        }
        val signature = Signature.getInstance(parameters.jcaSignature)
        signature.initSign(privateKey)
        if (perUse) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) throw PlatformKeyException.Failed()
            authorize(BiometricPrompt.CryptoObject(signature))
        }
        signature.update(signingInput)
        signature.sign()
    }

    /**
     * ECDH (RFC 7518 §4.6.2) with the validated `epk` point `0x04 ‖ X ‖ Y` (SEC 1 §2.3.3), on the
     * key's own curve; returns Z, the shared point's x-coordinate.
     */
    override fun agree(peerPublicKey: ByteArray): ByteArray = platformCall {
        if (parameters.family != KeyFamily.Ecdh) throw PlatformKeyException.Failed()
        val params = (publicKey as ECPublicKey).params
        val size = (params.curve.field.fieldSize + 7) / 8
        if (peerPublicKey.size != 1 + 2 * size || peerPublicKey[0] != 4.toByte()) throw PlatformKeyException.Failed()
        val point = ECPoint(
            BigInteger(1, peerPublicKey.copyOfRange(1, 1 + size)),
            BigInteger(1, peerPublicKey.copyOfRange(1 + size, 1 + 2 * size)),
        )
        val peer = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(ECPublicKeySpec(point, params))
        val agreement = KeyAgreement.getInstance("ECDH", KEYSTORE)
        agreement.init(privateKey)
        agreement.doPhase(peer, true)
        agreement.generateSecret()
    }

    /**
     * RSAES-OAEP decryption of the JWE Encrypted Key with SHA-256 and MGF1-SHA-256, empty label
     * (RFC 7518 §4.3). Never MGF1-SHA-1, never raw RSA. Any failure is `Failed`, which polyjose
     * reports as `DecryptionFailed` (RFC 7516 §11.5).
     */
    override fun decryptKey(alg: String, encryptedKey: ByteArray): ByteArray = platformCall {
        if (parameters.family != KeyFamily.RsaOaep || alg != "RSA-OAEP-256") throw PlatformKeyException.Failed()
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            privateKey,
            OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT),
        )
        if (perUse) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) throw PlatformKeyException.Failed()
            authorize(BiometricPrompt.CryptoObject(cipher))
        }
        cipher.doFinal(encryptedKey)
    }

    /** The type and [securityLevel] only: no alias, no public key (ADR 0071 §7, ADR 0065). */
    override fun toString(): String = "AndroidKeystoreKey(securityLevel=$securityLevel)"

    /**
     * Hands the initialised operation to the authorizer before it runs (ADR 0072 §4); without one,
     * a per-use key can't be used. The callers check API 28, which [generate] and [open] ensure.
     */
    private fun authorize(cryptoObject: BiometricPrompt.CryptoObject) {
        val hook = authorizer ?: throw PlatformKeyException.UserAuthenticationRequired()
        hook.authorize(cryptoObject)
    }

    /** Runs a platform call; any throwable becomes one of the three [PlatformKeyException]s (ADR 0071 §5). */
    private inline fun platformCall(call: () -> ByteArray): ByteArray = try {
        call()
    } catch (t: Throwable) {
        throw classify(t).toPlatformKeyException()
    }

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"

        /**
         * Creates a key under [alias] in the Android Keystore for [algorithm] (ADR 0072 §2).
         *
         * @param algorithm a JOSE name: ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384,
         *   PS512, `ECDH-ES` (the whole ECDH-ES family) or RSA-OAEP-256.
         * @param strongBox [StrongBox.Off] (the default), [StrongBox.Preferred] or [StrongBox.Required].
         * @param userAuthentication null for none, else time-bound or per use.
         * @param keySize RSA modulus bits (2048, the default, 3072 or 4096; StrongBox: 2048), or the
         *   ECDH-ES curve (256, the default, for P-256; 384; 521). ES256/384/512 imply their curve.
         * @param authorizer for a per-use key: shows the prompt for each operation.
         * @throws PolyjoseException `UnsupportedAlgorithm` when the device's API level or the
         *   chosen backend can't serve the algorithm or the authentication mode, also when an
         *   RSA-OAEP-256 key fails its self-test (ADR 0072 §5); `PlatformKeyFailed` when [alias]
         *   already holds a key (delete it first), StrongBox is required and absent, or the
         *   platform fails. A failed `generate` leaves no key under [alias].
         *
         * An RSA-OAEP-256 key without user authentication is checked before it is returned: 32
         * random bytes (an A256GCM content key) are encrypted to its public key by polyjose and
         * decrypted by the Keystore. A key with user authentication can't be checked this way.
         */
        @JvmStatic
        @JvmOverloads
        fun generate(
            alias: String,
            algorithm: String,
            strongBox: StrongBox = StrongBox.Off,
            userAuthentication: UserAuthentication? = null,
            keySize: Int? = null,
            authorizer: PlatformKeyAuthorizer? = null,
        ): AndroidKeystoreKey = generateKey(alias, algorithm, strongBox, userAuthentication, keySize, authorizer) { it }

        /**
         * Finds the key under [alias] again, for [algorithm] (ADR 0072 §2). The key must permit the
         * algorithm (`KeyInfo`: purpose, digest, padding, key type and size).
         *
         * @param authorizer for a per-use key: shows the prompt for each operation.
         * @throws PolyjoseException `KeyNotFound` when there is no key under [alias] or the platform
         *   has invalidated it; `KeyAlgorithmMismatch` when the key doesn't permit [algorithm];
         *   `UnsupportedAlgorithm` when the device's API level can't serve it; `PlatformKeyFailed`
         *   when the platform fails.
         */
        @JvmStatic
        @JvmOverloads
        fun open(alias: String, algorithm: String, authorizer: PlatformKeyAuthorizer? = null): AndroidKeystoreKey {
            if (algorithm !in KeyParameters.NAMES) throw unsupportedAlgorithm()
            return keystoreCall { load(keyStore(), alias, algorithm, authorizer) }
        }

        /**
         * Deletes the key under [alias]; nothing happens when there is none.
         *
         * @throws PolyjoseException `PlatformKeyFailed` when the platform fails.
         */
        @JvmStatic
        fun delete(alias: String) {
            keystoreCall { keyStore().deleteEntry(alias) }
        }

        /** [generate], with the self-test's key passed through [selfTestKey] (a test seam). */
        internal fun generateKey(
            alias: String,
            algorithm: String,
            strongBox: StrongBox,
            userAuthentication: UserAuthentication?,
            keySize: Int?,
            authorizer: PlatformKeyAuthorizer?,
            selfTestKey: (PlatformKey) -> PlatformKey,
        ): AndroidKeystoreKey {
            val p = KeyParameters.of(algorithm, keySize)
            val api = Build.VERSION.SDK_INT
            requireSupported(p, api, strongBox == StrongBox.Required)
            requireAuthenticationSupported(p, userAuthentication, api)
            val store = keystoreCall { keyStore() }
            // Never replace an existing key, so a failed generate can always clean up its alias.
            if (keystoreCall { store.containsAlias(alias) }) throw KeyFailure.Failed.toPolyjoseException()
            val tryStrongBox = when (strongBox) {
                StrongBox.Off -> false
                StrongBox.Required -> true
                StrongBox.Preferred -> isSupported(p, api, true)
            }
            try {
                createPair(alias, p, tryStrongBox, userAuthentication)
            } catch (first: Throwable) {
                discard(store, alias)
                if (strongBox != StrongBox.Preferred || !tryStrongBox) throw classify(first).toPolyjoseException()
                // Preferred: the TEE, reported as such by securityLevel (ADR 0072 §3, F2).
                try {
                    createPair(alias, p, false, userAuthentication)
                } catch (second: Throwable) {
                    discard(store, alias)
                    throw classify(second).toPolyjoseException()
                }
            }
            val key = try {
                load(store, alias, algorithm, authorizer)
            } catch (t: Throwable) {
                discard(store, alias)
                throw if (t is PolyjoseException) t else classify(t).toPolyjoseException()
            }
            if (p.family == KeyFamily.RsaOaep && userAuthentication == null && !selfTest(selfTestKey(key))) {
                discard(store, alias)
                throw unsupportedAlgorithm()
            }
            return key
        }

        /**
         * ADR 0072 §5: polyjose encrypts an A256GCM content key (32 random bytes) to the key's public
         * JWK with RSA-OAEP-256 in pure Rust, and the Keystore decrypts it. A HAL that can't do
         * MGF1-SHA-256 fails here, whatever the device's API level.
         */
        private fun selfTest(key: PlatformKey): Boolean = try {
            val plaintext = "polyjose RSA-OAEP-256 self-test".toByteArray()
            val token = jweEncryptCompact(
                plaintext,
                JweEncryptOptions(enc = "A256GCM", recipients = listOf(JweRecipient(alg = "RSA-OAEP-256", key = key.publicJwk()))),
            )
            val decrypted = jweDecryptCompactWithPlatformKey(
                token, key, JweDecryptOptions(allowedAlgs = listOf("RSA-OAEP-256"), allowedEnc = listOf("A256GCM")),
            )
            decrypted.plaintext.contentEquals(plaintext)
        } catch (_: Throwable) {
            false
        }

        private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

        /** Deletes what a failed generate may have left under [alias] (which held no key before). */
        private fun discard(store: KeyStore, alias: String) {
            try {
                store.deleteEntry(alias)
            } catch (_: Throwable) {
                // Nothing more can be done; the original failure is reported.
            }
        }

        /** Runs a Keystore call of generate, open or delete; a throwable becomes a [PolyjoseException]. */
        private inline fun <T> keystoreCall(call: () -> T): T = try {
            call()
        } catch (e: PolyjoseException) {
            throw e
        } catch (t: Throwable) {
            throw classify(t).toPolyjoseException()
        }

        private fun createPair(alias: String, p: KeyParameters, strongBox: Boolean, auth: UserAuthentication?) {
            KeyPairGenerator.getInstance(p.keyAlgorithm, KEYSTORE).run {
                initialize(keyGenSpec(alias, p, strongBox, auth))
                generateKeyPair()
            }
        }

        /** `PURPOSE_AGREE_KEY` (API 31), `PURPOSE_DECRYPT` or `PURPOSE_SIGN`: one purpose per key. */
        internal fun purposeOf(p: KeyParameters): Int = when (p.family) {
            KeyFamily.EcSign, KeyFamily.RsaSign -> KeyProperties.PURPOSE_SIGN
            KeyFamily.RsaOaep -> KeyProperties.PURPOSE_DECRYPT
            KeyFamily.Ecdh -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) KeyProperties.PURPOSE_AGREE_KEY else throw unsupportedAlgorithm()
        }

        /**
         * The fixed `KeyGenParameterSpec` of ADR 0072 §2: one purpose, the curve or RSA size with
         * public exponent 65537, exactly the algorithm's digest and padding, on API 35+
         * `setMgf1Digests(SHA-256)` for RSA-OAEP-256, StrongBox when asked, and the user
         * authentication of ADR 0072 §4.
         */
        internal fun keyGenSpec(alias: String, p: KeyParameters, strongBox: Boolean, auth: UserAuthentication?): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias, purposeOf(p))
            b.setAlgorithmParameterSpec(
                if (p.isRsa) RSAKeyGenParameterSpec(p.keySize, RSAKeyGenParameterSpec.F4) else ECGenParameterSpec(p.curveName),
            )
            p.digest?.let { b.setDigests(it) }
            p.signaturePadding?.let { b.setSignaturePaddings(it) }
            p.encryptionPadding?.let { b.setEncryptionPaddings(it) }
            if (p.family == KeyFamily.RsaOaep && Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                // The default MGF1 digest is SHA-1, which is not RSA-OAEP-256 (RFC 7518 §4.3).
                b.setMgf1Digests(KeyProperties.DIGEST_SHA256)
            }
            if (strongBox) {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) throw unsupportedAlgorithm()
                b.setIsStrongBoxBacked(true)
            }
            if (auth != null) {
                b.setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val types = KeyProperties.AUTH_BIOMETRIC_STRONG or (if (auth.allowDeviceCredential) KeyProperties.AUTH_DEVICE_CREDENTIAL else 0)
                    b.setUserAuthenticationParameters(auth.validitySeconds, types)
                } else {
                    // Below API 30: a duration (any authenticator), or -1 for every use (biometric).
                    @Suppress("DEPRECATION")
                    b.setUserAuthenticationValidityDurationSeconds(if (auth.validitySeconds == 0) -1 else auth.validitySeconds)
                }
            }
            return b.build()
        }

        /** The `KeyInfo` of a Keystore private key. */
        internal fun keyInfo(key: PrivateKey): KeyInfo =
            KeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java)

        /** [SecurityLevel] from `KeyInfo` (ADR 0072 §2). */
        internal fun securityLevelOf(info: KeyInfo): SecurityLevel {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                return when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.StrongBox
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TrustedEnvironment
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> SecurityLevel.Software
                    KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> SecurityLevel.SecureHardware
                    else -> SecurityLevel.Unknown
                }
            }
            @Suppress("DEPRECATION")
            return if (info.isInsideSecureHardware) SecurityLevel.SecureHardware else SecurityLevel.Software
        }

        /**
         * The key under [alias], checked against [algorithm] through `KeyInfo` (ADR 0072 §2), and
         * against the API-level table for the backend it lives in.
         */
        private fun load(store: KeyStore, alias: String, algorithm: String, authorizer: PlatformKeyAuthorizer?): AndroidKeystoreKey {
            val privateKey = store.getKey(alias, null) as? PrivateKey ?: throw AliasNotFound()
            val publicKey = store.getCertificate(alias)?.publicKey ?: throw AliasNotFound()
            val info = keyInfo(privateKey)
            if (privateKey.algorithm != KeyParameters.of(algorithm, null).keyAlgorithm) throw keyAlgorithmMismatch()
            val size = if (publicKey is ECPublicKey) publicKey.params.curve.field.fieldSize else info.keySize
            val p = try {
                KeyParameters.of(algorithm, size)
            } catch (_: PolyjoseException.UnsupportedAlgorithm) {
                throw keyAlgorithmMismatch()
            }
            val level = securityLevelOf(info)
            requireSupported(p, Build.VERSION.SDK_INT, level == SecurityLevel.StrongBox)
            if (info.purposes and purposeOf(p) == 0) throw keyAlgorithmMismatch()
            if (p.digest != null && p.digest !in info.digests) throw keyAlgorithmMismatch()
            if (p.signaturePadding != null && p.signaturePadding !in info.signaturePaddings) throw keyAlgorithmMismatch()
            if (p.encryptionPadding != null && p.encryptionPadding !in info.encryptionPaddings) throw keyAlgorithmMismatch()
            val perUse = info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds <= 0
            if (perUse) requireAuthenticationSupported(p, UserAuthentication(0, Build.VERSION.SDK_INT >= AUTH_PARAMETERS_MIN_API), Build.VERSION.SDK_INT)
            // The certificate's public key is SubjectPublicKeyInfo DER (RFC 5280 §4.1.2.7).
            val jwk = jwkFromDer(publicKey.encoded, "spki")
            return AndroidKeystoreKey(p, privateKey, publicKey, jwk, perUse, authorizer, level)
        }
    }
}
