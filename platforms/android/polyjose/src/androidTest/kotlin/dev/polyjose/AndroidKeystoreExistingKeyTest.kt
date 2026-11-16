package dev.polyjose

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.UUID
import javax.crypto.KeyGenerator
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * A key the app created itself with plain `KeyPairGenerator` and `KeyGenParameterSpec`, not through
 * polyjose, then opened with [AndroidKeystoreKey.open] (feature 0025 B04; ADR 0072 §2): which
 * `KeyGenParameterSpec` settings each algorithm needs (`open` checks them through `KeyInfo`), and
 * the error when the key doesn't permit the algorithm (RFC 8725 §3.1). Encrypting to the device
 * needs only the key's public JWK (RFC 7516 §5.1). The AVD's KeyMint is software: a pass here
 * proves function, not hardware (ADR 0072 §6).
 */
class AndroidKeystoreExistingKeyTest {
    private val store: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val aliases = mutableListOf<String>()

    private fun alias(): String = ("polyjose-b04-" + UUID.randomUUID()).also { aliases += it }

    @After
    fun deleteKeys() {
        for (a in aliases) store.deleteEntry(a)
    }

    /** An EC key pair under a new alias, made the way an app would, without polyjose. */
    private fun ecKey(curve: String, purposes: Int, configure: KeyGenParameterSpec.Builder.() -> Unit): String {
        val alias = alias()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(KeyGenParameterSpec.Builder(alias, purposes).setAlgorithmParameterSpec(ECGenParameterSpec(curve)).apply(configure).build())
            generateKeyPair()
        }
        return alias
    }

    /** An RSA key pair (public exponent 65537) under a new alias, made without polyjose. */
    private fun rsaKey(bits: Int, purposes: Int, configure: KeyGenParameterSpec.Builder.() -> Unit): String {
        val alias = alias()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore").run {
            initialize(
                KeyGenParameterSpec.Builder(alias, purposes)
                    .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4)).apply(configure).build(),
            )
            generateKeyPair()
        }
        return alias
    }

    /** A JWT signed by [key] (RFC 7519 §7.1) that verifies with its public JWK alone. */
    private fun signsAJwt(key: AndroidKeystoreKey, alg: String) {
        val jwt = jwtSignWithPlatformKey(CLAIMS, key, JwtSignOptions(alg = alg))
        val claims = jwtVerify(jwt, key.publicJwk(), verifyOptions(alg)).claims
        assertEquals("$alg: claims", CLAIMS, claims)
    }

    private fun verifyOptions(alg: String) = JwtVerifyOptions(allowedAlgs = listOf(alg), now = 1_700_000_000L, allowMissingExp = true)

    private fun decryptOptions(alg: String) = JweDecryptOptions(allowedAlgs = listOf(alg), allowedEnc = listOf("A256GCM"))

    /** Encrypted to the public JWK only, as a server would (RFC 7516 §5.1), then decrypted by [key]. */
    private fun decryptsAJweAndANestedJwt(key: AndroidKeystoreKey, alg: String) {
        val recipients = JweEncryptOptions(enc = "A256GCM", recipients = listOf(JweRecipient(alg = alg, key = key.publicJwk())))
        val jwe = jweEncryptCompact(PAYLOAD, recipients)
        assertArrayEquals("$alg: plaintext", PAYLOAD, jweDecryptCompactWithPlatformKey(jwe, key, decryptOptions(alg)).plaintext)
        // A nested JWT (RFC 7519 §5.2): signed by another existing key, encrypted to this one.
        val signer = AndroidKeystoreKey.open(ecKey("secp256r1", KeyProperties.PURPOSE_SIGN) { setDigests(KeyProperties.DIGEST_SHA256) }, "ES256")
        val nested = jwtEncryptNested(jwtSignWithPlatformKey(CLAIMS, signer, JwtSignOptions(alg = "ES256")), recipients)
        val verified = jwtDecryptNestedWithPlatformKey(nested, key, decryptOptions(alg), signer.publicJwk(), verifyOptions("ES256"))
        assertEquals("$alg: nested claims", CLAIMS, verified.inner.claims)
    }

    /**
     * Signing (RFC 7518 §3.3–§3.5): `PURPOSE_SIGN` (an app's usual `PURPOSE_SIGN or PURPOSE_VERIFY`
     * is accepted), the curve or an RSA size of 2048, 3072 or 4096, the algorithm's digest, and for
     * RS* / PS* its signature padding. Extra digests and paddings are accepted: one key with
     * SHA-256 and SHA-512 and both paddings opens as RS256, PS256 and RS512.
     */
    @Test
    fun anExistingSigningKeyOpensAndSignsAJwt() {
        val signVerify = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        val ec = listOf(
            Triple("ES256", "secp256r1", KeyProperties.DIGEST_SHA256),
            Triple("ES384", "secp384r1", KeyProperties.DIGEST_SHA384),
            Triple("ES512", "secp521r1", KeyProperties.DIGEST_SHA512),
        )
        for ((alg, curve, digest) in ec) {
            val alias = ecKey(curve, signVerify) { setDigests(digest) }
            val key = AndroidKeystoreKey.open(alias, alg)
            assertEquals(listOf(alg), key.algorithms())
            Log.i(TAG, "existing $alg key: securityLevel ${key.securityLevel}")
            signsAJwt(key, alg)
        }
        val rs256 = rsaKey(2048, KeyProperties.PURPOSE_SIGN) {
            setDigests(KeyProperties.DIGEST_SHA256)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        }
        signsAJwt(AndroidKeystoreKey.open(rs256, "RS256"), "RS256")
        val ps256 = rsaKey(3072, KeyProperties.PURPOSE_SIGN) {
            setDigests(KeyProperties.DIGEST_SHA256)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
        }
        signsAJwt(AndroidKeystoreKey.open(ps256, "PS256"), "PS256")
        val both = rsaKey(2048, signVerify) {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1, KeyProperties.SIGNATURE_PADDING_RSA_PSS)
        }
        for (alg in listOf("RS256", "PS256", "RS512")) signsAJwt(AndroidKeystoreKey.open(both, alg), alg)
        // The key is the app's: AndroidKeystoreKey.delete removes it like any other alias.
        AndroidKeystoreKey.delete(rs256)
        AndroidKeystoreKeyTest.expectCode("open after delete", "KeyNotFound") { AndroidKeystoreKey.open(rs256, "RS256") }
    }

    /** ECDH-ES (RFC 7518 §4.6), API 31+: `PURPOSE_AGREE_KEY` on P-256, P-384 or P-521; no digest. */
    @Test
    fun anExistingEcdhKeyDecryptsAJweAndANestedJwt() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return // PURPOSE_AGREE_KEY is API 31.
        val alias = ecKey("secp256r1", KeyProperties.PURPOSE_AGREE_KEY) {}
        val key = AndroidKeystoreKey.open(alias, "ECDH-ES")
        assertEquals(KeyParameters.ECDH_ES_FAMILY, key.algorithms())
        decryptsAJweAndANestedJwt(key, "ECDH-ES")
        decryptsAJweAndANestedJwt(key, "ECDH-ES+A256KW")
    }

    /**
     * RSA-OAEP-256 (RFC 7518 §4.3: SHA-256, MGF1 with SHA-256), API 34+: `PURPOSE_DECRYPT`,
     * `ENCRYPTION_PADDING_RSA_OAEP`, `DIGEST_SHA256`, and on API 35+ `setMgf1Digests(SHA-256)`.
     * On API 34, which has no `setMgf1Digests`, the key without it decrypts. On API 35+, `open`
     * doesn't read the MGF1 digest (ADR 0072 §5: accepted on trust): a key without it opens, and its
     * decryptions fail as `DecryptionFailed`.
     */
    @Test
    fun anExistingRsaOaep256Key() {
        if (Build.VERSION.SDK_INT < RSA_OAEP_256_MIN_API) return
        val oaep: KeyGenParameterSpec.Builder.() -> Unit = {
            setDigests(KeyProperties.DIGEST_SHA256)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            decryptsAJweAndANestedJwt(AndroidKeystoreKey.open(rsaKey(2048, KeyProperties.PURPOSE_DECRYPT, oaep), "RSA-OAEP-256"), "RSA-OAEP-256")
            Log.i(TAG, "existing RSA-OAEP-256 key without setMgf1Digests on API ${Build.VERSION.SDK_INT}: decrypts")
            return
        }
        val good = rsaKey(2048, KeyProperties.PURPOSE_DECRYPT) {
            oaep()
            setMgf1Digests(KeyProperties.DIGEST_SHA256)
        }
        decryptsAJweAndANestedJwt(AndroidKeystoreKey.open(good, "RSA-OAEP-256"), "RSA-OAEP-256")
        val noMgf1 = AndroidKeystoreKey.open(rsaKey(2048, KeyProperties.PURPOSE_DECRYPT, oaep), "RSA-OAEP-256")
        val jwe = jweEncryptCompact(
            PAYLOAD,
            JweEncryptOptions(enc = "A256GCM", recipients = listOf(JweRecipient(alg = "RSA-OAEP-256", key = noMgf1.publicJwk()))),
        )
        AndroidKeystoreKeyTest.expectCode("no MGF1-SHA-256", "DecryptionFailed") {
            jweDecryptCompactWithPlatformKey(jwe, noMgf1, decryptOptions("RSA-OAEP-256"))
        }
        Log.i(TAG, "existing RSA-OAEP-256 key without setMgf1Digests on API ${Build.VERSION.SDK_INT}: opens, DecryptionFailed")
    }

    /** A key that doesn't permit the algorithm is `KeyAlgorithmMismatch` at `open` (RFC 8725 §3.1). */
    @Test
    fun aKeyThatDoesNotPermitTheAlgorithmIsKeyAlgorithmMismatch() {
        val sign = KeyProperties.PURPOSE_SIGN
        val rows = mutableListOf<Triple<String, String, String>>(
            Triple("ES256 key with SHA-512 only", ecKey("secp256r1", sign) { setDigests(KeyProperties.DIGEST_SHA512) }, "ES256"),
            Triple("ES256 key with DIGEST_NONE only", ecKey("secp256r1", sign) { setDigests(KeyProperties.DIGEST_NONE) }, "ES256"),
            Triple("P-384 key as ES256", ecKey("secp384r1", sign) { setDigests(KeyProperties.DIGEST_SHA256) }, "ES256"),
            Triple("P-256 signing key as ECDH-ES", ecKey("secp256r1", sign) { setDigests(KeyProperties.DIGEST_SHA256) }, "ECDH-ES"),
            Triple("PKCS #1 key as PS256", rsaKey(2048, sign) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            }, "PS256"),
            Triple("RSA-1024 key as RS256", rsaKey(1024, sign) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            }, "RS256"),
            Triple("decrypting key as RS256", rsaKey(2048, KeyProperties.PURPOSE_DECRYPT) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            }, "RS256"),
            Triple("EC key as RS256", ecKey("secp256r1", sign) { setDigests(KeyProperties.DIGEST_SHA256) }, "RS256"),
        )
        if (Build.VERSION.SDK_INT >= RSA_OAEP_256_MIN_API) {
            rows += Triple("OAEP key with SHA-1 only as RSA-OAEP-256", rsaKey(2048, KeyProperties.PURPOSE_DECRYPT) {
                setDigests(KeyProperties.DIGEST_SHA1)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            }, "RSA-OAEP-256")
            rows += Triple("signing key as RSA-OAEP-256", rsaKey(2048, sign) {
                setDigests(KeyProperties.DIGEST_SHA256)
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            }, "RSA-OAEP-256")
        }
        for ((what, alias, alg) in rows) {
            AndroidKeystoreKeyTest.expectCode(what, "KeyAlgorithmMismatch") { AndroidKeystoreKey.open(alias, alg) }
        }
    }

    /**
     * What else `open` returns for an existing alias: an `ECDH-ES+A*KW` name is
     * `UnsupportedAlgorithm` (open the key as `ECDH-ES`, which serves the family), and an alias
     * holding a secret key (AES) has no private key, so it is `KeyNotFound`.
     */
    @Test
    fun otherOutcomesOfOpen() {
        val ec = ecKey("secp256r1", KeyProperties.PURPOSE_SIGN) { setDigests(KeyProperties.DIGEST_SHA256) }
        AndroidKeystoreKeyTest.expectCode("ECDH-ES+A256KW name", "UnsupportedAlgorithm") { AndroidKeystoreKey.open(ec, "ECDH-ES+A256KW") }
        val aes = alias()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(aes, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build(),
            )
            generateKey()
        }
        AndroidKeystoreKeyTest.expectCode("AES alias", "KeyNotFound") { AndroidKeystoreKey.open(aes, "ES256") }
    }

    companion object {
        const val TAG = "polyjose-t04"
        val PAYLOAD = "encrypted to an existing Android Keystore key".toByteArray()
        const val CLAIMS = """{"iss":"joe","sub":"existing-key"}"""
    }
}
