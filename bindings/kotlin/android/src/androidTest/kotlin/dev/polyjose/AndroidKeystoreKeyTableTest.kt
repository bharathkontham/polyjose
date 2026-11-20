package dev.polyjose

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.ProviderException
import java.security.SignatureException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The pure parts of [AndroidKeystoreKey] on the device (feature 0025 T04): the ADR 0072 §2
 * capability table for every (algorithm, API level 23–36, StrongBox on or off), the user
 * authentication limits of ADR 0072 §4, and the error mapping of ADR 0072 §2. None of these
 * depends on the device's own API level.
 */
class AndroidKeystoreKeyTableTest {
    /** One row of the ADR 0072 §2 table, written out here independently of the code. */
    private data class Row(val alg: String, val size: Int, val tee: Int?, val strongBox: Int?)

    private val oaep = RSA_OAEP_256_MIN_API

    private val table: List<Row> = buildList {
        add(Row("ES256", 256, 23, 28))
        add(Row("ES384", 384, 23, null))
        add(Row("ES512", 521, 23, null))
        for (alg in listOf("RS256", "PS256")) {
            add(Row(alg, 2048, 23, 28))
            add(Row(alg, 3072, 23, null))
            add(Row(alg, 4096, 23, null))
        }
        for (alg in listOf("RS384", "RS512", "PS384", "PS512")) for (size in listOf(2048, 3072, 4096)) add(Row(alg, size, 23, null))
        add(Row("ECDH-ES", 256, 31, 31))
        add(Row("ECDH-ES", 384, 31, null))
        add(Row("ECDH-ES", 521, 31, null))
        add(Row("RSA-OAEP-256", 2048, oaep, oaep))
        add(Row("RSA-OAEP-256", 3072, oaep, null))
        add(Row("RSA-OAEP-256", 4096, oaep, null))
    }

    @Test
    fun theRsaOaep256FloorIsOneConstantOf34Or35() {
        // ADR 0072 §5: 34 only with a passing API 34 run, else 35.
        assertTrue("RSA_OAEP_256_MIN_API is $oaep", oaep == 34 || oaep == 35)
    }

    @Test
    fun everyAlgorithmApiLevelAndBackendMatchesTheTable() {
        var checked = 0
        for (row in table) {
            val p = KeyParameters.of(row.alg, row.size)
            for (api in 23..36) for (strongBox in listOf(false, true)) {
                val min = if (strongBox) row.strongBox else row.tee
                val expected = min != null && api >= min
                val what = "${row.alg}/${row.size} API $api StrongBox=$strongBox"
                assertEquals(what, expected, isSupported(p, api, strongBox))
                if (expected) {
                    requireSupported(p, api, strongBox)
                } else {
                    expectUnsupported(what) { requireSupported(p, api, strongBox) }
                }
                checked++
            }
        }
        assertEquals(table.size * 14 * 2, checked)
        // Every name `generate` accepts has rows, and no row is outside them.
        assertEquals(KeyParameters.NAMES.toSet(), table.map { it.alg }.toSet())
    }

    @Test
    fun anythingElseIsUnsupportedAlgorithm() {
        for (alg in listOf("EdDSA", "ES256K", "HS256", "RSA1_5", "RSA-OAEP", "A256KW", "dir", "ECDH-ES+A128KW", "none", "es256", "")) {
            expectUnsupported(alg) { KeyParameters.of(alg, null) }
        }
        for ((alg, size) in listOf("ES256" to 384, "ES384" to 256, "ES512" to 512, "RS256" to 1024, "PS256" to 8192, "ECDH-ES" to 224, "RSA-OAEP-256" to 1024)) {
            expectUnsupported("$alg/$size") { KeyParameters.of(alg, size) }
        }
        // The defaults: RSA 2048, ECDH-ES on P-256; ES* imply their curve.
        assertEquals(2048, KeyParameters.of("RS256", null).keySize)
        assertEquals(2048, KeyParameters.of("RSA-OAEP-256", null).keySize)
        assertEquals(256, KeyParameters.of("ECDH-ES", null).keySize)
        assertEquals(521, KeyParameters.of("ES512", null).keySize)
        assertEquals(KeyParameters.ECDH_ES_FAMILY, KeyParameters.of("ECDH-ES", 384).algorithms)
        assertEquals(listOf("PS384"), KeyParameters.of("PS384", 3072).algorithms)
    }

    @Test
    fun generateAndOpenConsultTheTableFirst() {
        val alias = "polyjose-table-" + java.util.UUID.randomUUID()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        // StrongBox can't hold ES384 on any device: refused before the Keystore is asked.
        expectUnsupported("ES384 Required") { AndroidKeystoreKey.generate(alias, "ES384", AndroidKeystoreKey.StrongBox.Required) }
        expectUnsupported("EdDSA") { AndroidKeystoreKey.generate(alias, "EdDSA") }
        expectUnsupported("RS256/1024") { AndroidKeystoreKey.generate(alias, "RS256", keySize = 1024) }
        expectUnsupported("open EdDSA") { AndroidKeystoreKey.open(alias, "EdDSA") }
        assertFalse("a refused generate left a key", store.containsAlias(alias))
    }

    @Test
    fun userAuthenticationLimits() {
        val perUse = AndroidKeystoreKey.UserAuthentication(0, allowDeviceCredential = true)
        val perUseBiometric = AndroidKeystoreKey.UserAuthentication(0, allowDeviceCredential = false)
        val timeBound = AndroidKeystoreKey.UserAuthentication(30, allowDeviceCredential = true)
        val timeBoundBiometric = AndroidKeystoreKey.UserAuthentication(30, allowDeviceCredential = false)
        val ecdh = KeyParameters.of("ECDH-ES", null)
        val es256 = KeyParameters.of("ES256", null)
        val oaepKey = KeyParameters.of("RSA-OAEP-256", null)
        for (api in 23..36) {
            // ECDH keys are time-bound only (ADR 0072 §4, S4).
            expectUnsupported("ECDH per use, API $api") { requireAuthenticationSupported(ecdh, perUse, api) }
            expectUnsupported("ECDH per use (biometric), API $api") { requireAuthenticationSupported(ecdh, perUseBiometric, api) }
            requireAuthenticationSupported(es256, null, api)
            for (p in listOf(es256, oaepKey)) {
                val what = "${p.algorithm} API $api"
                when {
                    api < 28 -> {
                        expectUnsupported("$what per use") { requireAuthenticationSupported(p, perUseBiometric, api) }
                        expectUnsupported("$what per use + credential") { requireAuthenticationSupported(p, perUse, api) }
                    }
                    api < 30 -> {
                        requireAuthenticationSupported(p, perUseBiometric, api)
                        expectUnsupported("$what per use + credential") { requireAuthenticationSupported(p, perUse, api) }
                    }
                    else -> {
                        requireAuthenticationSupported(p, perUseBiometric, api)
                        requireAuthenticationSupported(p, perUse, api)
                    }
                }
            }
            for (p in listOf(es256, oaepKey, ecdh)) {
                requireAuthenticationSupported(p, timeBound, api)
                if (api < 30) {
                    expectUnsupported("${p.algorithm} API $api time-bound biometric only") { requireAuthenticationSupported(p, timeBoundBiometric, api) }
                } else {
                    requireAuthenticationSupported(p, timeBoundBiometric, api)
                }
            }
        }
        try {
            AndroidKeystoreKey.UserAuthentication(-1, true)
            fail("a negative validity was accepted")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun throwablesMapToTheThreeOutcomes() {
        val m = MARKER
        val cases: List<Pair<Throwable, KeyFailure>> = listOf(
            AliasNotFound() to KeyFailure.NotFound,
            KeyPermanentlyInvalidatedException("lock screen removed $m") to KeyFailure.NotFound,
            UserNotAuthenticatedException("not authenticated $m") to KeyFailure.UserAuthenticationRequired,
            StrongBoxUnavailableException("no StrongBox $m") to KeyFailure.Failed,
            KeyStoreException("keystore $m") to KeyFailure.Failed,
            ProviderException("provider $m") to KeyFailure.Failed,
            InvalidKeyException("invalid $m") to KeyFailure.Failed,
            SignatureException("signature $m") to KeyFailure.Failed,
            IllegalStateException("state $m") to KeyFailure.Failed,
            RuntimeException("runtime $m") to KeyFailure.Failed,
            OutOfMemoryError("oom $m") to KeyFailure.Failed,
            // Wrapped: the cause chain decides.
            SignatureException("wrapped $m", UserNotAuthenticatedException(m)) to KeyFailure.UserAuthenticationRequired,
            ProviderException("wrapped $m", KeyPermanentlyInvalidatedException(m)) to KeyFailure.NotFound,
            // An authorizer's own outcome keeps its kind.
            PlatformKeyException.UserAuthenticationRequired() to KeyFailure.UserAuthenticationRequired,
            PlatformKeyException.NotFound() to KeyFailure.NotFound,
            PlatformKeyException.Failed() to KeyFailure.Failed,
        )
        for ((thrown, expected) in cases) {
            val outcome = classify(thrown)
            assertEquals(thrown.javaClass.simpleName, expected, outcome)
            for (e in listOf<Throwable>(outcome.toPlatformKeyException(), outcome.toPolyjoseException())) {
                assertEquals(null, e.cause)
                for (text in listOf(e.message, e.localizedMessage, e.toString())) {
                    assertFalse("${thrown.javaClass.simpleName}: the platform text reached $text", text?.contains(MARKER) == true)
                }
            }
        }
        // The codes and fixed messages (ADR 0071 §6).
        assertEquals("KeyNotFound", KeyFailure.NotFound.toPolyjoseException().code())
        assertEquals("UserAuthenticationRequired", KeyFailure.UserAuthenticationRequired.toPolyjoseException().code())
        assertEquals("PlatformKeyFailed", KeyFailure.Failed.toPolyjoseException().code())
        assertTrue(KeyFailure.NotFound.toPlatformKeyException() is PlatformKeyException.NotFound)
        assertTrue(KeyFailure.UserAuthenticationRequired.toPlatformKeyException() is PlatformKeyException.UserAuthenticationRequired)
        assertTrue(KeyFailure.Failed.toPlatformKeyException() is PlatformKeyException.Failed)
        assertEquals("unsupported algorithm", unsupportedAlgorithm().detail)
    }

    companion object {
        const val MARKER = "keystore-exception-marker-7a31"

        fun expectUnsupported(what: String, call: () -> Unit) {
            try {
                call()
            } catch (e: PolyjoseException.UnsupportedAlgorithm) {
                assertEquals("$what: the message", KeystoreMessages.UNSUPPORTED_ALGORITHM, e.detail)
                assertEquals("UnsupportedAlgorithm", e.code())
                return
            }
            fail("$what: not refused")
        }
    }
}
