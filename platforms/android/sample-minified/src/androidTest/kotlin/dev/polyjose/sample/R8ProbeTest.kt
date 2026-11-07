package dev.polyjose.sample

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Runs on the emulator against the minified release build of the sample (testBuildType
 * "release"): if R8 had removed or renamed what JNA or the UniFFI-generated Kotlin need, these
 * calls would fail to load the library, bind a native method or read a `Structure` (ADR 0033 §2).
 * AndroidJUnitRunner runs it as a plain JUnit 4 class.
 */
class R8ProbeTest {
    /** The library loads through JNA and returns a version string (ADR 0030 §4). */
    @Test
    fun theLibraryLoadsAndReportsItsVersion() {
        assertTrue(R8Probe.libraryVersion().isNotEmpty())
    }

    /** An ES256 compact JWS round trip returns the signed payload (RFC 7515 §7.1, RFC 7518 §3.4). */
    @Test
    fun anEs256RoundTripReturnsThePayload() {
        val payload = "polyjose R8 sample".toByteArray()
        assertArrayEquals(payload, R8Probe.es256RoundTrip(payload))
    }

    /** A JWK that is not JSON fails with the stable code InvalidJson (RFC 7517 §4, ADR 0033 §3). */
    @Test
    fun anInvalidJwkIsReportedByItsCode() {
        assertEquals("InvalidJson", R8Probe.invalidJwkCode())
    }
}
