package dev.polyjose

import dev.polyjose.platformkey.PlatformKeyChecks
import org.junit.Assert.fail
import org.junit.Test

/**
 * The `PlatformKey` callback path on the device (feature 0025 T02; ADR 0071 §5): every check of the
 * shared [PlatformKeyChecks], with the software keys of `java.security` on Android. A failure names
 * each check that failed.
 */
class PlatformKeyInstrumentedTest {
    @Test
    fun everyPlatformKeyCheckPasses() {
        val failures = PlatformKeyChecks.all.mapNotNull { (name, check) ->
            try {
                check()
                null
            } catch (e: Throwable) {
                "$name: $e"
            }
        }
        if (failures.isNotEmpty()) fail(failures.joinToString("\n"))
    }
}
