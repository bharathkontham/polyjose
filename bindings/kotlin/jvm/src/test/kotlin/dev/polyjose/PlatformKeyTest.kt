package dev.polyjose

import dev.polyjose.platformkey.PlatformKeyChecks
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory

/**
 * The `PlatformKey` callback path on the host JVM (feature 0025 T02; ADR 0071 §5): every check of
 * the shared [PlatformKeyChecks], as one JUnit test each.
 */
class PlatformKeyTest {
    @TestFactory
    fun platformKeyChecks(): List<DynamicTest> =
        PlatformKeyChecks.all.map { (name, check) -> DynamicTest.dynamicTest(name) { check() } }
}
