# The sample's own rules: only its entry point, as a real app's reachable code would be. Nothing
# here keeps polyjose or JNA; that is the job of the AAR's consumer rules under test
# (polyjose/consumer-rules.pro, ADR 0033 §2).
-keep class dev.polyjose.sample.R8Probe { public *; }

# The test APK's androidx.test runs against the app's copy of the Kotlin standard library (AGP
# leaves dependencies shared with the app out of the test APK), and R8 would remove the parts the
# app itself does not use (measured: kotlin.jvm.internal.Lambda, a crash in AndroidJUnitRunner).
# This keeps nothing of polyjose or JNA.
-keep class kotlin.** { *; }
