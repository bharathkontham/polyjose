# R8 rules for the test APK only (testBuildType "release" minifies it too); the app under test is
# shrunk by proguard-rules.pro and the AAR's consumer rules alone.

# androidx.test refers to errorprone's compile-only annotations, which are not on the classpath.
-dontwarn com.google.errorprone.annotations.**

# The instrumented test itself, which AndroidJUnitRunner finds by reflection.
-keep class dev.polyjose.sample.R8ProbeTest { *; }
