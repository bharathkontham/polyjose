# R8/ProGuard rules shipped in the AAR (proguard.txt) and applied to every app that minifies with
# polyjose (ADR 0033 §2). The generated Kotlin calls Rust through JNA direct mapping, which finds
# native methods, Structure fields and callbacks by reflection, so none of them may be renamed or
# removed. The JNA rules follow JNA's FAQ ("How do I use JNA with ProGuard/R8?").

# JNA itself, and every class that extends or implements a JNA type (RustBuffer, ForeignBytes,
# the UniFFI callback interfaces and the Library interfaces).
-keep class com.sun.jna.** { *; }
-keep class * extends com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }

# The generated API and its FFI glue: `Native.register` binds the `external fun`s of UniffiLib by
# name, and `code()` is the stable error contract (ADR 0033 §3).
-keep class dev.polyjose.** { *; }

# JNA reads @Structure.FieldOrder and its other annotations at run time; AGP 9's R8 is reported
# to strip them from UniFFI/JNA code (0008 research §5).
-keepattributes RuntimeVisibleAnnotations,RuntimeVisibleParameterAnnotations,AnnotationDefault,Signature,InnerClasses,EnclosingMethod,Exceptions

# JNA's desktop helpers reference AWT, which Android does not have.
-dontwarn java.awt.**
