# UniFFI's Kotlin bindings reach the native library through JNA, which resolves callback
# structures reflectively. Stripping these renames methods the native side looks up by name,
# and the failure appears only at runtime in a release build.
-keep class uniffi.envelock.** { *; }
-keep class network.sharering.envelock.** { *; }
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
