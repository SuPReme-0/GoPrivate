// Root build.gradle.kts
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.jetbrains.kotlin.android) apply false

    // 🚨 ADD THIS LINE to define the KSP version for the whole project
    // This version (1.9.22-1.0.17) matches Kotlin 1.9.22.
    // If you are using a different Kotlin version, let me know!
    id("com.google.devtools.ksp") version "1.9.22-1.0.17" apply false
}