# ---------------------------------------------------------------------------
# 🛡️ GOPRIVATE SYSTEM HARDENING (PROGUARD / R8)
# ---------------------------------------------------------------------------

# === 🚨 CRITICAL: THE C++ JNI BRIDGE (Do NOT Touch) ===
# FIX: Using the (...) wildcard ensures R8 matches the Kotlin bytecode perfectly
# without failing on nullability annotations or primitive boxing.
-keep class com.goprivate.app.core.network.GoPrivateVpnService {
    public boolean onNativePacketIntercepted(...);
    public boolean protectNativeSocket(...);
    native <methods>;
}

# === ONNX Runtime (ML Execution) ===
-keep class ai.onnxruntime.** { *; }
-keep class com.microsoft.onnxruntime.** { *; }
-keepclasseswithmembernames class * { native <methods>; }

# === GoPrivate Core Architecture ===
-keep class com.goprivate.app.data.ml.** { *; }
-keep class com.goprivate.app.core.SecurityCore { *; }
-keep class com.goprivate.app.core.TelemetryManager { *; }
-keep class com.goprivate.app.core.FeatureHelper { *; }

# === 🧬 VIEWMODELS (Reflection Protection) ===
# FIX: Changed to -keepclassmembers. Prevents ViewModelProvider from failing.
-keepclassmembers class * extends androidx.lifecycle.ViewModel {
    public <init>(...);
}
-keep class com.goprivate.app.ui.viewmodels.** { *; }

# === 💎 HOLOGRAPHIC UI (Custom Views) ===
# Prevents R8 from stripping XML attributes and glitch animations
-keep class com.goprivate.app.ui.views.** { *; }
-keepclassmembers class * extends android.view.View {
    void set*(***);
    *** get*();
}

# === 📦 DATA MODELS & REPOSITORIES ===
# Essential for Room, SharedPrefs, and JSON serialization
-keep class com.goprivate.app.data.model.** { *; }
-keep class com.goprivate.app.data.repository.** { *; }

# === 🛠️ THIRD-PARTY LIBRARIES ===

# Gson (Serializing XAI Reports & Settings)
-keep class com.google.gson.** { *; }
-keepattributes *Annotation*, EnclosingMethod, Signature
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# Kotlin Coroutines & Flows
-keepclassmembers class kotlinx.coroutines.** { *; }
-keep class kotlinx.coroutines.android.HandlerContext { *; }

# MPAndroidChart
-keep class com.github.mikephil.charting.** { *; }
-keep interface com.github.mikephil.charting.** { *; }

# Lottie
-keep class com.airbnb.lottie.** { *; }

# === 🛡️ GENERAL SECURITY RULES ===
# Keeps stack traces somewhat readable for debugging telemetry
-keepattributes SourceFile, LineNumberTable

# Preserve Enums for Logic (Scanning Filters & Theme Modes)
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# JNI Helper Classes used in netguard.c
-keep class com.goprivate.app.core.network.ReusablePacketInfo { *; }
# ---------------------------------------------------------------------------
# 🛠️ OKIO & JAVAX ANNOTATION FIX
# Tells R8 to ignore missing metadata classes that don't affect runtime
# ---------------------------------------------------------------------------
-dontwarn javax.annotation.**
-keepattributes *Annotation*
-dontwarn org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement
-dontwarn okio.**