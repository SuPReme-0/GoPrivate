plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
    id("com.google.devtools.ksp") // ✅ KSP is required for Room code generation
}

android {
    namespace = "com.goprivate.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.goprivate.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                // 🚨 ADD THIS: Ensures C++ is built for all common phone architectures
                abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
            }
        }

        // 🚨 ADD THIS: Required for Room to export schemas (helps with migrations)
        ksp {
            arg("room.schemaLocation", "$projectDir/schemas")
        }
    }

    externalNativeBuild {
        cmake {
            path("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
            isShrinkResources = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/DEPENDENCIES"
            excludes += "META-INF/LICENSE*"
            excludes += "META-INF/NOTICE*"
            excludes += "META-INF/*.kotlin_module"
        }
        jniLibs {
            // 🚨 FIX: Changed to true to support older devices and NDK stability
            useLegacyPackaging = true
        }
    }

    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    // === Android Core & UI ===
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.material)

    implementation("com.airbnb.android:lottie:6.7.1")
    implementation("androidx.core:core-splashscreen:1.0.1")

    // === Architecture & Lifecycle ===
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)

    // === Background Processing ===
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    // === 🧠 ONNX Runtime (Synchronized Stack) ===
    implementation(libs.onnxruntime.android.v1243)
    implementation("com.microsoft.onnxruntime:onnxruntime-extensions-android:0.13.0")

    // === 📦 Data & Persistence (Room) ===
    val roomVersion = "2.6.1"
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    ksp("androidx.room:room-compiler:$roomVersion") // Uses KSP instead of KAPT for speed

    // === 🛡️ Async, Security, & Utilities ===
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.security.crypto)
    implementation(libs.gson)
    implementation(libs.mpandroidchart)
}