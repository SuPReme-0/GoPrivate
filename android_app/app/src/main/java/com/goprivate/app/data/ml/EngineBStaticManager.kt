@file:Suppress("SpellCheckingInspection", "UNCHECKED_CAST", "unused", "DEPRECATION")

package com.goprivate.app.data.ml

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import com.goprivate.app.core.FeatureHelper
import com.goprivate.app.core.SecurityCore
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.core.sensors.FastApkScanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.FloatBuffer
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll

/**
 * 🛡️ THE VANGUARD STATIC ANALYZER (ENGINE B) - PURE XAI VISUALIZER
 * Upgraded with Extended OEM Trust Matrix and Deep Forensic Telemetry.
 */
object EngineBStaticManager {
    private const val TAG = "EngineBStatic"
    private const val MODEL_FILENAME = "engine_b_model.enc"

    const val MALICIOUS_THRESHOLD = 0.75f

    private val _scanProgress = MutableStateFlow("IDLE")
    val scanProgressFlow: StateFlow<String> = _scanProgress.asStateFlow()

    private val _appsScanned = MutableStateFlow(0)
    val appsScannedFlow: StateFlow<Int> = _appsScanned.asStateFlow()

    private var ortEnv: OrtEnvironment? = null
    private var ortSession: OrtSession? = null
    private var targetFeaturesList: List<String> = emptyList()

    @Volatile
    private var isInitialized = false

    private val engineLock = ReentrantReadWriteLock()

    // 🚨 EXTENDED OEM TRUST MATRIX: Fixes false positives on system apps like Albums, Camera, etc.
    private val TRUSTED_DOMAINS = listOf(
        "com.google.", "com.android.", "com.samsung.", "com.microsoft.",
        "com.facebook.", "com.instagram.", "com.whatsapp.", "com.netflix.",
        "com.amazon.", "in.amazon.", "com.spotify.", "com.twitter.",
        "org.telegram.", "com.zhiliaoapp.", "com.snapchat.", "com.apple.",
        "com.vivo.", "com.oppo.", "com.xiaomi.", "com.miui.", "com.huawei.",
        "com.oneplus.", "com.motorola.", "com.coloros."
    )

    fun initialize(context: Context) {
        if (isInitialized) return

        engineLock.writeLock().lock()
        try {
            if (isInitialized) return

            _scanProgress.value = "[ BOOTING_NEURAL_CORE ]"
            targetFeaturesList = FeatureHelper.loadFeatureNames(context, "engine_b_features.json").map { it.lowercase() }
            ortEnv = OrtEnvironment.getEnvironment()

            val encryptedBytes = context.assets.open(MODEL_FILENAME).readBytes()
            val decryptedBytes = SecurityCore.decryptModelInMemory(encryptedBytes, MODEL_FILENAME)
                ?: throw IllegalStateException("Model decryption failed")

            try {
                val sessionOptions = OrtSession.SessionOptions().apply {
                    setIntraOpNumThreads(1)
                    setInterOpNumThreads(1)
                    try { addXnnpack(emptyMap()) } catch (_: Exception) {}
                }

                ortSession = ortEnv?.createSession(decryptedBytes, sessionOptions)
                isInitialized = true
                _scanProgress.value = "[ CORE_ONLINE ]"
            } finally {
                SecurityCore.secureWipe(decryptedBytes)
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to initialize Engine B", e)
            _scanProgress.value = "[ BOOT_FAILURE ]"
            shutdownInternal()
        } finally {
            engineLock.writeLock().unlock()
        }
    }

    suspend fun analyzeApp(packageName: String, context: Context): Pair<Float, List<String>> = withContext(Dispatchers.Default) {
        if (packageName.isBlank() || !isInitialized) return@withContext Pair(0f, emptyList())

        val startTimeMs = System.currentTimeMillis()
        var riskScore = 0f
        val combinedXaiFeatures = mutableListOf<String>()

        try {
            val pm = context.packageManager
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            }

            // 🚨 XAI: Permission Formatting for UI
            val requestedPerms = packageInfo.requestedPermissions?.map { "permission::$it" } ?: emptyList()
            combinedXaiFeatures.addAll(requestedPerms)

            // 🚨 XAI: Zero-Trust Provenance Injector
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                try { pm.getInstallSourceInfo(packageName).installingPackageName } catch (e: Exception) { null }
            } else {
                pm.getInstallerPackageName(packageName)
            }

            val safeInstallers = listOf("com.android.vending", "com.amazon.venezia", "com.sec.android.app.samsungapps")
            if (installer == null || !safeInstallers.contains(installer)) {
                combinedXaiFeatures.add("Provenance: ⚠️ Unverified Sideload (Source: ${installer ?: "Unknown OS Installer"})")
            } else {
                combinedXaiFeatures.add("Provenance: ✅ Verified Store ($installer)")
            }

            // 🚨 XAI: Human-Readable Capability Translator
            val permsString = requestedPerms.joinToString(" ")
            if (permsString.contains("CAMERA") || permsString.contains("RECORD_AUDIO")) {
                combinedXaiFeatures.add("> Covert Media Recording (Camera/Mic Access)")
            }
            if (permsString.contains("ACCESS_FINE_LOCATION") || permsString.contains("ACCESS_BACKGROUND_LOCATION")) {
                combinedXaiFeatures.add("> High-Precision Location Tracking")
            }
            if (permsString.contains("READ_CONTACTS") || permsString.contains("READ_SMS") || permsString.contains("READ_CALL_LOG")) {
                combinedXaiFeatures.add("> PII Data Harvesting (Contacts/SMS/Logs)")
            }
            if (permsString.contains("SYSTEM_ALERT_WINDOW")) {
                combinedXaiFeatures.add("> Screen Overlay (Potential Clickjacking)")
            }
            if (permsString.contains("QUERY_ALL_PACKAGES")) {
                combinedXaiFeatures.add("> Device Fingerprinting (Scans installed apps)")
            }

            _scanProgress.value = "[ EXTRACTING_PAYLOAD ]"

            val sourceDir = packageInfo.applicationInfo?.sourceDir ?: return@withContext Pair(
                0f,
                combinedXaiFeatures.distinct() + "error::NO_PHYSICAL_APK"
            )

            val apkFile = File(sourceDir)
            if (!apkFile.exists()) return@withContext Pair(0f, combinedXaiFeatures.distinct() + "error::APK_MISSING")

            // 🚨 XAI: Extract Binary Features
            val featureVector = FastApkScanner.extractFeatures(context, packageName, apkFile, targetFeaturesList) { progressPct, message ->
                _scanProgress.value = "[$progressPct%] $message"
            }

            val activeMlFeatures = targetFeaturesList.filterIndexed { index, _ -> featureVector[index] > 0.5f }
            combinedXaiFeatures.addAll(activeMlFeatures)

            // 🚨 XAI: UNIVERSAL SDK SIGNATURE MATRIX
            val rawFeaturesString = combinedXaiFeatures.joinToString(" ").lowercase()

            val corporateSignatures = mapOf(
                "Matrix: 🕵️ [Meta/Facebook Graph Tracker Detected]" to listOf("com.facebook", "graph.facebook"),
                "Matrix: 📡 [Google/Firebase Telemetry Detected]" to listOf("com.google.android.gms", "firebase", "crashlytics", "google-analytics"),
                "Matrix: 📦 [Amazon Device Framework Detected]" to listOf("com.amazon.device", "com.amazon.identity", "aws.amazon"),
                "Matrix: 🎬 [Netflix Streaming Media SDK]" to listOf("com.netflix"),
                "Matrix: 🎵 [Spotify Media SDK]" to listOf("com.spotify"),
                "Matrix: 💻 [Microsoft Telemetry Detected]" to listOf("com.microsoft", "appcenter"),
                "Matrix: 👻 [Snapchat Kit/SDK Detected]" to listOf("snapchat", "snap.kit"),
                "Matrix: 🐦 [Twitter/X SDK Detected]" to listOf("twitter", "twimg"),
                "Matrix: 🎯 [AppsFlyer Ad-Tracking Detected]" to listOf("appsflyer"),
                "Matrix: 🎯 [Flurry Analytics Detected]" to listOf("flurry"),
                "Matrix: 🎯 [AppLovin Ad Network Detected]" to listOf("applovin"),
                "Matrix: 🕵️ [TikTok/ByteDance SDK Detected]" to listOf("tiktok", "bytedance", "pangle"),
                "Matrix: 🎯 [Adjust Marketing SDK Detected]" to listOf("adjust.sdk", "adjust.io"),
                "Matrix: 🎮 [Unity 3D Engine SDK]" to listOf("com.unity3d"),
                "Matrix: 🎮 [Unreal Engine SDK]" to listOf("epicgames", "unreal"),
                "Matrix: 🐉 [Tencent Services/SDK Detected]" to listOf("tencent", "igexin"),
                "Matrix: 📊 [Mixpanel Analytics Detected]" to listOf("mixpanel"),
                "Matrix: 🔔 [OneSignal Push Tracking Detected]" to listOf("onesignal"),
                "Matrix: 🔗 [Branch Metrics Deep-Linking Detected]" to listOf("io.branch"),
                "Matrix: ⚠️ [Dynamic Payload Loader Detected]" to listOf("dalvik.system.dexclassloader")
            )

            // Inject matching signatures for UI rendering
            for ((tag, triggers) in corporateSignatures) {
                if (triggers.any { rawFeaturesString.contains(it) }) {
                    combinedXaiFeatures.add(tag)
                }
            }

            _scanProgress.value = "[ EXECUTING_TENSOR_MATH ]"

            engineLock.readLock().lock()
            try {
                val session = ortSession ?: return@withContext Pair(0f, combinedXaiFeatures.distinct())
                val env = ortEnv ?: return@withContext Pair(0f, combinedXaiFeatures.distinct())

                val shape = longArrayOf(1, featureVector.size.toLong())

                OnnxTensor.createTensor(env, FloatBuffer.wrap(featureVector), shape).use { inputTensor ->
                    val inputName = session.inputNames.iterator().next()
                    session.run(mapOf(inputName to inputTensor)).use { result ->
                        var lastOutput: Any? = null
                        val iterator = result.iterator()
                        while (iterator.hasNext()) { lastOutput = iterator.next().value.value }

                        riskScore = when (lastOutput) {
                            is Array<*> -> {
                                when (val firstRow = lastOutput.firstOrNull()) {
                                    is FloatArray -> firstRow.getOrNull(1) ?: 0f
                                    is Map<*, *> -> {
                                        (firstRow[1L] as? Float) ?: (firstRow[1] as? Float) ?: (firstRow["1"] as? Float) ?: 0f
                                    }
                                    else -> 0f
                                }
                            }
                            is List<*> -> {
                                val firstRow = lastOutput.firstOrNull()
                                if (firstRow is Map<*, *>) {
                                    (firstRow[1L] as? Float) ?: (firstRow[1] as? Float) ?: (firstRow["1"] as? Float) ?: 0f
                                } else 0f
                            }
                            else -> 0f
                        }
                    }
                }
            } finally {
                engineLock.readLock().unlock()
            }

            // 🚨 FALSE POSITIVE MITIGATION: DYNAMIC TRUST DOMAINS
            val isGloballyTrusted = TRUSTED_DOMAINS.any { packageName.lowercase().startsWith(it) }

            if (isGloballyTrusted) {
                combinedXaiFeatures.add("STATUS: ✅ [ Verified OEM/System Application ]")
                combinedXaiFeatures.add("Matrix: ℹ️ [ ML Risk Score suppressed due to root trust ]")
                // Override the high ML risk score to ensure UI displays as "SAFE"
                riskScore = Math.min(riskScore, 0.25f)
            } else if (riskScore < MALICIOUS_THRESHOLD) {
                combinedXaiFeatures.add("STATUS: 🟢 [ Behavioral Analysis: Benign ]")
            } else {
                combinedXaiFeatures.add("STATUS: 🚨 [ Behavioral Analysis: PREDATORY ]")
            }

            TelemetryManager.logInference("Engine B (Static)", System.currentTimeMillis() - startTimeMs, riskScore)
            TelemetryManager.logAppScanned()
            _appsScanned.value = TelemetryManager.appsScannedCount.value
            _scanProgress.value = "[ ANALYSIS_COMPLETE ]"

        } catch (e: kotlinx.coroutines.CancellationException) {
            Log.w(TAG, "⚠️ Scan cancelled by OS/User for $packageName")
            _scanProgress.value = "[ AUDIT_ABORTED ]"
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Inference error for $packageName", e)
            _scanProgress.value = "[ ERR_EXECUTION_FAILED ]"
            return@withContext Pair(0f, listOf("error::EXECUTION_FAILED"))
        }

        return@withContext Pair(riskScore, combinedXaiFeatures.distinct())
    }

    suspend fun analyzeApps(packageNames: List<String>, context: Context): List<Pair<Float, List<String>>> = withContext(Dispatchers.Default) {
        packageNames.map { packageName -> async { analyzeApp(packageName, context) } }.awaitAll()
    }

    fun isReady(): Boolean = isInitialized && ortSession != null

    fun shutdown() {
        engineLock.writeLock().lock()
        try {
            shutdownInternal()
        } finally {
            engineLock.writeLock().unlock()
        }
    }

    private fun shutdownInternal() {
        try {
            ortSession?.close()
            ortEnv?.close()
            ortSession = null
            ortEnv = null
            isInitialized = false
        } catch (e: Exception) { Log.e(TAG, "Error during shutdown", e) }
    }
}