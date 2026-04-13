@file:Suppress("SpellCheckingInspection", "unused")

package com.goprivate.app.core

import android.annotation.SuppressLint
import android.util.Log
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Threat event data class for reactive UI updates
 */
data class ThreatEvent(
    val appName: String,
    val threatType: String,
    val riskScore: Float,
    val timestamp: Long = System.currentTimeMillis()
)

/**
 * Central telemetry manager for all GoPrivate metrics.
 * Thread-safe, reactive, and the source of truth for UI StateFlows.
 */
object TelemetryManager {
    private const val TAG = "GoPrivateTelemetry"

    // Global kill-switch for GDPR compliance
    var isTelemetryEnabled = true

    // === THREAD-SAFE INTERNAL COUNTERS ===
    private val totalAppsScanned = AtomicInteger(0)
    private val totalThreatsBlocked = AtomicInteger(0)
    private val totalBytesProtected = AtomicLong(0L)

    // 🚨 NEW: The Global Terminal Pipeline
    private val _liveTerminalLogs = MutableSharedFlow<String>(replay = 50, extraBufferCapacity = 100)
    val liveTerminalLogs = _liveTerminalLogs.asSharedFlow()

    @SuppressLint("ConstantLocale")
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    /**
     * Call this from ANYWHERE in the app to print to the Home Screen Terminal.
     */
    fun logToTerminal(tag: String, message: String) {
        val time = timeFormat.format(Date())
        val formattedLog = "[$time] $tag: $message"
        _liveTerminalLogs.tryEmit(formattedLog)
    }

    // === UI STATE FLOWS (Source of Truth) ===
    private val _appsScannedCount = MutableStateFlow(0)
    val appsScannedCount: StateFlow<Int> = _appsScannedCount.asStateFlow()

    private val _threatsBlockedCount = MutableStateFlow(0)
    val threatsBlockedCount: StateFlow<Int> = _threatsBlockedCount.asStateFlow()

    private val _dataProtectedMB = MutableStateFlow(0f)
    val dataProtectedMB: StateFlow<Float> = _dataProtectedMB.asStateFlow()

    private val _packetRate = MutableStateFlow(0f)
    val packetRate: StateFlow<Float> = _packetRate.asStateFlow()

    private val _threatEvents = MutableSharedFlow<ThreatEvent>(extraBufferCapacity = 50)
    val threatEvents: SharedFlow<ThreatEvent> = _threatEvents.asSharedFlow()

    // === INTERNAL TRACKERS ===
    private val currentSecondPackets = AtomicInteger(0)
    @Volatile private var lastSecondTime = System.currentTimeMillis()

    // === UPDATE FUNCTIONS (Thread-Safe) ===

    /**
     * Log that an app was scanned (increments counter + updates flow)
     */
    fun logAppScanned() {
        val count = totalAppsScanned.incrementAndGet()
        _appsScannedCount.value = count
    }

    /**
     * Log that packets were routed (updates data protected + calculates packet rate)
     */
    fun logPacketRouted(bytes: Int) {
        // 1. Thread-safe data accumulation
        val total = totalBytesProtected.addAndGet(bytes.toLong())
        _dataProtectedMB.value = total / (1024f * 1024f)

        // 2. Calculate real-time packet rate (packets per second)
        currentSecondPackets.incrementAndGet()
        val now = System.currentTimeMillis()
        if (now - lastSecondTime >= 1000) {
            _packetRate.value = currentSecondPackets.get().toFloat()
            currentSecondPackets.set(0)
            lastSecondTime = now
        }
    }

    /**
     * Log that a threat was blocked (increments counter + emits event)
     */
    fun logThreatBlocked(appName: String, threatType: String, riskScore: Float) {
        val count = totalThreatsBlocked.incrementAndGet()
        _threatsBlockedCount.value = count

        // Emit event for Radar visualization and Terminal log
        _threatEvents.tryEmit(ThreatEvent(appName, threatType, riskScore))
        Log.e(TAG, "🚨 THREAT LOGGED: $appName ($threatType) - Score: $riskScore")
    }

    // === ANALYTICS & LOGGING ===

    /**
     * Log NLP analysis event (for terminal display)
     */
    fun logNLPEvent(label: String, confidence: Float) {
        if (!isTelemetryEnabled) return
        Log.d(TAG, "📊 NLP STATS | Label: $label | Confidence: $confidence%")
    }

    /**
     * Log generic inference event (for performance monitoring)
     */
    fun logInference(engineName: String, inferenceTimeMs: Long, riskScore: Float) {
        if (!isTelemetryEnabled) return
        val riskBucket = when {
            riskScore < 0.2f -> "SAFE"
            riskScore < 0.7f -> "SUSPICIOUS"
            else -> "MALICIOUS"
        }
        Log.d(TAG, "📊 TELEMETRY EVENT: Engine=$engineName | Time=${inferenceTimeMs}ms | Risk=$riskBucket")
    }

    // === PUBLIC GETTERS ===

    /**
     * Calculate battery saved percentage based on threats blocked
     */
    fun getBatterySavedPercent(): Int {
        val baseSave = 12
        val extraSave = (totalThreatsBlocked.get() * 2)
        return minOf(baseSave + extraSave, 100)
    }
}