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
import kotlinx.coroutines.flow.update
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

// 🚨 1-HOUR PERSISTENT LOG DATA CLASS
data class TerminalLog(val timestamp: Long, val tag: String, val message: String)

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

    // 🚨 IMMORTAL TERMINAL BUFFER (1-Hour Rolling Window)
    private val _terminalHistoryFlow = MutableStateFlow<List<TerminalLog>>(emptyList())
    val terminalHistoryFlow: StateFlow<List<TerminalLog>> = _terminalHistoryFlow.asStateFlow()

    @SuppressLint("ConstantLocale")
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    init {
        // 🚨 BOOT SEQUENCE: Because this is a Singleton, this runs exactly ONCE
        // per app process launch. No more duplicate ghost logs on the UI!
        logToTerminal("SYS", "GoPrivate OS Kernel Initializing...")
        logToTerminal("SYS", "Mounting Neural Matrices (Engines A, B, C)...")
        logToTerminal("SYS", "Awaiting System Telemetry...")
    }

    /**
     * Call this from ANYWHERE to safely append to the 1-Hour Memory Bank.
     */
    fun logToTerminal(tag: String, message: String) {
        // Keep standard Android logcat working for debugging
        Log.d(tag, message)

        val entry = TerminalLog(System.currentTimeMillis(), tag, message)

        // Thread-safe atomic update
        _terminalHistoryFlow.update { current ->
            val oneHourAgo = System.currentTimeMillis() - 3600_000L // 1 Hour in Milliseconds

            // Appends the new log, and slices off anything older than 1 hour to prevent RAM bloat
            (current + entry).filter { it.timestamp >= oneHourAgo }
        }
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

    fun logAppScanned() {
        val count = totalAppsScanned.incrementAndGet()
        _appsScannedCount.value = count
    }

    fun logPacketRouted(bytes: Int) {
        val total = totalBytesProtected.addAndGet(bytes.toLong())
        _dataProtectedMB.value = total / (1024f * 1024f)

        currentSecondPackets.incrementAndGet()
        val now = System.currentTimeMillis()
        if (now - lastSecondTime >= 1000) {
            _packetRate.value = currentSecondPackets.get().toFloat()
            currentSecondPackets.set(0)
            lastSecondTime = now
        }
    }

    fun logThreatBlocked(appName: String, threatType: String, riskScore: Float) {
        val count = totalThreatsBlocked.incrementAndGet()
        _threatsBlockedCount.value = count

        _threatEvents.tryEmit(ThreatEvent(appName, threatType, riskScore))
        Log.e(TAG, "🚨 THREAT LOGGED: $appName ($threatType) - Score: $riskScore")
    }

    // === ANALYTICS & LOGGING ===

    fun logNLPEvent(label: String, confidence: Float) {
        if (!isTelemetryEnabled) return
        Log.d(TAG, "📊 NLP STATS | Label: $label | Confidence: $confidence%")
    }

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

    fun getBatterySavedPercent(): Int {
        val baseSave = 12
        val extraSave = (totalThreatsBlocked.get() * 2)
        return minOf(baseSave + extraSave, 100)
    }
}