@file:Suppress("unused")

package com.goprivate.app.ui.viewmodels

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.goprivate.app.core.TelemetryManager
import com.goprivate.app.data.ml.EngineANetworkManager
import com.goprivate.app.data.ml.EngineCNLPManager
import com.goprivate.app.data.model.DashboardState
import com.goprivate.app.data.model.NetworkDataPoint
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * ViewModel for Home Dashboard.
 * Acts as the "Central Nervous System" connecting ML engines to UI.
 */
class HomeViewModel(application: Application) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow(DashboardState())
    val uiState: StateFlow<DashboardState> = _uiState.asStateFlow()

    private val forensicCache: SharedPreferences = application.getSharedPreferences("goprivate_forensic_cache", Context.MODE_PRIVATE)

    private val cacheListener = SharedPreferences.OnSharedPreferenceChangeListener { sharedPrefs, _ ->
        val totalScannedReports = sharedPrefs?.all?.size ?: 0
        _uiState.update { it.copy(scannedCount = totalScannedReports) }
    }

    // 🚨 MILLISECOND PRECISION CLOCK
    private val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())
    private fun getTimestamp(): String = timeFormat.format(Date())

    init {
        // 1. Initialize Dashboard Statistics
        _uiState.update { it.copy(scannedCount = forensicCache.all.size) }
        forensicCache.registerOnSharedPreferenceChangeListener(cacheListener)

        viewModelScope.launch {
            TelemetryManager.threatsBlockedCount.collect { count ->
                _uiState.update { it.copy(blockedCount = count) }
            }
        }

        viewModelScope.launch {
            TelemetryManager.dataProtectedMB.collect { mb ->
                _uiState.update { it.copy(protectedMb = mb) }
            }
        }

        // 2. Sync Network Values
        viewModelScope.launch {
            TelemetryManager.packetRate.collect { rate ->
                _uiState.update { it.copy(packetRate = rate) }
            }
        }

        viewModelScope.launch {
            while (true) {
                val currentRate = _uiState.value.packetRate
                updateNetworkChart(currentRate)
                delay(1000L)
            }
        }

        // 3. ENTERPRISE SIEM CYBER TERMINAL INITIALIZATION
        _uiState.update { currentState ->
            currentState.copy(
                terminalLog = listOf(
                    "[${getTimestamp()}] >_ GoPrivate OS Kernel Initializing...",
                    "[${getTimestamp()}] >_ Mounting Neural Matrices (Engines A, B, C)...",
                    "[${getTimestamp()}] >_ Awaiting System Telemetry..."
                )
            )
        }

        // 🚨 ADVANCED TELEMETRY MERGING
        viewModelScope.launch {

            // Vector 1: Engine C NLP Logs
            val nlpLogs = EngineCNLPManager.nlpEventsFlow.map { event ->
                "[${getTimestamp()}] $event"
            }

            // Vector 2: High-Severity Threat Interceptions (Engine A & B)
            val threatLogs = TelemetryManager.threatEvents.map { event ->
                val riskPct = (event.riskScore * 100).toInt()
                "[${getTimestamp()}] 🚨 CRITICAL_INTERCEPT: [${event.appName}]\n      └─ Vector: ${event.threatType} | Severity: $riskPct%"
            }

            // Vector 3: Kernel Network Shield Status (Distinct prevents spam)
            val vpnLogs = EngineANetworkManager.vpnActiveFlow.map { isActive ->
                if (isActive) {
                    "[${getTimestamp()}] >_ KERNEL: Network Shield ENGAGED. Traffic routed to Engine A."
                } else {
                    "[${getTimestamp()}] >_ KERNEL: Network Shield OFFLINE. System endpoints unprotected."
                }
            }

            // Merge all vectors and feed into the UI State
            merge(nlpLogs, threatLogs, vpnLogs).collect { message ->
                _uiState.update { currentState ->
                    // 🚨 Increased log history from 50 to 100 for better SIEM scrolling
                    val updatedLog = (currentState.terminalLog + message).takeLast(100)
                    currentState.copy(terminalLog = updatedLog)
                }
            }
        }
    }

    private fun updateNetworkChart(rate: Float) {
        val timestamp = System.currentTimeMillis()
        _uiState.update { currentState ->
            val newData = (currentState.networkData + NetworkDataPoint(timestamp, rate)).takeLast(60)
            currentState.copy(networkData = newData)
        }
    }

    override fun onCleared() {
        super.onCleared()
        forensicCache.unregisterOnSharedPreferenceChangeListener(cacheListener)
    }
}

class HomeViewModelFactory(
    private val application: Application
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(HomeViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return HomeViewModel(application) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}