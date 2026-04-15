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
import com.goprivate.app.data.model.DashboardState
import com.goprivate.app.data.model.NetworkDataPoint
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * ViewModel for Home Dashboard.
 * Completely decoupled from log generation to prevent Lifecycle Ghosting.
 * Formats the 1-Hour persistent memory for the UI Terminal.
 */
class HomeViewModel(application: Application) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow(DashboardState())
    val uiState: StateFlow<DashboardState> = _uiState.asStateFlow()

    private val forensicCache: SharedPreferences = application.getSharedPreferences("goprivate_forensic_cache", Context.MODE_PRIVATE)

    private val cacheListener = SharedPreferences.OnSharedPreferenceChangeListener { sharedPrefs, _ ->
        val totalScannedReports = sharedPrefs?.all?.size ?: 0
        _uiState.update { it.copy(scannedCount = totalScannedReports) }
    }

    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

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

        // 3. 🚨 THE XAI & SYSTEM TERMINAL FORMATTER
        // Constantly observes the immortal 1-hour memory bank.
        viewModelScope.launch {
            TelemetryManager.terminalHistoryFlow.collect { history ->
                val formattedLogs = history.map { entry ->
                    val timeStr = timeFormat.format(Date(entry.timestamp))

                    // 🧠 SURGICAL UI FORMATTING
                    when (entry.tag) {
                        "XAI" -> {
                            // Highlights the multi-line forensic clause extraction
                            "[$timeStr] \uD83E\uDDE0 [XAI_FORENSIC_ENGINE]\n${entry.message}"
                        }
                        "WRN", "CRIT", "ERR" -> {
                            "[$timeStr] \uD83D\uDEA8 [${entry.tag}] ${entry.message}"
                        }
                        "NLP" -> {
                            "[$timeStr] \uD83D\uDC41️\u200D\uD83D\uDDE8️ [${entry.tag}] ${entry.message}"
                        }
                        "INF" -> {
                            "[$timeStr] ✅ [${entry.tag}] ${entry.message}"
                        }
                        else -> {
                            "[$timeStr] >_ [${entry.tag}] ${entry.message}"
                        }
                    }
                }

                _uiState.update { it.copy(terminalLog = formattedLogs) }
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